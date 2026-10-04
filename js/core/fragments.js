/*
 * IPv4 分片重组（在 TCP 流重组之前运行）。
 *
 * 数据报身份 = 源地址 | 目的地址 | 协议 | IP ID —— 不同地址间相同 IP ID 的分片互不干扰。
 *
 * 取证安全约束：
 *  - 字节一律按分片偏移落位，绝不按抓包到达顺序拼接；
 *  - 完全相同的重复分片字节不增加任何内容；
 *  - 重叠位置字节不一致 -> 冲突证据（保留每个候选字节及其来源包号），整组不产出正文；
 *  - 缺失区间（含未抓全分片的声明尾部）-> 显式缺口，整组不产出正文；
 *  - 最终长度不一致（多个末片给出不同总长 / 分片越出总长）或分片不合法
 *    （非末片长度非 8 的倍数、非末片 0 字节、越出 65535）-> 不产出可信正文；
 *  - 只有「首片在、最终长度唯一、每个声明字节都抓到、无冲突」的组才解码 TCP：
 *    解码结果写回 offset 0 的首片包对象（fragmentIndexes 记录实际供字节的来源包号，
 *    组记录里的 segments 给出逐段贡献图），该包随后进入常规 TCP 重组；
 *    其余情况所有成员包保持 ip_fragment 丢弃标记，绝不进入 TCP 重组。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PcapFragments = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var MAX_IP_TOTAL = 65535;

  function groupKeyOf(p) {
    return p.srcIp + "|" + p.dstIp + "|" + p.fragment.protocol + "|" + p.ipId;
  }

  /* 从完整重组出的字节流解码 TCP 头；成功则把 TCP 字段写到首片包上 */
  function decodeTcp(packet, bytes, contributorIndexes) {
    if (bytes.length < 20) return false;
    var v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var hdrLen = (bytes[12] >> 4) * 4;
    if (hdrLen < 20 || hdrLen > bytes.length) return false;
    packet.srcPort = v.getUint16(0);
    packet.dstPort = v.getUint16(2);
    packet.seq = v.getUint32(4);
    packet.ack = v.getUint32(8);
    packet.flags = bytes[13];
    packet.window = v.getUint16(14);
    packet.tcpHeaderLen = hdrLen;
    packet.payload = bytes.slice(hdrLen);
    packet.payloadCapturedLen = packet.payloadDeclaredLen =
      packet.payload.length;
    packet.fragmentIndexes = contributorIndexes;
    packet.discardReason = null;
    return true;
  }

  function assembleGroup(key, members) {
    var p0 = members[0];
    var record = {
      key: key,
      srcIp: p0.srcIp,
      dstIp: p0.dstIp,
      protocol: p0.fragment.protocol,
      ipId: p0.ipId,
      indexes: members.map(function (p) {
        return p.index;
      }),
      status: "incomplete",
      reasons: [],
      totalLen: null,
      holes: [],
      conflicts: [],
      segments: [], // 贡献图：重组报文的 [start,end) 来自哪个包
      duplicateBytes: 0,
    };

    // —— 1. 单片合法性 ——
    var invalid = false;
    members.forEach(function (p) {
      var f = p.fragment;
      var end = f.offset + f.declared;
      if (end > MAX_IP_TOTAL) {
        invalid = true;
        record.reasons.push(
          "pkt" + p.index + "：分片越界（offset+declared=" + end + " > 65535）",
        );
      }
      if (f.more && f.declared === 0) {
        invalid = true;
        record.reasons.push("pkt" + p.index + "：非末片声明 0 字节数据");
      }
      if (f.more && f.declared % 8 !== 0) {
        invalid = true;
        record.reasons.push(
          "pkt" + p.index + "：非末片数据长度 " + f.declared + " 不是 8 的倍数",
        );
      }
    });

    // —— 2. 最终长度一致性：所有末片必须给出同一个总长，且任何分片不得越出总长 ——
    var totalLen = null;
    var lengthMismatch = false;
    members.forEach(function (p) {
      if (p.fragment.more) return;
      var end = p.fragment.offset + p.fragment.declared;
      if (totalLen == null) totalLen = end;
      else if (end !== totalLen) {
        lengthMismatch = true;
        record.reasons.push(
          "末片总长不一致：" + totalLen + " 与 " + end + "（pkt" + p.index + "）",
        );
      }
    });
    if (totalLen != null) {
      members.forEach(function (p) {
        var end = p.fragment.offset + p.fragment.declared;
        if (end > totalLen) {
          lengthMismatch = true;
          record.reasons.push(
            "pkt" + p.index + " 声明到 " + end + "，超出末片总长 " + totalLen,
          );
        }
      });
    }
    record.totalLen = totalLen;

    // —— 3. 逐字节落位：相同去重、矛盾留证 ——
    var cell = new Map(); // pos -> {byte, owner}
    var conflictAt = new Map(); // pos -> {pos, byPkt}
    members.forEach(function (p) {
      var f = p.fragment;
      for (var i = 0; i < f.bytes.length; i++) {
        var pos = f.offset + i;
        var b = f.bytes[i];
        var ex = cell.get(pos);
        if (!ex) {
          cell.set(pos, { byte: b, owner: p.index });
        } else if (ex.byte === b) {
          // 完全相同的重复字节：不增加内容
          p.fragDupBytes = (p.fragDupBytes || 0) + 1;
          record.duplicateBytes++;
        } else {
          var c = conflictAt.get(pos);
          if (!c) {
            c = { pos: pos, byPkt: {} };
            c.byPkt[ex.owner] = ex.byte;
            conflictAt.set(pos, c);
          }
          c.byPkt[p.index] = b;
          p.fragConflictBytes = (p.fragConflictBytes || 0) + 1;
        }
      }
    });
    record.conflicts = Array.from(conflictAt.values()).sort(function (a, b) {
      return a.pos - b.pos;
    });

    // —— 4. 覆盖区间 / 贡献图 / 缺口 ——
    var positions = Array.from(cell.keys()).sort(function (a, b) {
      return a - b;
    });
    var segs = [];
    positions.forEach(function (pos) {
      var owner = cell.get(pos).owner;
      var last = segs[segs.length - 1];
      if (last && last.end === pos && last.pktIndex === owner)
        last.end = pos + 1;
      else segs.push({ start: pos, end: pos + 1, pktIndex: owner });
    });
    record.segments = segs;

    var holes = [];
    var cur = 0;
    segs.forEach(function (s) {
      if (s.start > cur) holes.push({ start: cur, end: s.start });
      if (s.end > cur) cur = s.end;
    });
    if (totalLen != null && cur < totalLen)
      holes.push({ start: cur, end: totalLen });
    record.holes = holes;
    record.missingFirst = !cell.has(0);
    record.missingFinal = totalLen == null;

    var holeBytes = holes.reduce(function (n, h) {
      return n + h.end - h.start;
    }, 0);
    if (record.missingFirst) record.reasons.push("缺少首片（offset 0）");
    if (record.missingFinal) record.reasons.push("缺少末片（MF=0），总长未知");
    if (holeBytes > 0)
      record.reasons.push("缺失 " + holeBytes + " 字节（" + holes.length + " 段）");
    if (record.conflicts.length)
      record.reasons.push("重叠字节冲突 " + record.conflicts.length + " 处");

    // —— 5. 状态裁定：任何疑点都不产出可信正文 ——
    if (invalid) record.status = "invalid";
    else if (lengthMismatch) record.status = "length_mismatch";
    else if (record.conflicts.length) record.status = "conflict";
    else if (record.missingFirst || record.missingFinal || holeBytes > 0)
      record.status = "incomplete";
    else {
      // 覆盖必然是 [0,totalLen)：拼出完整字节流，解码写回首片包
      var bytes = new Uint8Array(totalLen);
      cell.forEach(function (c, pos) {
        bytes[pos] = c.byte;
      });
      var target = null;
      members.forEach(function (p) {
        if (
          p.fragment.offset === 0 &&
          (target == null || p.index < target.index)
        )
          target = p;
      });
      var contributors = Array.from(
        new Set(
          positions.map(function (pos) {
            return cell.get(pos).owner;
          }),
        ),
      ).sort(function (a, b) {
        return a - b;
      });
      if (target && decodeTcp(target, bytes, contributors)) {
        record.status = "complete";
        record.decodedPacket = target.index;
      } else {
        record.status = "invalid_tcp";
        record.reasons.push("重组字节不含合法 TCP 头");
      }
    }
    return record;
  }

  function assemble(analysis) {
    var groups = new Map();
    analysis.packets.forEach(function (p) {
      if (!p.fragment) return;
      var key = groupKeyOf(p);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    });
    analysis.fragmentGroups = [];
    groups.forEach(function (members, key) {
      analysis.fragmentGroups.push(assembleGroup(key, members));
    });
    return analysis;
  }

  return { assemble: assemble };
});
