/*
 * IPv4 分片重组（与环境无关）。
 *
 * 与 TCP 重组同等级的取证约束：
 *  - 数据报身份 = 源地址 | 目的地址 | 协议 | IP ID —— 不同通信之间相同 IP ID 互不干扰；
 *  - 分片字节按偏移落位，绝不按抓包到达顺序拼接；
 *  - 完全相同的重复分片字节只去重，不产生新内容；
 *  - 重叠且字节矛盾 -> 冲突证据（保留每个候选字节及来源包号），不产出可信正文；
 *  - 缺失区间（含抓包截断导致“声明了却没抓到”的尾部）是显式 holes，不产出可信正文；
 *  - 终止长度不一致（多个末片声明不同总长，或某分片越过总长）或分片不合法
 *    （非末片长度非 8 倍数、越过数据报尺寸上限）-> 不产出可信正文；
 *  - 仅当首片存在、总长唯一、[0,totalLen) 每个字节齐全且无冲突时，才把重组出的
 *    TCP 报文写回承载包（包号最小的首片），全部成员包号记入 fragmentIndexes。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PcapFragments = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* 数据报载荷上限：IP 总长 ≤ 65535，IPv4 头至少 20 字节 */
  var MAX_IP_PAYLOAD = 65535 - 20;

  function groupKeyOf(p) {
    return p.srcIp + "|" + p.dstIp + "|" + p.fragment.protocol + "|" + p.ipId;
  }

  /*
   * 重组成功后把完整 TCP 报文写回承载包。
   * 校验失败时一字不写（包保持 ip_fragment 证据状态），返回 false。
   */
  function decode(packet, bytes) {
    if (bytes.length < 20) return false;
    var v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var length = (bytes[12] >> 4) * 4;
    if (length < 20 || length > bytes.length) return false;
    packet.srcPort = v.getUint16(0);
    packet.dstPort = v.getUint16(2);
    packet.seq = v.getUint32(4);
    packet.ack = v.getUint32(8);
    packet.flags = bytes[13];
    packet.window = v.getUint16(14);
    packet.tcpHeaderLen = length;
    packet.payload = bytes.slice(length);
    packet.payloadCapturedLen = packet.payloadDeclaredLen = packet.payload.length;
    packet.discardReason = null;
    return true;
  }

  function assembleGroup(key, members) {
    var first = members[0];
    var rec = {
      key: key,
      srcIp: first.srcIp,
      dstIp: first.dstIp,
      protocol: first.fragment.protocol,
      ipId: first.ipId,
      indexes: members
        .map(function (p) {
          return p.index;
        })
        .sort(function (a, b) {
          return a - b;
        }),
      members: [],
      status: "incomplete",
      detail: "",
      totalLen: null,
      declaredTotals: [],
      capturedBytes: 0,
      dupBytes: 0,
      carrierIndex: null,
      holes: [],
      conflicts: [],
      sources: [],
      invalidFragments: [],
    };

    /* 确定性处理顺序：按分片偏移，再按包号 */
    var sorted = members.slice().sort(function (a, b) {
      return a.fragment.offset - b.fragment.offset || a.index - b.index;
    });

    /* 逐分片合法性检查 + 字节落位到绝对网格（重复去重、矛盾留证） */
    var grid = new Map(); // pos -> {byte, owner}
    var conflictAt = new Map(); // pos -> {pos, byPkt}
    sorted.forEach(function (p) {
      var f = p.fragment;
      rec.members.push({
        index: p.index,
        offset: f.offset,
        more: f.more,
        declared: f.declared,
        captured: f.bytes.length,
        truncated: f.bytes.length < f.declared,
      });
      if (f.more && f.declared % 8 !== 0) {
        rec.invalidFragments.push({
          index: p.index,
          reason: "non_last_length_not_multiple_of_8",
          declared: f.declared,
        });
      }
      if (f.offset + f.declared > MAX_IP_PAYLOAD) {
        rec.invalidFragments.push({
          index: p.index,
          reason: "beyond_max_datagram",
          offset: f.offset,
          declared: f.declared,
        });
      }
      for (var i = 0; i < f.bytes.length; i++) {
        var pos = f.offset + i;
        var b = f.bytes[i];
        var cur = grid.get(pos);
        if (!cur) {
          grid.set(pos, { byte: b, owner: p.index });
          rec.capturedBytes++;
        } else if (cur.byte === b) {
          rec.dupBytes++; // 完全相同的重复字节：不增加任何内容
        } else {
          var c = conflictAt.get(pos);
          if (!c) {
            c = { pos: pos, byPkt: {} };
            c.byPkt[cur.owner] = cur.byte;
            conflictAt.set(pos, c);
          }
          c.byPkt[p.index] = b;
        }
      }
    });

    /* 终止长度：所有末片必须声明同一个总长，且任何分片不得越过它 */
    var totals = [];
    sorted.forEach(function (p) {
      if (p.fragment.more) return;
      var t = p.fragment.offset + p.fragment.declared;
      if (totals.indexOf(t) < 0) totals.push(t);
    });
    totals.sort(function (a, b) {
      return a - b;
    });
    rec.declaredTotals = totals;
    var lengthProblems = [];
    if (totals.length > 1) {
      lengthProblems.push(
        "last fragments declare different totals " + totals.join(","),
      );
    } else if (totals.length === 1) {
      rec.totalLen = totals[0];
      sorted.forEach(function (p) {
        var end = p.fragment.offset + p.fragment.declared;
        if (end > rec.totalLen) {
          lengthProblems.push(
            "pkt" +
              p.index +
              " ends at " +
              end +
              " beyond declared total " +
              rec.totalLen,
          );
        }
      });
    }
    var lengthMismatch = lengthProblems.length > 0;
    if (lengthMismatch) rec.totalLen = null;

    /* 覆盖区间 -> 缺口（总长未知时只能列已覆盖区之间的缺口） */
    var positions = Array.from(grid.keys()).sort(function (a, b) {
      return a - b;
    });
    var runs = [];
    positions.forEach(function (pos) {
      var last = runs[runs.length - 1];
      if (last && pos === last.end) last.end = pos + 1;
      else runs.push({ start: pos, end: pos + 1 });
    });
    var cursor = 0;
    runs.forEach(function (r) {
      if (r.start > cursor) rec.holes.push({ start: cursor, end: r.start });
      cursor = Math.max(cursor, r.end);
    });
    if (rec.totalLen != null && cursor < rec.totalLen) {
      rec.holes.push({ start: cursor, end: rec.totalLen });
    }

    /* 矛盾重叠 -> 冲突区间（相邻位置合并，候选字节与来源包号全保留） */
    Array.from(conflictAt.keys())
      .sort(function (a, b) {
        return a - b;
      })
      .forEach(function (pos) {
        var entry = conflictAt.get(pos);
        var last = rec.conflicts[rec.conflicts.length - 1];
        if (last && pos === last.end) {
          last.end = pos + 1;
          last.entries.push(entry);
        } else {
          rec.conflicts.push({ start: pos, end: pos + 1, entries: [entry] });
        }
      });

    /* 来源追溯：连续同包区间（冲突位置记首个落位包，候选字节见 conflicts） */
    positions.forEach(function (pos) {
      var owner = grid.get(pos).owner;
      var last = rec.sources[rec.sources.length - 1];
      if (last && last.packetIndex === owner && pos === last.end) {
        last.end = pos + 1;
      } else {
        rec.sources.push({ start: pos, end: pos + 1, packetIndex: owner });
      }
    });

    /* 状态裁定：任一硬约束不满足都不产出可信正文 */
    var hasFirst = false;
    sorted.forEach(function (p) {
      if (p.fragment.offset === 0) hasFirst = true;
    });

    var reasons = [];
    rec.invalidFragments.forEach(function (x) {
      reasons.push("pkt" + x.index + " " + x.reason);
    });
    lengthProblems.forEach(function (s) {
      reasons.push(s);
    });
    if (rec.conflicts.length) {
      reasons.push(
        "contradictory overlap at " +
          rec.conflicts
            .map(function (c) {
              return c.start + ".." + c.end;
            })
            .join(","),
      );
    }
    if (!hasFirst) reasons.push("missing first fragment");
    if (!totals.length) reasons.push("missing last fragment");
    if (rec.holes.length) {
      reasons.push(
        "holes at " +
          rec.holes
            .map(function (h) {
              return h.start + ".." + h.end;
            })
            .join(","),
      );
    }
    rec.detail = reasons.join("; ");

    if (rec.invalidFragments.length) rec.status = "invalid_fragment";
    else if (lengthMismatch) rec.status = "length_mismatch";
    else if (rec.conflicts.length) rec.status = "conflict";
    else if (!hasFirst || !totals.length || rec.holes.length)
      rec.status = "incomplete";
    else {
      var bytes = new Uint8Array(rec.totalLen);
      positions.forEach(function (pos) {
        bytes[pos] = grid.get(pos).byte;
      });
      var carrier = null;
      for (var i = 0; i < sorted.length; i++) {
        if (sorted[i].fragment.offset === 0) {
          carrier = sorted[i];
          break;
        }
      }
      if (decode(carrier, bytes)) {
        rec.status = "complete";
        rec.carrierIndex = carrier.index;
      } else {
        rec.status = "invalid_tcp";
        rec.detail = "reassembled bytes are not a valid TCP segment";
      }
    }
    return rec;
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
      var rec = assembleGroup(key, members);
      // 双向追溯：每个分片包都能找到自己的组与全部成员包号
      members.forEach(function (p) {
        p.fragmentIndexes = rec.indexes.slice();
        p.fragmentGroup = key;
      });
      analysis.fragmentGroups.push(rec);
    });
    return analysis;
  }

  return { assemble: assemble };
});
