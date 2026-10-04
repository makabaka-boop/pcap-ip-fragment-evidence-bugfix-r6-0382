/*
 * TCP 双向重组（与环境无关）。
 *
 * 关键原则：
 *  - 只按 (连接四元组, 方向, 序号) 重组，绝不按抓包到达顺序拼接；
 *  - 相同字节的重传去重；不一致的重叠 -> 冲突，保留双方证据，不选边覆盖；
 *  - 没抓到的字节区间一律是显式 gap，绝不用 0、后续包或想象内容填充；
 *  - 32 位序号回绕：以已观测区间中心为参考做有符号距离换算，天然支持回绕；
 *  - snaplen 截断的段：仅落入实际抓到的前缀，声明而缺失的尾部仍算缺口。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(
      require("./pcap"),
      require("./util"),
      require("./fragments"),
    );
  } else
    root.PcapReassemble = factory(
      root.PcapCore,
      root.PcapUtil,
      root.PcapFragments,
    );
})(typeof self !== "undefined" ? self : this, function (Core, Util, Fragments) {
  "use strict";

  var MOD32 = 0x100000000;

  function s32(x) {
    return x | 0;
  }

  /* u32 序号 -> 以 refAbs 附近为参考的绝对序号（支持回绕） */
  function toAbs(u32, refAbs) {
    return refAbs + s32((u32 >>> 0) - (refAbs >>> 0));
  }

  function endpointKey(ip, port) {
    return ip + ":" + port;
  }

  function connKeyOf(pkt) {
    var a = endpointKey(pkt.srcIp, pkt.srcPort);
    var b = endpointKey(pkt.dstIp, pkt.dstPort);
    return a < b ? a + "|" + b : b + "|" + a;
  }

  function dirOf(pkt) {
    var a = endpointKey(pkt.srcIp, pkt.srcPort);
    var b = endpointKey(pkt.dstIp, pkt.dstPort);
    return a < b ? 0 : 1; // 0: A(endpoint 较小) -> B，1: B -> A
  }

  function DirectionStream() {
    this.present = false;
    this.baseAbs = null; // 第一个占用序号空间的事件的绝对序号锚点
    this.spanLo = Infinity;
    this.spanHi = -Infinity;
    this.segments = [];
    this.synAbs = null;
    this.synPktIndexes = [];
    this.synRetrans = 0;
    this.finAbs = null;
    this.finPktIndex = null;
    this.finRetrans = 0;
    this.rstPktIndexes = [];
    this.highWater = null; // 到达顺序上见过的最高数据末端（乱序判定）
  }

  DirectionStream.prototype._ref = function () {
    return Math.floor((this.spanLo + this.spanHi) / 2);
  };

  DirectionStream.prototype._observe = function (absStart, absEndExcl) {
    if (absStart < this.spanLo) this.spanLo = absStart;
    if (absEndExcl > this.spanHi) this.spanHi = absEndExcl;
  };

  /* 处理一个成功解析出 TCP 头的包（纯 ACK 也可，用于锚点/方向存在感） */
  DirectionStream.prototype.add = function (pkt) {
    this.present = true;
    var F = Core.FLAGS;
    var isSyn = (pkt.flags & F.SYN) !== 0;
    var isFin = (pkt.flags & F.FIN) !== 0;
    var isRst = (pkt.flags & F.RST) !== 0;

    var refAbs = this.baseAbs == null ? pkt.seq >>> 0 : this._ref();
    var seqAbs = this.baseAbs == null ? pkt.seq >>> 0 : toAbs(pkt.seq, refAbs);
    if (this.baseAbs == null) this.baseAbs = seqAbs;
    pkt.absSeq = seqAbs;

    if (isRst) {
      this.rstPktIndexes.push(pkt.index);
      pkt.tcpEvent = "RST";
    }

    if (isSyn) {
      this.synPktIndexes.push(pkt.index);
      pkt.tcpEvent = pkt.tcpEvent ? pkt.tcpEvent + "+SYN" : "SYN";
      if (this.synAbs == null) {
        this.synAbs = seqAbs;
        this._observe(seqAbs, seqAbs + 1);
      } else if (seqAbs === this.synAbs) {
        this.synRetrans++;
      } else {
        this.synRetrans++;
        pkt.synSeqChanged = true; // 非同序号 SYN，异常但保留证据
      }
    }

    var capLen = pkt.payloadCapturedLen || 0;
    var declLen = pkt.payloadDeclaredLen || 0;
    // SYN 占用一个序号，SYN 上若携带数据（罕见），数据从 seq+1 开始
    var dataAbsStart = isSyn ? seqAbs + 1 : seqAbs;

    if (capLen > 0 || declLen > 0) {
      var seg = {
        start: dataAbsStart,
        declaredEnd: dataAbsStart + declLen,
        capLen: capLen,
        data: pkt.payload,
        pktIndex: pkt.index,
      };
      this.segments.push(seg);
      this._observe(dataAbsStart, dataAbsStart + declLen);

      // 乱序：本包首字节落在已见过的最高水位之前
      if (this.highWater !== null && dataAbsStart < this.highWater)
        pkt.outOfOrder = true;
      var endSeen = dataAbsStart + capLen;
      if (this.highWater === null || endSeen > this.highWater)
        this.highWater = endSeen;
    }

    if (isFin) {
      // FIN 位于数据之后：seq + 声明载荷长度（SYN+FIN 时数据从 +1 起，FIN 在 +decl+1）
      var finPos = seqAbs + declLen;
      pkt.finPos = finPos;
      if (this.finAbs == null) {
        this.finAbs = finPos;
        this.finPktIndex = pkt.index;
        this._observe(finPos, finPos + 1);
      } else if (finPos === this.finAbs) {
        this.finRetrans++;
      } else {
        this.finRetrans++;
        pkt.finPosChanged = true;
      }
    }
  };

  function insertFrag(frags, nf) {
    var lo = 0,
      hi = frags.length;
    while (lo < hi) {
      var mid = (lo + hi) >> 1;
      if (frags[mid].start < nf.start) lo = mid + 1;
      else hi = mid;
    }
    frags.splice(lo, 0, nf);
  }

  /* 从区间 [baseS,baseE) 中减去若干不重叠有序子区间，返回剩余区间列表 */
  function subtractRanges(base, covers) {
    var out = [];
    var cur = base[0];
    var end = base[1];
    covers.forEach(function (cv) {
      var cs = Math.max(cur, cv[0]),
        ce = Math.min(end, cv[1]);
      if (cs > cur) out.push([cur, cs]);
      cur = Math.max(cur, ce);
    });
    if (cur < end) out.push([cur, end]);
    return out;
  }

  function makeOwner(pktIndex, len) {
    var o = new Uint32Array(len);
    o.fill(pktIndex);
    return o;
  }

  /*
   * 合并算法：
   * 碎片(frag)是一段连续覆盖区间 [start,end)，内部由互不重叠、按序排列的
   * piece 组成（每个 piece 来自一个包的一段字节，带 owner）。piece 总数 O(段数)。
   * 新段可能与多个碎片重叠，也可能横跨碎片间的缺口把它们焊成一个碎片——
   * 因此要找出所有相交（含相邻）碎片，逐 piece 逐字节比较重叠区，
   * 再把“没有旧内容”的子区间作为新 piece 并入。
   */
  DirectionStream.prototype.build = function (packets) {
    var segs = this.segments.slice().sort(function (a, b) {
      return (
        a.start - b.start ||
        a.declaredEnd - b.declaredEnd ||
        a.pktIndex - b.pktIndex
      );
    });

    var frags = []; // [{start,end,pieces:[{s,e,bytes,owner}]}]
    var conflicts = [];
    var conflictAt = Object.create(null);

    function comparePiece(piece, seg, ovS, ovE, pkt) {
      for (var p = ovS; p < ovE; p++) {
        var oldByte = piece.bytes[p - piece.s];
        var newByte = seg.data[p - seg.start];
        if (oldByte === newByte) {
          pkt.dupBytes = (pkt.dupBytes || 0) + 1;
        } else {
          pkt.conflictBytes = (pkt.conflictBytes || 0) + 1;
          var c = conflictAt[p];
          if (!c) {
            c = { pos: p, byPkt: {} };
            c.byPkt[piece.owner[p - piece.s]] = oldByte;
            conflictAt[p] = c;
            conflicts.push(c);
          }
          c.byPkt[seg.pktIndex] = newByte;
        }
      }
    }

    function fragOverlap(f, cs, ce, cb) {
      // 二分找到第一个可能相交的 piece：piece.s < ce
      var lo = 0,
        hi = f.pieces.length;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (f.pieces[mid].e <= cs) lo = mid + 1;
        else hi = mid;
      }
      for (var i = lo; i < f.pieces.length; i++) {
        var pc = f.pieces[i];
        if (pc.s >= ce) break;
        var ovS = Math.max(pc.s, cs),
          ovE = Math.min(pc.e, ce);
        if (ovS < ovE) cb(pc, ovS, ovE);
      }
    }

    segs.forEach(function (seg) {
      var cs = seg.start;
      var ce = seg.start + seg.capLen;
      if (ce <= cs) return;
      var pkt = packets[seg.pktIndex];

      // 找所有相交或相邻（ce>=f.start && cs<=f.end）的碎片
      var first = -1,
        last = -1;
      for (var i = 0; i < frags.length; i++) {
        if (frags[i].end < cs) continue;
        if (frags[i].start > ce) break;
        if (first < 0) first = i;
        last = i;
      }

      if (first < 0) {
        // 插入到有序位置
        var nf = {
          start: cs,
          end: ce,
          pieces: [
            {
              s: cs,
              e: ce,
              bytes: seg.data.slice(0),
              owner: makeOwner(seg.pktIndex, ce - cs),
            },
          ],
        };
        insertFrag(frags, nf);
        return;
      }

      // 1) 与每个旧碎片的重叠区逐字节比较
      for (var j = first; j <= last; j++) {
        fragOverlap(frags[j], cs, ce, function (pc, ovS, ovE) {
          comparePiece(pc, seg, ovS, ovE, pkt);
        });
      }

      // 2) 计算新段未被旧碎片覆盖的子区间（旧碎片彼此可能不相连）
      var cover = [];
      for (var k = first; k <= last; k++) {
        cover.push([Math.max(frags[k].start, cs), Math.min(frags[k].end, ce)]);
      }
      var holes = subtractRanges([cs, ce], cover);

      // 3) 合并：新边界 = 并集；pieces = 旧 pieces + 填空 pieces
      var newStart = Math.min(cs, frags[first].start);
      var newEnd = Math.max(ce, frags[last].end);
      var pieces = [];
      for (var m = first; m <= last; m++) {
        frags[m].pieces.forEach(function (pc) {
          pieces.push(pc);
        });
      }
      holes.forEach(function (h) {
        var off = h[0] - seg.start;
        var len = h[1] - h[0];
        pieces.push({
          s: h[0],
          e: h[1],
          bytes: seg.data.slice(off, off + len),
          owner: makeOwner(seg.pktIndex, len),
        });
      });
      pieces.sort(function (a, b) {
        return a.s - b.s;
      });
      var merged = { start: newStart, end: newEnd, pieces: pieces };
      frags.splice(first, last - first + 1, merged);
    });

    // 连续冲突位置合并为区间
    conflicts.sort(function (a, b) {
      return a.pos - b.pos;
    });
    var conflictRanges = [];
    conflicts.forEach(function (c) {
      var lastC = conflictRanges[conflictRanges.length - 1];
      if (lastC && c.pos === lastC.end) {
        lastC.end = c.pos + 1;
        lastC.entries.push(c);
      } else {
        conflictRanges.push({ start: c.pos, end: c.pos + 1, entries: [c] });
      }
    });

    // 显示原点：有 SYN 用 SYN（数据相对偏移从 1 起），否则用最早数据
    var origin;
    if (this.synAbs != null) origin = this.synAbs;
    else if (segs.length) origin = segs[0].start;
    else origin = this.baseAbs == null ? 0 : this.baseAbs;

    var extentEnd = null;
    if (this.finAbs != null) extentEnd = this.finAbs + 1;
    else if (segs.length) {
      extentEnd = segs.reduce(function (m, s) {
        return Math.max(m, s.declaredEnd);
      }, -Infinity);
    }

    // 最终拼接：每个碎片只拷贝一次
    var finalized = frags.map(function (f) {
      var len = f.end - f.start;
      var bytes = new Uint8Array(len);
      var owner = new Uint32Array(len);
      f.pieces.forEach(function (pc) {
        bytes.set(pc.bytes, pc.s - f.start);
        owner.set(pc.owner, pc.s - f.start);
      });
      return { start: f.start, end: f.end, bytes: bytes, owner: owner };
    });

    var gaps = [];
    for (var fi = 1; fi < finalized.length; fi++) {
      if (finalized[fi].start > finalized[fi - 1].end) {
        gaps.push({
          start: finalized[fi - 1].end,
          end: finalized[fi].start,
          kind: "internal",
        });
      }
    }
    var dataOrigin = origin + (this.synAbs != null ? 1 : 0);
    if (this.finAbs != null && finalized.length) {
      if (finalized[0].start > dataOrigin) {
        gaps.unshift({
          start: dataOrigin,
          end: finalized[0].start,
          kind: "leading",
        });
      }
      // FIN 自身占用 finAbs 这一个序号，数据区间只到 finAbs 为止
      if (finalized[finalized.length - 1].end < this.finAbs) {
        gaps.push({
          start: finalized[finalized.length - 1].end,
          end: this.finAbs,
          kind: "trailing",
        });
      }
    }
    gaps.sort(function (a, b) {
      return a.start - b.start;
    });

    if (segs.length) {
      segs.forEach(function (seg) {
        var pkt = packets[seg.pktIndex];
        if ((pkt.dupBytes || 0) > 0) pkt.isRetrans = true;
      });
    }

    return {
      present: this.present,
      origin: origin,
      synAbs: this.synAbs,
      finAbs: this.finAbs,
      finPktIndex: this.finPktIndex,
      synPktIndexes: this.synPktIndexes,
      synRetrans: this.synRetrans,
      finRetrans: this.finRetrans,
      rstPktIndexes: this.rstPktIndexes,
      frags: finalized,
      conflictRanges: conflictRanges,
      gaps: gaps,
      extentEnd: extentEnd,
      complete: gaps.length === 0,
    };
  };

  function makeOwner(pktIndex, len) {
    var o = new Uint32Array(len);
    o.fill(pktIndex);
    return o;
  }

  /*
   * 将碎片 / 缺口 / 冲突合成有序的 chunk 列表（冻结结果的标准表示）：
   *  {kind:'data', start,end, bytes, owner}
   *  {kind:'gap',  start,end, gapKind}
   *  {kind:'conflict', start,end, entries:[{pos,byPkt}]}
   * 冲突位置处的数据被拆出，绝不与任何一方字节混在一起。
   * 做法：在每个冲突区间边界把碎片切成带 [s,e) 的 data 事件，然后按位置单遍扫掠；
   * data 事件彼此贴合即归并，遇到 gap/conflict 则断开。
   */
  function buildChunks(built) {
    var events = []; // [start, end, kind, payload]
    built.frags.forEach(function (f) {
      var cuts = built.conflictRanges.filter(function (c) {
        return c.start >= f.start && c.end <= f.end;
      });
      var cur = f.start;
      cuts.forEach(function (c) {
        if (c.start > cur) events.push([cur, c.start, "data", f]);
        events.push([c.start, c.end, "conflict", c]);
        cur = c.end;
      });
      if (cur < f.end) events.push([cur, f.end, "data", f]);
    });
    built.gaps.forEach(function (g) {
      events.push([g.start, g.end, "gap", g]);
    });

    events.sort(function (a, b) {
      if (a[0] !== b[0]) return a[0] - b[0];
      // 同位时冲突事件在 data 之前（正常切割已保证不重叠，这里只作确定性排序）
      if (a[2] !== b[2]) return a[2] === "conflict" ? -1 : 1;
      return a[1] - b[1];
    });

    var chunks = [];
    function pushDataFrom(f, s, e) {
      var nb = f.bytes.slice(s - f.start, e - f.start);
      var no = f.owner.slice(s - f.start, e - f.start);
      var last = chunks[chunks.length - 1];
      if (last && last.kind === "data" && last.end === s) {
        var b2 = new Uint8Array(last.bytes.length + nb.length);
        b2.set(last.bytes, 0);
        b2.set(nb, last.bytes.length);
        var o2 = new Uint32Array(last.owner.length + no.length);
        o2.set(last.owner, 0);
        o2.set(no, last.owner.length);
        last.end = e;
        last.bytes = b2;
        last.owner = o2;
      } else {
        chunks.push({ kind: "data", start: s, end: e, bytes: nb, owner: no });
      }
    }

    events.forEach(function (ev) {
      var s = ev[0],
        e = ev[1],
        kind = ev[2],
        pl = ev[3];
      if (kind === "data") pushDataFrom(pl, s, e);
      else if (kind === "gap")
        chunks.push({ kind: "gap", start: s, end: e, gapKind: pl.kind });
      else
        chunks.push({
          kind: "conflict",
          start: s,
          end: e,
          entries: pl.entries,
        });
    });
    return chunks;
  }

  /*
   * 全量重组入口。返回可冻结结果（结构化克隆安全，payload 为独立 Uint8Array）。
   */
  function reassemble(analysis) {
    Fragments.assemble(analysis);
    var packets = analysis.packets;
    var conns = new Map();

    packets.forEach(function (pkt) {
      if (!pkt.srcIp || pkt.srcPort == null) return; // 非 IPv4/TCP 包不参与
      var key = connKeyOf(pkt);
      var c = conns.get(key);
      if (!c) {
        var parts = key.split("|");
        c = {
          id: "c" + conns.size,
          key: key,
          endpointA: parts[0],
          endpointB: parts[1],
          dirs: [new DirectionStream(), new DirectionStream()],
          pktIndexes: [],
        };
        conns.set(key, c);
      }
      c.pktIndexes.push(pkt.index);
      pkt.connId = c.id;
      pkt.dir = dirOf(pkt);
      c.dirs[pkt.dir].add(pkt);
    });

    var connList = [];
    conns.forEach(function (c) {
      var built = [c.dirs[0].build(packets), c.dirs[1].build(packets)];
      var dirsOut = built.map(function (b, d) {
        var chunks = buildChunks(b);
        enrichPackets(c.dirs[d], b, packets);
        return {
          present: b.present,
          origin: b.origin,
          synAbs: b.synAbs,
          finAbs: b.finAbs,
          complete: b.complete,
          gaps: b.gaps,
          conflictRanges: b.conflictRanges,
          chunks: chunks,
          stats: dirStats(b),
        };
      });
      connList.push({
        id: c.id,
        key: c.key,
        endpointA: c.endpointA,
        endpointB: c.endpointB,
        pktIndexes: c.pktIndexes.slice(),
        dirs: dirsOut,
      });
    });

    // 连接排序：按第一个包出现的顺序，稳定直观
    connList.sort(function (a, b) {
      return a.pktIndexes[0] - b.pktIndexes[0];
    });
    connList.forEach(function (c, i) {
      c.order = i;
    });

    // 表用相对序号
    packets.forEach(function (pkt) {
      if (pkt.connId == null || pkt.absSeq == null) return;
      var c = connList.find(function (x) {
        return x.id === pkt.connId;
      });
      pkt.relSeq = pkt.absSeq - c.dirs[pkt.dir].origin;
    });

    var stats = globalStats(packets, connList, analysis);
    return {
      header: analysis.header,
      fileSize: analysis.fileSize,
      limits: analysis.limits,
      stoppedTruncated: analysis.stoppedTruncated,
      connections: connList,
      packets: packets.map(publicPacket),
      fragmentGroups: analysis.fragmentGroups,
      stats: stats,
      frozenAt: new Date().toISOString(),
    };
  }

  function dirStats(b) {
    var dataBytes = 0,
      gapBytes = 0,
      conflictBytes = 0;
    b.gaps.forEach(function (g) {
      gapBytes += g.end - g.start;
    });
    b.conflictRanges.forEach(function (c) {
      conflictBytes += c.end - c.start;
    });
    b.frags.forEach(function (f) {
      dataBytes += f.end - f.start;
    });
    return {
      dataBytes: dataBytes,
      gapBytes: gapBytes,
      conflictBytes: conflictBytes,
      syn: b.synAbs != null,
      fin: b.finAbs != null,
      reset: b.rstPktIndexes.length > 0,
      synRetrans: b.synRetrans,
      finRetrans: b.finRetrans,
      rstCount: b.rstPktIndexes.length,
    };
  }

  function enrichPackets(dirStream, built, packets) {
    // 到达顺序乱序标记在 add() 已写；这里仅补充流级标签引用
    dirStream.segments.forEach(function (seg) {
      var pkt = packets[seg.pktIndex];
      if (!pkt) return;
      if ((pkt.dupBytes || 0) > 0 && !pkt.isRetrans) pkt.isRetrans = true;
    });
  }

  function globalStats(packets, connList, analysis) {
    var s = {
      packetCount: packets.length,
      parsedTcp: 0,
      discarded: 0,
      retransPackets: 0,
      conflictPackets: 0,
      outOfOrderPackets: 0,
      snapTruncatedPackets: 0,
      payloadTruncatedPackets: 0,
      totalDataBytes: 0,
      totalGapBytes: 0,
      totalConflictBytes: 0,
      connectionCount: 0,
    };
    packets.forEach(function (p) {
      if (p.discardReason) s.discarded++;
      else if (p.srcIp) s.parsedTcp++;
      if (p.isRetrans) s.retransPackets++;
      if (p.conflictBytes) s.conflictPackets++;
      if (p.outOfOrder) s.outOfOrderPackets++;
      if (p.snapTruncated) s.snapTruncatedPackets++;
      if (p.payloadTruncated) s.payloadTruncatedPackets++;
    });
    connList.forEach(function (c) {
      c.dirs.forEach(function (d) {
        s.totalDataBytes += d.stats.dataBytes;
        s.totalGapBytes += d.stats.gapBytes;
        s.totalConflictBytes += d.stats.conflictBytes;
      });
    });
    s.connectionCount = connList.length;
    return s;
  }

  function publicPacket(p) {
    return {
      index: p.index,
      tsText: p.tsText,
      inclLen: p.inclLen,
      origLen: p.origLen,
      snapTruncated: !!p.snapTruncated,
      srcIp: p.srcIp || null,
      dstIp: p.dstIp || null,
      srcPort: p.srcPort ?? null,
      dstPort: p.dstPort ?? null,
      seq: p.seq ?? null,
      ack: p.ack ?? null,
      relSeq: p.relSeq ?? null,
      flags: p.flags || 0,
      flagText: flagText(p.flags),
      window: p.window ?? null,
      payloadDeclaredLen: p.payloadDeclaredLen,
      payloadCapturedLen: p.payloadCapturedLen,
      payloadTruncated: !!p.payloadTruncated,
      ipTruncated: !!p.ipTruncated,
      discardReason: p.discardReason || null,
      fragmentIndexes: p.fragmentIndexes || null,
      fragmentGroup: p.fragmentGroup || null,
      connId: p.connId || null,
      dir: p.dir ?? null,
      isRetrans: !!p.isRetrans,
      outOfOrder: !!p.outOfOrder,
      dupBytes: p.dupBytes || 0,
      conflictBytes: p.conflictBytes || 0,
      tcpEvent: p.tcpEvent || null,
      synSeqChanged: !!p.synSeqChanged,
      finPosChanged: !!p.finPosChanged,
    };
  }

  function flagText(flags) {
    if (!flags) return "";
    var F = Core.FLAGS;
    var out = "";
    if (flags & F.FIN) out += "F";
    if (flags & F.SYN) out += "S";
    if (flags & F.RST) out += "R";
    if (flags & F.PSH) out += "P";
    if (flags & F.ACK) out += "A";
    if (flags & F.URG) out += "U";
    return out;
  }

  return {
    MOD32: MOD32,
    toAbs: toAbs,
    connKeyOf: connKeyOf,
    dirOf: dirOf,
    DirectionStream: DirectionStream,
    reassemble: reassemble,
    buildChunks: buildChunks,
    flagText: flagText,
  };
});
