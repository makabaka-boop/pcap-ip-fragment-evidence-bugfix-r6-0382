/*
 * 独立参考 TCP 重组器：与生产代码 (js/core/reassemble.js) 不同思路实现，
 * 直接维护“绝对位置 -> 字节 + 持有包号”的映射，逐字节裁定重传/冲突/缺口，
 * 用于对拍。只处理测试构造的、规模很小的样本。
 *
 * 坐标规则刻意对齐真实 TCP 语义但独立实现：
 *  - 锚点 = 方向上第一个观测包的 seq（乱序到达时通常就是 SYN/最早包），
 *    之后所有序号按 32 位有符号差换算（自动支持回绕）；
 *  - SYN 占一个序号，数据从 seq+1 开始；FIN 位于 seq+declLen。
 */
"use strict";

function s32(x) {
  return x | 0;
}

function referenceReassemble(packets) {
  var SYN = 0x02,
    FIN = 0x01,
    RST = 0x04;
  var dirs = [newDir(), newDir()];

  function classify(p) {
    var a = p.srcIp + ":" + p.srcPort,
      b = p.dstIp + ":" + p.dstPort;
    return a < b ? 0 : 1;
  }

  // —— 第一遍：锚点与控制事件 ——
  packets.forEach(function (p) {
    if (!p.srcIp || p.srcPort == null || p.discardReason) return;
    var d = dirs[classify(p)];
    d.seen = true;
    if (d.base == null) d.base = p.seq >>> 0;
    var seqAbs = toAbs(p.seq, d.base);
    if (p.flags & SYN && d.synAbs == null) d.synAbs = seqAbs;
    if (p.flags & RST) d.rst = true;
  });

  // —— 第二遍：填字节、FIN、乱序/重传统计 ——
  packets.forEach(function (p) {
    if (!p.srcIp || p.srcPort == null || p.discardReason) return;
    var d = dirs[classify(p)];
    var isSyn = (p.flags & SYN) !== 0,
      isFin = (p.flags & FIN) !== 0;
    var seqAbs = toAbs(p.seq, d.base);
    var dataStart = isSyn ? seqAbs + 1 : seqAbs;
    var cap = p.payloadCapturedLen,
      decl = p.payloadDeclaredLen;

    if (d.hw != null && (cap > 0 || decl > 0) && dataStart < d.hw)
      d.oooPkts.add(p.index);
    if (cap > 0 || decl > 0)
      d.hw = Math.max(d.hw == null ? -Infinity : d.hw, dataStart + cap);

    for (var i = 0; i < cap; i++) {
      var pos = dataStart + i;
      var byte = p.payload[i];
      var existing = d.cells.get(pos);
      if (existing === undefined) {
        d.cells.set(pos, { byte: byte, owner: p.index });
      } else if (existing.byte === byte) {
        d.retransPkts.add(p.index);
      } else {
        d.conflictPkts.add(p.index);
        if (!existing.candidates) existing.candidates = [];
        existing.candidates.push({ byte: byte, owner: p.index });
      }
    }
    if (decl > 0) {
      d.dataLo = Math.min(d.dataLo, dataStart);
      d.declHi = Math.max(d.declHi, dataStart + decl);
    }
    if (isFin) {
      var finPos = seqAbs + decl;
      if (d.finAbs == null) d.finAbs = finPos;
      else if (d.finAbs !== finPos) d.finChanged = true;
    }
  });

  return dirs.map(finalize);
}

function newDir() {
  return {
    seen: false,
    base: null,
    synAbs: null,
    finAbs: null,
    cells: new Map(),
    dataLo: Infinity,
    declHi: -Infinity,
    hw: null,
    retransPkts: new Set(),
    conflictPkts: new Set(),
    oooPkts: new Set(),
    rst: false,
  };
}

function toAbs(u32, base) {
  return base + s32((u32 >>> 0) - (base >>> 0));
}

function finalize(d) {
  var origin =
    d.synAbs != null
      ? d.synAbs
      : d.dataLo === Infinity
        ? d.base || 0
        : d.dataLo;
  var dataOrigin = d.synAbs != null ? origin + 1 : origin;
  var extentEnd =
    d.finAbs != null
      ? d.finAbs
      : d.declHi === -Infinity
        ? dataOrigin
        : d.declHi;

  var positions = Array.from(d.cells.keys()).sort(function (a, b) {
    return a - b;
  });
  var frags = [];
  positions.forEach(function (pos) {
    var last = frags[frags.length - 1];
    if (last && pos === last.end) last.end = pos + 1;
    else frags.push({ start: pos, end: pos + 1 });
  });

  var gaps = [];
  for (var i = 1; i < frags.length; i++) {
    if (frags[i].start > frags[i - 1].end) {
      gaps.push({
        start: frags[i - 1].end,
        end: frags[i].start,
        kind: "internal",
      });
    }
  }
  if (d.finAbs != null && frags.length) {
    if (frags[0].start > dataOrigin)
      gaps.unshift({ start: dataOrigin, end: frags[0].start, kind: "leading" });
    if (frags[frags.length - 1].end < d.finAbs) {
      gaps.push({
        start: frags[frags.length - 1].end,
        end: d.finAbs,
        kind: "trailing",
      });
    }
  }

  var conflictPositions = [];
  d.cells.forEach(function (cell, pos) {
    if (cell.candidates) conflictPositions.push(pos);
  });
  conflictPositions.sort(function (a, b) {
    return a - b;
  });
  var conflictRanges = [];
  conflictPositions.forEach(function (pos) {
    var last = conflictRanges[conflictRanges.length - 1];
    if (last && pos === last.end) last.end = pos + 1;
    else conflictRanges.push({ start: pos, end: pos + 1 });
  });

  return {
    origin: origin,
    dataOrigin: dataOrigin,
    extentEnd: extentEnd,
    frags: frags,
    gaps: gaps,
    conflictRanges: conflictRanges,
    retransPkts: Array.from(d.retransPkts),
    conflictPkts: Array.from(d.conflictPkts),
    oooPkts: Array.from(d.oooPkts),
    byteAt: function (pos) {
      var c = d.cells.get(pos);
      return c ? c.byte : undefined;
    },
    ownerAt: function (pos) {
      var c = d.cells.get(pos);
      return c ? c.owner : undefined;
    },
    candidatesAt: function (pos) {
      var c = d.cells.get(pos);
      if (!c) return [];
      var set = new Set([c.byte]);
      (c.candidates || []).forEach(function (x) {
        set.add(x.byte);
      });
      return Array.from(set).sort(function (a, b) {
        return a - b;
      });
    },
  };
}

module.exports = { referenceReassemble: referenceReassemble };
