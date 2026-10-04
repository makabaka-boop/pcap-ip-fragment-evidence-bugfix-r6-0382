/*
 * IPv4 分片重组测试：乱序、重复、跨地址同 IP ID、缺口、矛盾重叠、
 * 终止长度不一致、非法分片、抓包截断分片、完整报文追溯、导出一致性，
 * 以及普通未分片报文与分片共存时的既有行为。
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Core = require("../js/core/pcap.js");
const R = require("../js/core/reassemble.js");
const View = require("../js/core/viewmodel.js");
const B = require("./pcap-builder.js");

const PSH = 0x08,
  ACK = 0x10;

function toAb(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}
function reas(buf) {
  return R.reassemble(Core.analyzePcap(toAb(buf)));
}
function reassembledText(dir) {
  let out = "";
  dir.chunks.forEach((ch) => {
    if (ch.kind === "data") {
      for (let i = 0; i < ch.bytes.length; i++)
        out += String.fromCharCode(ch.bytes[i]);
    }
  });
  return out;
}

const A_IP = Buffer.from([10, 1, 0, 1]);
const B_IP = Buffer.from([10, 1, 0, 2]);
const C_IP = Buffer.from([10, 9, 0, 1]);
const D_IP = Buffer.from([10, 9, 0, 2]);

/* 一个分片记录：ipId + 字节偏移 + MF + 原始分片字节 */
function frag(ipId, off, more, data, ips) {
  return {
    frame: B.buildFragFrame({
      ipId: ipId,
      fragWord: ((off / 8) & 0x1fff) | (more ? 0x2000 : 0),
      data: data,
      srcIp: (ips && ips.src) || A_IP,
      dstIp: (ips && ips.dst) || B_IP,
    }),
  };
}

/* 标准被分片报文：20 字节 TCP 头 + 20 字节载荷 = 40 字节 */
function stdSeg() {
  return B.buildTcpSegment({
    srcPort: 4444,
    dstPort: 80,
    seq: 1000,
    flags: PSH | ACK,
    payload: B.str("ABCDEFGHIJKLMNOPQRST"),
  });
}

test("乱序分片：按偏移重组出完整报文，内容可追溯到原始包", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(100, 16, true, seg.slice(16, 32)), // idx 0：中段先到
    frag(100, 32, false, seg.slice(32, 40)), // idx 1：末片
    frag(100, 0, true, seg.slice(0, 16)), // idx 2：首片最后到
  ]);
  const res = reas(pcap);
  assert.equal(res.fragmentGroups.length, 1);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "complete");
  assert.equal(g.totalLen, 40);
  assert.deepEqual(g.indexes, [0, 1, 2]);
  assert.equal(g.carrierIndex, 2); // 载体 = 包号最小的首片
  // 逐段来源追溯：字节区间 -> 原始包号
  assert.deepEqual(
    g.sources.map((s) => [s.start, s.end, s.packetIndex]),
    [
      [0, 16, 2],
      [16, 32, 0],
      [32, 40, 1],
    ],
  );
  // 载体包取得完整 TCP 报文；其余成员保持分片证据状态
  const carrier = res.packets[2];
  assert.equal(carrier.discardReason, null);
  assert.deepEqual(carrier.fragmentIndexes, [0, 1, 2]);
  assert.equal(carrier.fragmentGroup, g.key);
  assert.equal(carrier.payloadCapturedLen, 20);
  assert.equal(res.packets[0].discardReason, "ip_fragment");
  assert.deepEqual(res.packets[0].fragmentIndexes, [0, 1, 2]);
  // TCP 流内容是按序号/偏移还原的原文，不是到达顺序的拼接
  assert.equal(res.connections.length, 1);
  assert.equal(reassembledText(res.connections[0].dirs[0]), "ABCDEFGHIJKLMNOPQRST");
});

test("完全重复的分片：去重，不产生额外内容", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(200, 0, true, seg.slice(0, 16)),
    frag(200, 0, true, seg.slice(0, 16)), // 完全重复的首片
    frag(200, 16, true, seg.slice(16, 32)),
    frag(200, 32, false, seg.slice(32, 40)),
    frag(200, 32, false, seg.slice(32, 40)), // 重复的末片
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "complete");
  assert.equal(g.dupBytes, 24); // 16 + 8 重复字节
  assert.equal(g.totalLen, 40);
  assert.equal(res.connections[0].dirs[0].stats.dataBytes, 20);
  assert.equal(reassembledText(res.connections[0].dirs[0]), "ABCDEFGHIJKLMNOPQRST");
});

test("不同地址相同 IP ID：分组互不干扰", () => {
  const seg1 = B.buildTcpSegment({
    srcPort: 4001,
    dstPort: 80,
    seq: 100,
    flags: PSH | ACK,
    payload: B.str("aaaaaaaaaaaaaaaa"),
  });
  const seg2 = B.buildTcpSegment({
    srcPort: 4002,
    dstPort: 80,
    seq: 100,
    flags: PSH | ACK,
    payload: B.str("BBBBBBBBBBBBBBBB"),
  });
  const cd = { src: C_IP, dst: D_IP };
  const pcap = B.buildPcap([
    frag(300, 0, true, seg1.slice(0, 16)),
    frag(300, 0, true, seg2.slice(0, 16), cd), // 同 ID、不同地址对
    frag(300, 16, true, seg1.slice(16, 32)),
    frag(300, 16, true, seg2.slice(16, 32), cd),
    frag(300, 32, false, seg1.slice(32, 36)),
    frag(300, 32, false, seg2.slice(32, 36), cd),
  ]);
  const res = reas(pcap);
  assert.equal(res.fragmentGroups.length, 2);
  assert.ok(res.fragmentGroups.every((g) => g.status === "complete"));
  assert.equal(res.connections.length, 2);
  const texts = res.connections.map((c) => reassembledText(c.dirs[0])).sort();
  assert.deepEqual(texts, ["BBBBBBBBBBBBBBBB", "aaaaaaaaaaaaaaaa"]);
});

test("缺少中间分片：显式缺口，不产出可读流", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(400, 0, true, seg.slice(0, 16)),
    frag(400, 32, false, seg.slice(32, 40)),
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "incomplete");
  assert.deepEqual(g.holes, [{ start: 16, end: 32 }]);
  assert.equal(res.connections.length, 0); // 没有任何 TCP 流被展示出来
  assert.ok(res.packets.every((p) => p.discardReason === "ip_fragment"));
});

test("缺少首片：leading 缺口 + incomplete", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(401, 16, true, seg.slice(16, 32)),
    frag(401, 32, false, seg.slice(32, 40)),
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "incomplete");
  assert.deepEqual(g.holes, [{ start: 0, end: 16 }]);
  assert.match(g.detail, /missing first fragment/);
  assert.equal(res.connections.length, 0);
});

test("矛盾重叠：冲突候选字节全部留证，不产出可信正文", () => {
  const seg = stdSeg();
  const evil = Buffer.from(seg.slice(0, 16));
  evil[4] = 0xff; // seg[4] 原为 0x00（seq=1000 的高字节）
  evil[9] = 0xff; // seg[9] 原为 0x00（ack=0）
  const pcap = B.buildPcap([
    frag(500, 0, true, seg.slice(0, 16)),
    frag(500, 0, true, evil),
    frag(500, 16, true, seg.slice(16, 32)),
    frag(500, 32, false, seg.slice(32, 40)),
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "conflict");
  assert.equal(g.conflicts.length, 2);
  assert.deepEqual(
    g.conflicts.map((c) => [c.start, c.end]),
    [
      [4, 5],
      [9, 10],
    ],
  );
  // 两个候选字节及其来源包号都保留
  const e0 = g.conflicts[0].entries[0];
  assert.deepEqual(Object.keys(e0.byPkt).map(Number).sort(), [0, 1]);
  assert.deepEqual([e0.byPkt[0], e0.byPkt[1]].sort((a, b) => a - b), [
    0x00,
    0xff,
  ]);
  assert.equal(res.connections.length, 0);
});

test("两个末片声明不同总长：length_mismatch，不产出正文", () => {
  const seg = stdSeg();
  const tail = Buffer.concat([seg.slice(16, 32), Buffer.alloc(8, 0x61)]);
  const pcap = B.buildPcap([
    frag(600, 0, true, seg.slice(0, 16)),
    frag(600, 16, false, seg.slice(16, 32)), // 末片 A：总长 32
    frag(600, 16, false, tail), // 末片 B：总长 40（重叠区字节一致）
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "length_mismatch");
  assert.deepEqual(g.declaredTotals, [32, 40]);
  assert.equal(res.connections.length, 0);
});

test("分片越过末片声明的总长：length_mismatch", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(601, 0, true, seg.slice(0, 16)),
    frag(601, 16, false, seg.slice(16, 32)), // 末片声明总长 32
    frag(601, 32, true, seg.slice(32, 40)), // 却还有 32..40 的非末片
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "length_mismatch");
  assert.match(g.detail, /beyond declared total/);
  assert.equal(res.connections.length, 0);
});

test("非末片长度非 8 倍数：invalid_fragment，不产出正文", () => {
  const seg = stdSeg();
  const pcap = B.buildPcap([
    frag(700, 0, true, seg.slice(0, 20)), // MF 且 20 字节：非法
    frag(700, 24, false, seg.slice(24, 40)),
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "invalid_fragment");
  assert.deepEqual(
    g.invalidFragments.map((x) => x.reason),
    ["non_last_length_not_multiple_of_8"],
  );
  assert.equal(res.connections.length, 0);
});

test("抓包截断的分片：声明而缺失的尾部是显式缺口", () => {
  const seg = stdSeg();
  const lastFrame = B.buildFragFrame({
    ipId: 900,
    fragWord: 16 / 8, // 末片，声明携带 24 字节
    data: seg.slice(16, 40),
    srcIp: A_IP,
    dstIp: B_IP,
  });
  const pcap = B.buildPcap([
    frag(900, 0, true, seg.slice(0, 16)),
    {
      frame: lastFrame,
      origLen: lastFrame.length,
      inclOverride: lastFrame.length - 16, // 只抓到 8 字节分片数据
    },
  ]);
  const res = reas(pcap);
  const g = res.fragmentGroups[0];
  assert.equal(g.status, "incomplete");
  assert.deepEqual(g.holes, [{ start: 24, end: 40 }]);
  assert.equal(g.members[1].declared, 24);
  assert.equal(g.members[1].captured, 8);
  assert.equal(g.members[1].truncated, true);
  assert.equal(res.packets[1].ipTruncated, true);
  assert.equal(res.connections.length, 0);
});

test("重组字节不是合法 TCP：invalid_tcp，不产出正文", () => {
  const seg = Buffer.from(stdSeg());
  seg[12] = 0x10; // dataOffset = 16 字节 < 20：非法 TCP 头
  const pcap = B.buildPcap([
    frag(1000, 0, true, seg.slice(0, 16)),
    frag(1000, 16, true, seg.slice(16, 32)),
    frag(1000, 32, false, seg.slice(32, 40)),
  ]);
  const res = reas(pcap);
  assert.equal(res.fragmentGroups[0].status, "invalid_tcp");
  assert.equal(res.connections.length, 0);
});

test("冻结导出与页面同源：fragmentGroups（含不完整/冲突组）与 fragmentIndexes 都在导出中", () => {
  const seg = stdSeg();
  const evil = Buffer.from(seg.slice(16, 32));
  evil[0] ^= 0xff; // 与同范围的另一片矛盾
  const pcap = B.buildPcap([
    frag(1100, 0, true, seg.slice(0, 16)),
    frag(1100, 16, true, seg.slice(16, 32)),
    frag(1100, 32, false, seg.slice(32, 40)),
    frag(1101, 0, true, seg.slice(0, 16)),
    frag(1101, 16, true, seg.slice(16, 32)),
    frag(1101, 16, true, evil), // 与上一片同范围但字节矛盾 -> 冲突组
    frag(1101, 32, false, seg.slice(32, 40)),
  ]);
  const res = reas(pcap);
  const json = JSON.parse(View.exportJson(res));
  assert.equal(json.fragmentGroups.length, 2);
  const byId = {};
  json.fragmentGroups.forEach((g) => {
    byId[g.ipId] = g;
  });
  assert.equal(byId[1100].status, "complete");
  assert.equal(byId[1101].status, "conflict");
  // 包级追溯进入导出：每个成员包都能找到自己的组
  const member = json.packets.find((p) => p.index === 4);
  assert.deepEqual(member.fragmentIndexes, [3, 4, 5, 6]);
  assert.equal(member.fragmentGroup, byId[1101].key);
  // 完整组的来源区间也随组导出
  assert.ok(byId[1100].sources.length >= 3);
  // TXT 导出同样包含分片证据
  const txt = View.exportText(res);
  assert.match(txt, /IPv4 Fragment Groups/);
  assert.match(txt, /status=conflict/);
  assert.match(txt, /ip-frag\[3,4,5,6\]/);
});

test("普通未分片报文与分片组共存：既有分析行为不变", () => {
  const isn = 42;
  const seg = B.buildTcpSegment({
    srcPort: 2222,
    dstPort: 443,
    seq: 7,
    flags: PSH | ACK,
    payload: B.str("FRAG"),
  });
  const pcap = B.buildPcap([
    // 普通未分片连接（既有行为）
    { srcPort: 1111, dstPort: 80, srcIp: A_IP, dstIp: B_IP, flags: 0x02, seq: isn },
    {
      srcPort: 1111,
      dstPort: 80,
      srcIp: A_IP,
      dstIp: B_IP,
      flags: 0x18,
      seq: isn + 1,
      payload: B.str("plain"),
    },
    { srcPort: 1111, dstPort: 80, srcIp: A_IP, dstIp: B_IP, flags: 0x11, seq: isn + 6 },
    // 另一对地址上的完整分片组
    frag(1200, 0, true, seg.slice(0, 16), { src: C_IP, dst: D_IP }),
    frag(1200, 16, false, seg.slice(16, 24), { src: C_IP, dst: D_IP }),
  ]);
  const res = reas(pcap);
  assert.equal(res.fragmentGroups.length, 1);
  assert.equal(res.fragmentGroups[0].status, "complete");
  assert.equal(res.connections.length, 2);
  const plain = res.connections.find((c) => c.endpointA === "10.1.0.1:1111");
  assert.equal(reassembledText(plain.dirs[0]), "plain");
  assert.equal(plain.dirs[0].complete, true);
  const fragged = res.connections.find((c) => c.endpointA === "10.9.0.1:2222");
  assert.equal(reassembledText(fragged.dirs[0]), "FRAG");
});
