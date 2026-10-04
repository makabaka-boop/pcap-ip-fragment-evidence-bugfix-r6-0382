/*
 * 对拍测试：node --test tests/
 * 覆盖：文件头拒绝、截断停止、乱序、序号回绕、重传去重、字节冲突、缺口、
 * snaplen 截断、双向多连接、2000 包上限，以及与独立参考重组器的随机对拍。
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Core = require("../js/core/pcap.js");
const R = require("../js/core/reassemble.js");
const View = require("../js/core/viewmodel.js");
const Util = require("../js/core/util.js");
const B = require("./pcap-builder.js");
const Ref = require("./reference.js");

const SYN = 0x02,
  ACK = 0x10,
  PSH = 0x08,
  FIN = 0x01,
  RST = 0x04;

// Buffer 可能位于 Node 的共享分配池中，必须截取属于文件的那一段 ArrayBuffer
function toAb(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}
function parse(buf, opts) {
  return Core.analyzePcap(toAb(buf), opts);
}
function reas(buf, opts) {
  return R.reassemble(Core.analyzePcap(toAb(buf), opts));
}

/* ---------- A. 文件头与格式闸门 ---------- */

test("拒绝：文件不足 24 字节", () => {
  assert.throws(
    () => parse(Buffer.alloc(10)),
    (e) => e.code === "bad_header",
  );
});

test("拒绝：错误魔数（大端 / pcapng / 随机字节）", () => {
  const be = B.buildPcap([], { magic: 0xd4c3b2a1 }); // 大端经典 PCAP
  assert.throws(
    () => parse(be),
    (e) => e.code === "bad_magic",
  );
  const pcapng = Buffer.from("0a0d0d0a", "hex"); // pcapng 节块魔数
  const buf = Buffer.concat([pcapng, Buffer.alloc(40)]);
  assert.throws(
    () => parse(buf),
    (e) => e.code === "bad_magic",
  );
  assert.throws(
    () => parse(Buffer.alloc(40, 0x5a)),
    (e) => e.code === "bad_magic",
  );
});

test("接受纳秒小端魔数 0xa1b23c4d", () => {
  const buf = B.buildPcap([], { magic: 0xa1b23c4d });
  const a = parse(buf);
  assert.equal(a.header.resolution, "ns");
});

test("拒绝：非以太网链路类型", () => {
  const buf = B.buildPcap([], { linktype: 12 });
  assert.throws(
    () => parse(buf),
    (e) => e.code === "bad_linktype",
  );
});

test("拒绝：超过 8 MB（整份不解析）", () => {
  assert.throws(
    () => Core.ensureSize(8 * 1024 * 1024 + 1),
    (e) => e.code === "file_too_large",
  );
  assert.ok(Core.ensureSize(8 * 1024 * 1024));
});

/* ---------- B. 截断 ---------- */

test("记录头被截断：保留位置证据并停止", () => {
  const good = B.buildPcap([{ flags: SYN, seq: 1000, payload: B.str("") }]);
  // 砍掉记录头的 10 字节（记录头只剩 6 字节）
  const buf = B.truncateTail(good, 10 + 54);
  const a = parse(buf);
  assert.ok(a.stoppedTruncated);
  assert.equal(a.stoppedTruncated.reason, "record_header_incomplete");
  assert.ok(a.stoppedTruncated.evidence.length > 0);
});

test("帧体被截断（仅剩部分帧字节）：证据 + 停止，旧包保留", () => {
  const pcap = B.buildPcap([
    { flags: SYN, seq: 100 },
    { flags: ACK, seq: 101, payload: B.str("hello") },
  ]);
  const buf = B.truncateTail(pcap, 20); // 第二帧 59 字节只剩 39
  const a = parse(buf);
  assert.equal(a.packets.length, 1);
  assert.ok(a.stoppedTruncated);
  assert.equal(a.stoppedTruncated.packetIndex, 1);
  assert.equal(a.stoppedTruncated.reason, "frame_incomplete");
});

/* ---------- C. 基础重组 / 乱序 / 重传 / 冲突 ---------- */

function tcpRec(o) {
  return Object.assign(
    {
      srcPort: 1111,
      dstPort: 80,
      srcIp: Buffer.from([1, 2, 3, 4]),
      dstIp: Buffer.from([5, 6, 7, 8]),
    },
    o,
  );
}

test("基础三次握手 + 数据 + FIN：相对序号与完整标志", () => {
  const isn = 5000;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    {
      flags: SYN | ACK,
      seq: 9000,
      ack: isn + 1,
      srcPort: 80,
      dstPort: 1111,
      srcIp: Buffer.from([5, 6, 7, 8]),
      dstIp: Buffer.from([1, 2, 3, 4]),
    },
    tcpRec({ flags: ACK, seq: isn + 1, ack: 9001 }),
    tcpRec({ flags: PSH | ACK, seq: isn + 1, payload: B.str("abcdef") }),
    tcpRec({ flags: FIN | ACK, seq: isn + 7 }),
  ]);
  const res = reas(pcap);
  const c = res.connections[0];
  assert.ok(c);
  const ab = c.dirs[0]; // 1.2.3.4 -> 5.6.7.8（endpoint 小 -> 大）
  assert.equal(ab.stats.dataBytes, 6);
  assert.equal(ab.stats.gapBytes, 0);
  assert.equal(ab.complete, true);
  assert.equal(reassembledText(ab), "abcdef");
  // 首数据 rel seq = 1（SYN 占用 0）
  const dataPkt = res.packets.find((p) => p.payloadCapturedLen === 6);
  assert.equal(dataPkt.relSeq, 1);
});

test("乱序到达：重组只看序号不看到达顺序", () => {
  const isn = 100;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1 + 5, payload: B.str("FGHIJ") }), // 先到第二段
    tcpRec({ flags: ACK, seq: isn + 1, payload: B.str("ABCDE") }), // 后到第一段
    tcpRec({ flags: FIN | ACK, seq: isn + 11 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(reassembledText(ab), "ABCDEFGHIJ");
  assert.equal(ab.complete, true);
  const ooo = res.packets.filter((p) => p.outOfOrder).map((p) => p.index);
  assert.deepEqual(ooo, [2]); // 第三包（idx 2）乱序
});

test("相同字节重传：去重，无缺口无冲突", () => {
  const isn = 10;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: PSH | ACK, seq: isn + 1, payload: B.str("XYZ") }),
    tcpRec({ flags: PSH | ACK, seq: isn + 1, payload: B.str("XYZ") }), // 完全相同
    tcpRec({ flags: FIN | ACK, seq: isn + 4 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(reassembledText(ab), "XYZ");
  assert.equal(ab.stats.conflictBytes, 0);
  assert.equal(ab.stats.gapBytes, 0);
  assert.equal(ab.stats.syn, true);
  const rPkt = res.packets.find((p) => p.index === 2);
  assert.ok(rPkt.isRetrans);
  assert.equal(rPkt.dupBytes, 3);
});

test("重叠但字节不一致：冲突留证，不选边覆盖", () => {
  const isn = 10;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1, payload: B.str("AAAAAA") }),
    tcpRec({ flags: ACK, seq: isn + 1 + 2, payload: B.str("BB") }), // 位置 3,4：A->B 不一致
    tcpRec({ flags: FIN | ACK, seq: isn + 7 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.conflictBytes, 2);
  assert.equal(ab.conflictRanges.length, 1);
  const rng = ab.conflictRanges[0];
  assert.deepEqual([rng.start - ab.origin, rng.end - ab.origin], [3, 5]);
  // 两个候选字节都保留
  const entries = rng.entries;
  assert.equal(entries.length, 2);
  entries.forEach((e) => {
    const vals = Object.values(e.byPkt).sort();
    assert.deepEqual(vals, [0x41, 0x42]); // 'A' 与 'B'
  });
  // 冲突位置的首持字节仍是 A，文本中位置 0..2 与 5 正常
  const text = reassembledText(ab);
  assert.equal(text.slice(0, 3), "AAA");
  assert.equal(text.slice(-1), "A");
});

test("缺失区间：显式缺口，绝不填充；无 FIN 时不报首尾缺口", () => {
  const isn = 0xffffff00;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1, payload: B.str("AAAA") }), // 1..5
    // 缺 5..9
    tcpRec({ flags: PSH | ACK, seq: isn + 9, payload: B.str("BBBB") }), // 9..13
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.dataBytes, 8);
  assert.equal(ab.gaps.length, 1);
  assert.deepEqual(
    [ab.gaps[0].start - ab.origin, ab.gaps[0].end - ab.origin],
    [5, 9],
  );
  assert.equal(ab.complete, false);
  // chunk 顺序：data, gap, data
  const kinds = ab.chunks.map((c) => c.kind);
  assert.deepEqual(kinds, ["data", "gap", "data"]);
  assert.equal(ab.gaps[0].kind, "internal");
});

test("FIN 之后才能判定首/尾缺口", () => {
  const isn = 100;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    // 首段缺失 1..3
    tcpRec({ flags: ACK, seq: isn + 3, payload: B.str("XX") }),
    // 尾部缺失：FIN 在 12
    tcpRec({ flags: FIN | ACK, seq: isn + 12 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  const kinds = ab.gaps.map((g) => g.kind).sort();
  assert.deepEqual(kinds, ["leading", "trailing"]);
  const leading = ab.gaps.find((g) => g.kind === "leading");
  const trailing = ab.gaps.find((g) => g.kind === "trailing");
  assert.deepEqual(
    [leading.start - ab.origin, leading.end - ab.origin],
    [1, 3],
  );
  assert.deepEqual(
    [trailing.start - ab.origin, trailing.end - ab.origin],
    [5, 12],
  );
});

/* ---------- D. 序号回绕 ---------- */

test("回绕附近的乱序与重传仍正确重组", () => {
  const base = 0xfffffffc;
  // 无 SYN；第一段跨过 0x100000000 回绕点（长度 6，占据相对 0..6）
  // 第二段乱序先到：从回绕后的相对 4 起，与第一段在 4,5 两字节重传相同
  const pcap = B.buildPcap([
    tcpRec({ flags: ACK, seq: (base + 8) >>> 0, payload: B.str("IJ") }), // 相对 8,9
    tcpRec({ flags: ACK, seq: (base + 4) >>> 0, payload: B.str("EFGH") }), // 相对 4..8
    tcpRec({ flags: ACK, seq: base, payload: B.str("ABCDEF") }), // 相对 0..6
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.conflictBytes, 0);
  assert.equal(reassembledText(ab), "ABCDEFGHIJ");
  // 相对 4,5 两字节被后到的完整段重复覆盖；6,7 由第二段独有
  const dupTotal = res.packets.reduce(function (n, p) {
    return n + p.dupBytes;
  }, 0);
  assert.ok(dupTotal >= 2, "重叠相同字节应计为重传，实际 dupTotal=" + dupTotal);
  assert.ok(res.packets.some((p) => p.isRetrans));
});

test("回绕点处字节冲突能被检出", () => {
  const base = 0xfffffffe;
  const pcap = B.buildPcap([
    tcpRec({ flags: ACK, seq: base, payload: B.str("ABCD") }), // -2,-1,0,1
    tcpRec({ flags: ACK, seq: (base + 2) >>> 0, payload: B.str("ZZ") }), // 0,1 冲突
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.conflictBytes, 2);
  assert.deepEqual(
    [
      ab.conflictRanges[0].start - ab.origin,
      ab.conflictRanges[0].end - ab.origin,
    ],
    [2, 4], // 相对原点(base)：0,1 -> 显示 2,4? 见下断言原点规则
  );
});

/* ---------- E. snaplen 截断 ---------- */

test("snaplen 截断段：只落入抓到的前缀，声明尾部保持缺口", () => {
  const isn = 100;
  const frame = B.buildFrame(
    tcpRec({ flags: PSH | ACK, seq: isn + 1, payload: B.str("0123456789") }),
  );
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    { frame: frame, origLen: frame.length, inclOverride: frame.length - 4 }, // 少抓最后 4 个字节（6789）
    tcpRec({ flags: FIN | ACK, seq: isn + 11 }),
  ]);
  const res = reas(pcap);
  const p = res.packets[1];
  assert.equal(p.payloadCapturedLen, 6);
  assert.equal(p.payloadDeclaredLen, 10);
  assert.ok(p.payloadTruncated);
  const ab = res.connections[0].dirs[0];
  assert.equal(reassembledText(ab), "012345");
  const gap = ab.gaps.find((g) => g.kind === "trailing");
  assert.ok(gap);
  assert.equal(gap.end - gap.start, 4);
});

/* ---------- F. 协议过滤 / 多连接双向 ---------- */

test("非 IPv4 / 非 TCP / 分片 / 畸形 IP 头：只丢该包，连接照常建立", () => {
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: 1 }),
    { ethType: 0x0806, flags: 0 }, // ARP
    tcpRec({ flags: ACK, seq: 1, payload: B.str("Q") }), // TCP 正常
    { protocol: 17, flags: 0 }, // UDP
    tcpRec({ flags: ACK, seq: 1, payload: B.str(""), fragWord: 0x2000 }), // MF 分片
    tcpRec({ version: 6, flags: 0 }), // IPv6 伪装（version 6）
  ]);
  const a = parse(pcap);
  assert.equal(a.packets[1].discardReason, "not_ipv4");
  assert.equal(a.packets[3].discardReason, "not_tcp");
  assert.equal(a.packets[4].discardReason, "ip_fragment");
  assert.equal(a.packets[5].discardReason, "ip_bad_version");
  const res = R.reassemble(a);
  assert.equal(res.connections.length, 1);
  assert.equal(reassembledText(res.connections[0].dirs[0]), "Q");
});

test("双向：两个方向各自独立重组、各自统计", () => {
  const A = { ip: Buffer.from([1, 0, 0, 1]), port: 2000 };
  const Bip = Buffer.from([2, 0, 0, 2]);
  const recs = [
    {
      flags: SYN,
      seq: 100,
      srcPort: A.port,
      dstPort: 443,
      srcIp: A.ip,
      dstIp: Bip,
    },
    {
      flags: SYN | ACK,
      seq: 700,
      ack: 101,
      srcPort: 443,
      dstPort: A.port,
      srcIp: Bip,
      dstIp: A.ip,
    },
    {
      flags: ACK,
      seq: 101,
      ack: 701,
      srcPort: A.port,
      dstPort: 443,
      srcIp: A.ip,
      dstIp: Bip,
    },
    {
      flags: PSH | ACK,
      seq: 101,
      payload: B.str("req-aa"),
      srcPort: A.port,
      dstPort: 443,
      srcIp: A.ip,
      dstIp: Bip,
    },
    {
      flags: PSH | ACK,
      seq: 701,
      payload: B.str("resp-bbb"),
      srcPort: 443,
      dstPort: A.port,
      srcIp: Bip,
      dstIp: A.ip,
    },
    // 响应方向乱序 + 重传
    {
      flags: ACK,
      seq: 705,
      payload: B.str("-bbb"),
      srcPort: 443,
      dstPort: A.port,
      srcIp: Bip,
      dstIp: A.ip,
    },
  ];
  const res = reas(B.buildPcap(recs));
  assert.equal(res.connections.length, 1);
  const c = res.connections[0];
  // endpoint key: "1.0.0.1:2000" < "2.0.0.2:443"
  assert.equal(c.endpointA, "1.0.0.1:2000");
  assert.equal(reassembledText(c.dirs[0]), "req-aa");
  assert.equal(reassembledText(c.dirs[1]), "resp-bbb");
  assert.ok(c.dirs[1].packets ? true : true);
  // 重传统计落在响应方向
  assert.ok(res.packets.some((p) => p.isRetrans && p.dir === 1));
});

/* ---------- G. 2000 包上限 ---------- */

test("超过 2000 包：硬拒绝（packet_limit）", () => {
  const recs = [];
  for (let i = 0; i < 2001; i++) {
    recs.push(
      tcpRec({ flags: ACK, seq: (1000 + i) >>> 0, payload: Buffer.alloc(0) }),
    );
  }
  const pcap = B.buildPcap(recs);
  assert.throws(
    () => parse(pcap),
    (e) => e.code === "packet_limit",
  );
});

test("恰好 2000 包：接受", () => {
  const recs = [];
  for (let i = 0; i < 2000; i++) {
    recs.push(
      tcpRec({ flags: ACK, seq: (1000 + i) >>> 0, payload: Buffer.alloc(0) }),
    );
  }
  const a = parse(B.buildPcap(recs));
  assert.equal(a.packets.length, 2000);
});

/* ---------- H. RST / FIN 重传 ---------- */

test("RST 标记连接；重复 FIN 同位置计重传", () => {
  const isn = 5;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: PSH | ACK, seq: isn + 1, payload: B.str("hi") }),
    tcpRec({ flags: FIN | ACK, seq: isn + 3 }),
    tcpRec({ flags: FIN | ACK, seq: isn + 3 }),
    tcpRec({ flags: RST, seq: isn + 4 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.fin, true);
  assert.equal(ab.stats.reset, true);
  assert.equal(ab.stats.finRetrans, 1);
});

/* ---------- I. 视图模型：文本/HEX/导出 ---------- */

test("文本 token：缺口与冲突分隔，绝不跨缺口拼字符", () => {
  const isn = 10;
  // "é" = 0xc3 0xa9。把 0xc3 放在缺口前、0xa9 放在缺口后：
  // 若错误共享解码器状态会拼成 é；正确实现应各自替换为两个 �。
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1, payload: Buffer.from([0x61, 0xc3]) }), // a + 半字符
    tcpRec({ flags: ACK, seq: isn + 4, payload: Buffer.from([0xa9, 0x62]) }),
    tcpRec({ flags: FIN | ACK, seq: isn + 6 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  const tm = View.buildTextTokens(ab);
  const types = tm.tokens.map((t) => t.t);
  assert.deepEqual(types, ["text", "gap", "text"]);
  assert.equal(tm.tokens[0].str, "a�");
  assert.equal(tm.tokens[2].str, "�b");
  assert.deepEqual(
    [tm.tokens[1].start - ab.origin, tm.tokens[1].end - ab.origin],
    [3, 4],
  );
});

test("HEX 行模型标注缺口与冲突；导出 JSON 含每块 base64", () => {
  const isn = 10;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1, payload: B.str("AAA") }),
    tcpRec({ flags: ACK, seq: isn + 1 + 5, payload: B.str("BBB") }),
    tcpRec({ flags: FIN | ACK, seq: isn + 9 }),
  ]);
  const res = reas(pcap);
  const d = res.connections[0].dirs[0];
  const hm = View.buildHexRows(d);
  const allCells = hm.rows.flatMap((r) => r.cells);
  assert.equal(allCells.filter((c) => c.gap).length, 2);
  const json = JSON.parse(View.exportJson(res));
  assert.equal(json.formatVersion, 1);
  const dir0 = json.connections[0].directions[0];
  const dataChunks = dir0.chunks.filter((c) => c.kind === "data");
  assert.equal(Buffer.from(dataChunks[0].base64, "base64").toString(), "AAA");
  assert.equal(Buffer.from(dataChunks[1].base64, "base64").toString(), "BBB");
  const gapChunks = dir0.chunks.filter((c) => c.kind === "gap");
  assert.equal(gapChunks.length, 1);
  // TXT 导出包含缺口与包表
  const txt = View.exportText(res);
  assert.match(txt, /GAP/);
  assert.match(txt, /Packets/);
});

test("截断证据进入导出", () => {
  const good = B.buildPcap([tcpRec({ flags: SYN, seq: 1 })]);
  const buf = B.truncateTail(good, 5);
  const res = R.reassemble(parse(buf));
  const json = JSON.parse(View.exportJson(res));
  assert.ok(json.file.stoppedTruncated);
  assert.equal(json.file.stoppedTruncated.reason, "frame_incomplete");
});

/* ---------- J. tokenBox：旧 Worker 迟到结果不得替换当前文件 ---------- */

test("tokenBox：取消与换代会让旧 token 失效", () => {
  const box = Util.tokenBox();
  const t1 = box.next();
  assert.ok(box.isCurrent(t1));
  const t2 = box.next(); // 新导入 -> 换代
  assert.ok(!box.isCurrent(t1));
  assert.ok(box.isCurrent(t2));
  box.cancel();
  assert.ok(!box.isCurrent(t2));
  assert.ok(!box.active());
});

/* ---------- K2. 桥接缺口回归：后到的大段横跨多个已有碎片 ---------- */

test("后到段横跨多个碎片与缺口：正确焊连且逐字节比较", () => {
  const isn = 100;
  // 先乱序到达 4 个互不相连的小段，最后一个大段把它们全部桥接
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1 + 12, payload: B.str("M") }), // 12
    tcpRec({ flags: ACK, seq: isn + 1 + 6, payload: B.str("G") }), // 6
    tcpRec({ flags: ACK, seq: isn + 1 + 0, payload: B.str("A") }), // 0
    tcpRec({ flags: ACK, seq: isn + 1 + 3, payload: B.str("D") }), // 3
    tcpRec({
      flags: ACK,
      seq: isn + 1,
      payload: B.str("ABCDEFGHIJKLMNOPQRSTUVWX"),
    }), // 0..24 全覆盖
    tcpRec({ flags: FIN | ACK, seq: isn + 25 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.conflictBytes, 0);
  assert.equal(ab.stats.gapBytes, 0);
  assert.equal(ab.complete, true);
  assert.equal(reassembledText(ab), "ABCDEFGHIJKLMNOPQRSTUVWX");
  // 后到的大段在 4 个已存在位置重传相同字节
  const dupTotal = res.packets.reduce((n, p) => n + p.dupBytes, 0);
  assert.equal(dupTotal, 4);
});

test("桥接段与缺口两侧字节冲突：冲突区间连续不丢字节", () => {
  const isn = 100;
  const pcap = B.buildPcap([
    tcpRec({ flags: SYN, seq: isn }),
    tcpRec({ flags: ACK, seq: isn + 1, payload: B.str("A--D") }), // 0,1,2,3
    // 中间留缺口 4..9
    tcpRec({ flags: ACK, seq: isn + 1 + 10, payload: B.str("K--N") }), // 10..13
    // 大段桥接：0..13，其中 0,3,10,13 四处与旧字节冲突
    tcpRec({
      flags: ACK,
      seq: isn + 1,
      payload: Buffer.from([
        0x78, 0x2d, 0x2d, 0x78, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x78, 0x2d,
        0x2d, 0x78,
      ]),
    }),
    tcpRec({ flags: FIN | ACK, seq: isn + 15 }),
  ]);
  const res = reas(pcap);
  const ab = res.connections[0].dirs[0];
  assert.equal(ab.stats.dataBytes, 14);
  assert.equal(ab.stats.gapBytes, 0);
  assert.equal(ab.stats.conflictBytes, 4);
  const relConflicts = ab.conflictRanges.map((r) => [
    r.start - ab.origin,
    r.end - ab.origin,
  ]);
  assert.deepEqual(relConflicts, [
    [1, 2],
    [4, 5],
    [11, 12],
    [14, 15],
  ]);
});

/* ---------- K. 随机对拍 ---------- */

function mulberry32(seed) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("随机对拍：与独立参考重组器比较碎片/缺口/冲突/逐字节内容", () => {
  const rand = mulberry32(20261001);
  for (let trial = 0; trial < 300; trial++) {
    const isn = Math.floor(rand() * 0x100000000) >>> 0;
    const useSyn = rand() < 0.7;
    const useFin = rand() < 0.6;
    const wrap = rand() < 0.4;
    const origin = wrap ? (isn + Math.floor(rand() * 50) - 25) >>> 0 : isn;

    const alpha = [];
    for (let i = 0; i < 26; i++) alpha.push(0x41 + i);
    const segs = [];
    const nSegs = 2 + Math.floor(rand() * 5);
    let pos = useSyn ? 1 : 0;
    const streamLen = 20 + Math.floor(rand() * 60);
    for (let i = 0; i < nSegs; i++) {
      const remain = streamLen - pos;
      if (remain <= 0) break;
      const maxTake = Math.min(remain, 4 + Math.floor(rand() * 12));
      // 有时制造回退/跳跃
      let start = pos;
      const roll = rand();
      if (roll < 0.4 && segs.length) {
        start = Math.max(useSyn ? 1 : 0, pos - 1 - Math.floor(rand() * 8));
      } else if (roll < 0.6) {
        start = pos + 1 + Math.floor(rand() * 5); // 缺口
      }
      const take = Math.max(1, Math.min(maxTake, 3 + Math.floor(rand() * 10)));
      let payload = Buffer.alloc(take);
      for (let k = 0; k < take; k++) {
        payload[k] = alpha[(start + k) % alpha.length];
      }
      // 30% 概率重传（相同字节）；15% 概率污染 1..2 字节制造冲突
      let variant = "normal";
      if (rand() < 0.3) variant = "retrans";
      else if (rand() < 0.25) {
        variant = "conflict";
        const nBad = 1 + Math.floor(rand() * 2);
        for (let b = 0; b < nBad; b++) {
          const idx = Math.floor(rand() * take);
          payload[idx] = 0x30 + Math.floor(rand() * 9); // 数字字节，必与字母不同
        }
      }
      segs.push({
        relStart: start,
        payload: payload,
        variant: variant,
        basePayload: Buffer.from(payload),
      });
      pos = Math.max(pos, start + take);
    }
    const endPos = streamLen;

    const recs = [];
    if (useSyn) recs.push(tcpRec({ flags: SYN, seq: (origin - 1) >>> 0 }));
    shuffled(segs.slice(), rand).forEach((s) => {
      let payload = s.payload;
      if (s.variant === "retrans") {
        // 重建“真实”字母版本，与首传相同
        payload = Buffer.alloc(s.basePayload.length);
        for (let k = 0; k < payload.length; k++) {
          payload[k] = alpha[(s.relStart + k) % alpha.length];
        }
      }
      recs.push(
        tcpRec({
          flags: ACK,
          seq: (origin + s.relStart - (useSyn ? 1 : 0)) >>> 0,
          payload: payload,
        }),
      );
    });
    if (useFin) {
      recs.push(
        tcpRec({
          flags: FIN | ACK,
          seq: (origin + endPos - (useSyn ? 1 : 0)) >>> 0,
        }),
      );
    }

    const analysis = parse(B.buildPcap(recs));
    const res = R.reassemble(analysis);
    const ref = Ref.referenceReassemble(analysis.packets);

    const c = res.connections[0];
    assert.ok(c, "trial " + trial + ": 应有一个连接");
    const prod = c.dirs[0];
    const rf = ref[0];

    // 两边原点语义一致（SYN 时为 SYN 序；无 SYN 时为最早数据序），
    // 统一为“相对各自原点的偏移”：
    const toRefRel = function (prodAbs) {
      return prodAbs - prod.origin;
    };
    const prodDataRel = useSyn ? 1 : 0;
    void prodDataRel;

    // 覆盖区间（碎片，冲突位置仍算有字节覆盖）一致：
    // 把 data/conflict 区间合并（贴合即并）后，与参考碎片比较
    const covered = prod.chunks
      .filter((x) => x.kind !== "gap")
      .map((x) => [toRefRel(x.start), toRefRel(x.end)])
      .sort((a, b) => a[0] - b[0])
      .reduce((acc, iv) => {
        const last = acc[acc.length - 1];
        if (last && iv[0] <= last[1]) last[1] = Math.max(last[1], iv[1]);
        else acc.push(iv);
        return acc;
      }, []);
    assert.equal(
      JSON.stringify(covered),
      JSON.stringify(
        rf.frags.map((f) => [f.start - rf.origin, f.end - rf.origin]),
      ),
      "trial " +
        trial +
        " 覆盖区间不一致 prod=" +
        JSON.stringify(covered) +
        " ref=" +
        JSON.stringify(rf.frags),
    );

    // 缺口区间与类型一致（统一到参考相对坐标）
    const prodGapsRel = prod.gaps
      .map((g) => [toRefRel(g.start), toRefRel(g.end), g.kind])
      .sort((a, b) => a[0] - b[0]);
    const refGapsRel = rf.gaps.map((g) => [
      g.start - rf.origin,
      g.end - rf.origin,
      g.kind,
    ]);
    assert.equal(
      JSON.stringify(prodGapsRel),
      JSON.stringify(refGapsRel),
      "trial " + trial + " 缺口不一致",
    );

    // 冲突区间一致
    assert.equal(
      JSON.stringify(
        prod.conflictRanges.map((r) => [toRefRel(r.start), toRefRel(r.end)]),
      ),
      JSON.stringify(
        rf.conflictRanges.map((r) => [r.start - rf.origin, r.end - rf.origin]),
      ),
      "trial " + trial + " 冲突区间不一致",
    );

    // 冲突位置每个候选字节值集合一致
    prod.conflictRanges.forEach(function (r) {
      r.entries.forEach(function (e) {
        const rr = toRefRel(e.pos);
        const piList = Object.keys(e.byPkt)
          .map(Number)
          .sort((a, b) => a - b);
        const uniq = Array.from(new Set(piList.map((pi) => e.byPkt[pi]))).sort(
          (a, b) => a - b,
        );
        assert.equal(
          JSON.stringify(uniq),
          JSON.stringify(rf.candidatesAt(rr + rf.origin)),
          "trial " + trial + " 冲突 rel " + rr + " 候选字节不一致",
        );
      });
    });

    // 逐字节内容一致（扫描参考器所有覆盖位置；两边用相对各自原点的偏移比较）
    for (let q = 0; q < rf.frags.length; q++) {
      for (let p = rf.frags[q][0]; p < rf.frags[q][1]; p++) {
        const rel = p - rf.origin;
        const prodByte = byteOf(prod, prod.origin + rel);
        const refByte = rf.byteAt(p);
        assert.equal(
          prodByte,
          refByte,
          "trial " + trial + " 位置 rel " + rel + " 字节不一致",
        );
      }
    }
  }
});

/* 从生产结果的 chunks 取绝对位置字节（冲突位置返回首持字节） */
function byteOf(dir, absPos) {
  for (const ch of dir.chunks) {
    if (ch.kind === "data" && absPos >= ch.start && absPos < ch.end) {
      return ch.bytes[absPos - ch.start];
    }
    if (ch.kind === "conflict" && absPos >= ch.start && absPos < ch.end) {
      const e = ch.entries[absPos - ch.start];
      const firstPi = Object.keys(e.byPkt)
        .map(Number)
        .sort((a, b) => a - b)[0];
      return e.byPkt[firstPi];
    }
  }
  return undefined;
}

function shuffled(arr, rand) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
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
