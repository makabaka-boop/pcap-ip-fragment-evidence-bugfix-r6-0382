/*
 * 生成演示 PCAP：sample-disorder.pcap
 * 包含：握手、乱序数据、相同重传、字节冲突、中间缺口、FIN 后判定首尾缺口、
 * snaplen 截断段，以及第二个连接。
 * 运行：node tests/make-sample.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const B = require("./pcap-builder.js");

const A = {
  srcIp: Buffer.from([192, 168, 1, 10]),
  srcPort: 51514,
  dstIp: Buffer.from([93, 184, 216, 34]),
  dstPort: 443,
};

const isn = 0x01020304;
const recs = [
  Object.assign({}, A, { flags: 0x02, seq: isn }), // SYN
  Object.assign({}, A, {
    flags: 0x12,
    seq: 0x99887766,
    ack: isn + 1,
    srcIp: A.dstIp,
    srcPort: 443,
    dstIp: A.srcIp,
    dstPort: 51514,
  }), // SYN,ACK 反向
  Object.assign({}, A, { flags: 0x10, seq: isn + 1, ack: 0x99887767 }), // ACK
  // 请求方向：先到第二段（乱序）
  Object.assign({}, A, {
    flags: 0x18,
    seq: isn + 1 + 11,
    payload: B.str("REQUEST-WORLD!"),
  }), // rel 11..
  Object.assign({}, A, { flags: 0x18, seq: isn + 1, payload: B.str("HELLO-") }), // rel 1..7
  // 完全相同的重传
  Object.assign({}, A, { flags: 0x18, seq: isn + 1, payload: B.str("HELLO-") }),
  // 重叠但字节不一致（rel 13,14 -> 与 'WO' 冲突）
  Object.assign({}, A, {
    flags: 0x18,
    seq: isn + 1 + 12,
    payload: B.str("xx"),
  }),
  // 中间缺口：rel 25..34 缺失，之后还有数据
  Object.assign({}, A, {
    flags: 0x18,
    seq: isn + 1 + 34,
    payload: B.str("TAIL"),
  }),
  Object.assign({}, A, { flags: 0x11, seq: isn + 1 + 38 }), // FIN
];

const pcap = B.buildPcap(recs, { snaplen: 65535 });

// 再加一个被 snaplen 截断的独立连接：直接构造一条 incl < orig 的记录
const truncatedFrame = B.buildFrame({
  srcPort: 40000,
  dstPort: 22,
  srcIp: Buffer.from([10, 10, 0, 5]),
  dstIp: Buffer.from([10, 10, 0, 9]),
  flags: 0x18,
  seq: 700,
  payload: B.str("SSH-2.0-OpenSSH_long_payload_cut_here"),
});
const pcap2 = B.buildPcap([
  {
    frame: truncatedFrame,
    origLen: truncatedFrame.length,
    inclOverride: truncatedFrame.length - 12,
  },
]);

// 手工拼接两个 pcap：保留第二个的全局头替换为记录
const records2 = pcap2.slice(24);
const out = Buffer.concat([pcap, records2]);
const target = path.join(__dirname, "..", "sample-disorder.pcap");
fs.writeFileSync(target, out);
console.log("wrote", target, out.length, "bytes");
