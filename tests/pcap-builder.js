/*
 * 测试用 PCAP 构造器：独立于生产解析代码手工拼字节。
 */
"use strict";

function u8(n) {
  return n & 0xff;
}

/* 构造一个以太网/IPv4/TCP 记录的帧字节（不含 PCAP 记录头）。
 * opts.rawIpPayload：直接指定 IP 载荷原始字节（用于构造非首片分片，
 * 此时不拼 TCP 头，totalLen 按 IP 头 + rawIpPayload 计算）。 */
function buildFrame(opts) {
  var payload = opts.payload || Buffer.alloc(0);
  var rawIp = opts.rawIpPayload != null ? Buffer.from(opts.rawIpPayload) : null;
  var srcMac = opts.srcMac || Buffer.from("001122334455", "hex");
  var dstMac = opts.dstMac || Buffer.from("6677889900aa", "hex");
  var ethType = opts.ethType == null ? 0x0800 : opts.ethType;

  var tcpHdrLen = 20;
  var ipHdrLen = opts.ihl == null ? 20 : opts.ihl;
  var totalLen =
    ipHdrLen + (rawIp ? rawIp.length : tcpHdrLen + payload.length);
  if (opts.totalLen != null) totalLen = opts.totalLen;

  var ip = Buffer.alloc(ipHdrLen);
  ip[0] = ((opts.version == null ? 4 : opts.version) << 4) | (ipHdrLen / 4);
  ip[1] = opts.tos || 0;
  ip.writeUInt16BE(totalLen, 2);
  ip.writeUInt16BE(opts.ipId || 0, 4);
  var frag = opts.fragWord || 0;
  ip.writeUInt16BE(frag, 6);
  ip[8] = opts.ttl == null ? 64 : opts.ttl;
  ip[9] = opts.protocol == null ? 6 : opts.protocol;
  ip.writeUInt16BE(0, 10); // checksum 不校验
  var srcIp = opts.srcIp || Buffer.from([10, 0, 0, 1]);
  var dstIp = opts.dstIp || Buffer.from([10, 0, 0, 2]);
  srcIp.copy(ip, 12);
  dstIp.copy(ip, 16);

  var tcp = Buffer.alloc(tcpHdrLen);
  tcp.writeUInt16BE(opts.srcPort == null ? 12345 : opts.srcPort, 0);
  tcp.writeUInt16BE(opts.dstPort == null ? 80 : opts.dstPort, 2);
  tcp.writeUInt32BE(opts.seq >>> 0, 4);
  tcp.writeUInt32BE(opts.ack >>> 0, 8);
  tcp[12] = (tcpHdrLen / 4) << 4;
  tcp[13] = opts.flags || 0;
  tcp.writeUInt16BE(opts.window == null ? 64240 : opts.window, 14);

  var l2 = Buffer.concat([
    dstMac,
    srcMac,
    Buffer.from([(ethType >> 8) & 0xff, ethType & 0xff]),
  ]);
  var frame = rawIp
    ? Buffer.concat([l2, ip, rawIp])
    : Buffer.concat([l2, ip, tcp, payload]);
  return frame;
}

/*
 * 拼整个 PCAP 文件。
 * records: [{frame:Buffer, origLen?, tsSec?, tsFrac?, inclOverride?}]
 * 或直接传 buildFrame 的对象数组（自动 buildFrame）。
 */
function buildPcap(records, opts) {
  opts = opts || {};
  var magic = opts.magic == null ? 0xa1b2c3d4 : opts.magic;
  var linktype = opts.linktype == null ? 1 : opts.linktype;
  var gh = Buffer.alloc(24);
  gh.writeUInt32LE(magic, 0);
  gh.writeUInt16LE(opts.major == null ? 2 : opts.major, 4);
  gh.writeUInt16LE(opts.minor == null ? 4 : opts.minor, 6);
  gh.writeInt32LE(0, 8);
  gh.writeUInt32LE(0, 12);
  gh.writeUInt32LE(opts.snaplen == null ? 65535 : opts.snaplen, 16);
  gh.writeUInt32LE(linktype, 20);

  var parts = [gh];
  var ts = opts.tsSec == null ? 1700000000 : opts.tsSec;
  records.forEach(function (r, i) {
    var frame = r.frame || buildFrame(r);
    var incl = r.inclOverride != null ? r.inclOverride : frame.length;
    var orig = r.origLen == null ? frame.length : r.origLen;
    var rh = Buffer.alloc(16);
    rh.writeUInt32LE(r.tsSec == null ? ts + i : r.tsSec, 0);
    rh.writeUInt32LE(r.tsFrac == null ? i * 1000 : r.tsFrac, 4);
    rh.writeUInt32LE(incl, 8);
    rh.writeUInt32LE(orig, 12);
    parts.push(rh);
    // 帧内容必须从 frame 开头截取（不能带 parts 中记录头的偏移）
    parts.push(frame.slice(0, incl));
  });
  return Buffer.concat(parts);
}

function str(s) {
  return Buffer.from(s, "utf8");
}

/* 在文件尾部截断 n 字节（制造 record/frame 截断） */
function truncateTail(buf, n) {
  return buf.slice(0, buf.length - n);
}

/* 把某条记录的 incl_len 改大（声称的帧超过文件结尾） */
function tamperInclLen(buf, recordIndex, newLen) {
  var out = Buffer.from(buf);
  var off = 24;
  for (var i = 0; i < recordIndex; i++) off += 16 + out.readUInt32LE(off + 8);
  out.writeUInt32LE(newLen >>> 0, off + 8);
  return out;
}

module.exports = {
  buildFrame: buildFrame,
  buildPcap: buildPcap,
  str: str,
  truncateTail: truncateTail,
  tamperInclLen: tamperInclLen,
};
