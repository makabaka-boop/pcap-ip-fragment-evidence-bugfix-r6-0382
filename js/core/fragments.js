(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PcapFragments = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";
  function decode(packet, bytes, members) {
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
    packet.payloadCapturedLen = packet.payloadDeclaredLen =
      packet.payload.length;
    packet.fragmentIndexes = members.map((p) => p.index);
    packet.discardReason = null;
    return true;
  }
  function assemble(analysis) {
    var groups = new Map();
    for (var p of analysis.packets) {
      if (!p.fragment) continue;
      var key = String(p.ipId);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(p);
    }
    analysis.fragmentGroups = [];
    for (var [key, members] of groups) {
      var record = {
        key: key,
        indexes: members.map((p) => p.index),
        status: "incomplete",
        holes: [],
        conflicts: [],
      };
      analysis.fragmentGroups.push(record);
      var first = members.find((p) => p.fragment.offset === 0);
      var last = members.find((p) => !p.fragment.more);
      if (!first || !last) continue;
      var length = members.reduce((n, p) => n + p.fragment.bytes.length, 0);
      var bytes = new Uint8Array(length),
        cursor = 0;
      for (var part of members) {
        bytes.set(part.fragment.bytes, cursor);
        cursor += part.fragment.bytes.length;
      }
      record.status = decode(first, bytes, members)
        ? "complete"
        : "invalid_tcp";
    }
    return analysis;
  }
  return { assemble: assemble };
});
