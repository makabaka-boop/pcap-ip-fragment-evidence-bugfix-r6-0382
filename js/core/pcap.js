/*
 * 限定版 PCAP 解析：
 *  - 仅小端经典 PCAP（magic 0xA1B2C3D4 微秒 / 0xA1B23C4D 纳秒）
 *  - 仅 LINKTYPE_ETHERNET(1)
 *  - 仅以太网 EtherType 0x0800 -> IPv4 -> TCP
 * 文件头错误：整份拒绝（PcapFatalError）。
 * 记录头/帧字节在文件层面被截断：保留位置证据，停止整个文件的后续解析
 * （截断点之后无法可靠定位下一条记录，继续读等于猜测）。
 * 其余 IP/TCP 层面的畸形只丢弃该包，记录 discardReason，不影响后续包。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    var U = require("./util");
    module.exports = factory(U);
  } else root.PcapCore = factory(root.PcapUtil);
})(typeof self !== "undefined" ? self : this, function (Util) {
  "use strict";

  var MAX_FILE_SIZE = 8 * 1024 * 1024;
  var MAX_PACKETS = 2000;

  var MAGIC_US = 0xa1b2c3d4; // 秒 + 微秒
  var MAGIC_NS = 0xa1b23c4d; // 秒 + 纳秒

  var LINKTYPE_ETHERNET = 1;
  var ETHERTYPE_IPV4 = 0x0800;
  var IPPROTO_TCP = 6;
  var TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20;

  function PcapFatalError(code, message) {
    var err = new Error(message);
    err.name = "PcapFatalError";
    err.code = code;
    return err;
  }

  function ensureSize(size) {
    if (size > MAX_FILE_SIZE) {
      throw PcapFatalError(
        "file_too_large",
        "文件 " +
          size +
          " 字节，超过限定版 8 MB 上限（" +
          MAX_FILE_SIZE +
          " 字节）",
      );
    }
    return true;
  }

  function parseGlobalHeader(view, bytes) {
    if (bytes.length < 24) {
      throw PcapFatalError(
        "bad_header",
        "文件不足 24 字节，没有完整的 PCAP 全局头",
      );
    }
    var magic = view.getUint32(0, true);
    var resolution;
    if (magic === MAGIC_US) resolution = "us";
    else if (magic === MAGIC_NS) resolution = "ns";
    else {
      throw PcapFatalError(
        "bad_magic",
        "魔数错误：仅支持小端经典 PCAP（0xa1b2c3d4 / 0xa1b23c4d）。" +
          "大端、pcapng 及其他格式一律拒绝。",
      );
    }
    var versionMajor = view.getUint16(4, true);
    var versionMinor = view.getUint16(6, true);
    var snaplen = view.getUint32(16, true);
    var linktype = view.getUint32(20, true);
    if (linktype !== LINKTYPE_ETHERNET) {
      throw PcapFatalError(
        "bad_linktype",
        "不支持链路类型 " +
          linktype +
          "：限定版仅解析以太网（LINKTYPE_ETHERNET=1）",
      );
    }
    return {
      magic: magic === MAGIC_NS ? "0xa1b23c4d" : "0xa1b2c3d4",
      versionMajor: versionMajor,
      versionMinor: versionMinor,
      thisZone: view.getInt32(8, true),
      sigfigs: view.getUint32(12, true),
      snaplen: snaplen,
      linktype: linktype,
      resolution: resolution,
    };
  }

  function joinIp(b, o) {
    return b[o] + "." + b[o + 1] + "." + b[o + 2] + "." + b[o + 3];
  }

  /*
   * 解析一帧（以太网/IPv4/TCP）。
   * buf 整个 ArrayBuffer；[start, end) 为本记录实际抓到的字节。
   * 仅向 pkt 上写字段；文件层截断由调用方负责，这里只处理包内畸形。
   */
  function dissectFrame(buf, view, start, end, pkt) {
    var capLen = end - start;
    if (capLen < 14) {
      pkt.discardReason = "eth_too_short";
      return;
    }
    pkt.dstMac = Util.bytesToHex(new Uint8Array(buf, start, 6));
    pkt.srcMac = Util.bytesToHex(new Uint8Array(buf, start + 6, 6));
    var ethType = view.getUint16(start + 12, false); // EtherType 为大端
    pkt.ethType = ethType;
    if (ethType !== ETHERTYPE_IPV4) {
      pkt.discardReason = "not_ipv4"; // ARP / VLAN / IPv6 等一律不解析
      return;
    }

    var ip0 = start + 14;
    if (end - ip0 < 20) {
      pkt.discardReason = "ip_too_short";
      return;
    }
    var vihl = view.getUint8(ip0);
    var version = vihl >> 4;
    var ihl = (vihl & 0x0f) * 4;
    if (version !== 4) {
      pkt.discardReason = "ip_bad_version";
      return;
    }
    if (ihl < 20 || end - ip0 < ihl) {
      pkt.discardReason = "ip_bad_header";
      return;
    }
    var totalLen = view.getUint16(ip0 + 2, false);
    var fragWord = view.getUint16(ip0 + 6, false);
    var moreFrags = (fragWord & 0x2000) !== 0;
    var fragOffset = fragWord & 0x1fff;
    var protocol = view.getUint8(ip0 + 9);
    pkt.ipId = view.getUint16(ip0 + 4, false);
    pkt.ttl = view.getUint8(ip0 + 8);
    pkt.srcIp = joinIp(new Uint8Array(buf), ip0 + 12);
    pkt.dstIp = joinIp(new Uint8Array(buf), ip0 + 16);
    pkt.ihl = ihl;
    pkt.ipTotalLen = totalLen;

    if (moreFrags || fragOffset !== 0) {
      if (protocol !== IPPROTO_TCP || totalLen < ihl) {
        pkt.discardReason = "invalid_fragment";
        return;
      }
      var declared = totalLen - ihl;
      var available = Math.max(0, Math.min(declared, end - ip0 - ihl));
      pkt.fragment = {
        offset: fragOffset * 8,
        more: moreFrags,
        protocol: protocol,
        declared: declared,
        bytes: new Uint8Array(buf, ip0 + ihl, available).slice(),
      };
      pkt.discardReason = "ip_fragment";
      return;
    }
    if (protocol !== IPPROTO_TCP) {
      pkt.discardReason = "not_tcp";
      return;
    }
    if (totalLen < ihl) {
      pkt.discardReason = "ip_bad_totallen";
      return;
    }

    // IP 报文在本记录中实际可及的结尾（抓包截断时短于 totalLen）
    var ipDeclaredEnd = ip0 + totalLen;
    var ipAvailableEnd = Math.min(end, ipDeclaredEnd);
    if (ipDeclaredEnd > end) pkt.ipTruncated = true;

    var tcp0 = ip0 + ihl;
    if (ipAvailableEnd - tcp0 < 20) {
      pkt.discardReason = "tcp_header_truncated";
      return;
    }
    pkt.srcPort = view.getUint16(tcp0, false);
    pkt.dstPort = view.getUint16(tcp0 + 2, false);
    pkt.seq = view.getUint32(tcp0 + 4, false); // TCP 序号/确认号为大端
    pkt.ack = view.getUint32(tcp0 + 8, false);
    var dataOffset = (view.getUint8(tcp0 + 12) >> 4) * 4;
    pkt.flags = view.getUint8(tcp0 + 13);
    pkt.window = view.getUint16(tcp0 + 14, false);
    pkt.tcpHeaderLen = dataOffset;
    if (dataOffset < 20 || tcp0 + dataOffset > ipAvailableEnd) {
      pkt.discardReason = "tcp_bad_header";
      return;
    }

    var payloadStart = tcp0 + dataOffset;
    var declaredPayload = Math.max(0, ipDeclaredEnd - payloadStart);
    var capturedPayload = Math.max(0, ipAvailableEnd - payloadStart);
    pkt.payloadDeclaredLen = declaredPayload;
    pkt.payloadCapturedLen = capturedPayload;
    if (ipDeclaredEnd > end) pkt.payloadTruncated = true; // 声明的载荷有一部分没抓到
    if (capturedPayload > 0) {
      // 只拷贝实际抓到的前缀：缺失部分绝不能用 0 或后续字节顶替
      pkt.payload = new Uint8Array(capturedPayload);
      pkt.payload.set(new Uint8Array(buf, payloadStart, capturedPayload));
    } else {
      pkt.payload = new Uint8Array(0);
    }
  }

  /*
   * 主入口。
   * opts.onProgress(donePackets) 可选。
   * 返回 { header, packets, stoppedTruncated:{...}|null, limits }
   */
  function analyzePcap(buffer, opts) {
    opts = opts || {};
    ensureSize(buffer.byteLength);
    var view = new DataView(buffer);
    var bytes = new Uint8Array(buffer);
    var header = parseGlobalHeader(view, bytes);

    var packets = [];
    var offset = 24;
    var total = buffer.byteLength;
    var stoppedTruncated = null;

    while (offset < total) {
      if (packets.length >= MAX_PACKETS) {
        throw PcapFatalError(
          "packet_limit",
          "包数量超过限定版上限 " +
            MAX_PACKETS +
            " 个：为保证浏览器本地处理，第 " +
            (MAX_PACKETS + 1) +
            " 个包起整份拒绝（请用 tcpdump -c / Wireshark 切分后再导入）。",
        );
      }
      var recIndex = packets.length;

      // —— 记录头 16 字节 ——
      if (total - offset < 16) {
        stoppedTruncated = {
          packetIndex: recIndex,
          fileOffset: offset,
          reason: "record_header_incomplete",
          detail: "剩余 " + (total - offset) + " 字节不足 16 字节记录头",
          evidence: new Uint8Array(buffer, offset, total - offset).slice(),
        };
        break;
      }
      var tsSec = view.getUint32(offset, true);
      var tsFrac = view.getUint32(offset + 4, true);
      var inclLen = view.getUint32(offset + 8, true);
      var origLen = view.getUint32(offset + 12, true);
      var recHeaderOffset = offset;
      offset += 16;

      if (inclLen > total - offset || inclLen > origLen) {
        // 帧体声称的长度超过文件剩余字节：截断记录，保留位置证据后停止
        stoppedTruncated = {
          packetIndex: recIndex,
          fileOffset: recHeaderOffset,
          reason: "frame_incomplete",
          detail:
            "记录声称 incl_len=" +
            inclLen +
            "，文件剩余 " +
            (total - offset) +
            " 字节",
          inclLen: inclLen,
          origLen: origLen,
          evidence: new Uint8Array(
            buffer,
            offset,
            Math.min(total - offset, 64),
          ).slice(),
        };
        break;
      }

      var frameStart = offset;
      var frameEnd = offset + inclLen;
      var pkt = {
        index: recIndex,
        fileOffset: recHeaderOffset,
        frameOffset: frameStart,
        tsSec: tsSec,
        tsFrac: tsFrac,
        tsText: Util.formatTs(tsSec, tsFrac, header.resolution),
        inclLen: inclLen,
        origLen: origLen,
        snapTruncated: inclLen < origLen,
        flags: 0,
        payload: new Uint8Array(0),
        payloadDeclaredLen: 0,
        payloadCapturedLen: 0,
      };
      try {
        dissectFrame(buffer, view, frameStart, frameEnd, pkt);
      } catch (e) {
        pkt.discardReason = "dissector_exception:" + (e && e.message);
      }
      packets.push(pkt);
      offset = frameEnd;

      if (opts.onProgress && recIndex % 200 === 0)
        opts.onProgress(recIndex + 1);
    }

    return {
      header: header,
      packets: packets,
      stoppedTruncated: stoppedTruncated,
      limits: { maxFileSize: MAX_FILE_SIZE, maxPackets: MAX_PACKETS },
      fileSize: total,
      parsedPackets: packets.length,
    };
  }

  return {
    MAX_FILE_SIZE: MAX_FILE_SIZE,
    MAX_PACKETS: MAX_PACKETS,
    PcapFatalError: PcapFatalError,
    ensureSize: ensureSize,
    parseGlobalHeader: parseGlobalHeader,
    analyzePcap: analyzePcap,
    FLAGS: {
      FIN: TCP_FIN,
      SYN: TCP_SYN,
      RST: TCP_RST,
      PSH: TCP_PSH,
      ACK: TCP_ACK,
      URG: TCP_URG,
    },
  };
});
