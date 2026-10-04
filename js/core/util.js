/*
 * 公共小工具：UMD，可同时在浏览器 / Worker / Node 中使用。
 * 不依赖任何全局环境 API（除了 TextDecoder，调用方按需传入）。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PcapUtil = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  function base64Encode(bytes) {
    var out = "";
    var i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out +=
        B64[(n >> 18) & 63] +
        B64[(n >> 12) & 63] +
        B64[(n >> 6) & 63] +
        B64[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
      var n1 = bytes[i] << 16;
      out += B64[(n1 >> 18) & 63] + B64[(n1 >> 12) & 63] + "==";
    } else if (rem === 2) {
      var n2 = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out +=
        B64[(n2 >> 18) & 63] + B64[(n2 >> 12) & 63] + B64[(n2 >> 6) & 63] + "=";
    }
    return out;
  }

  function bytesToHex(bytes, max) {
    var n = Math.min(bytes.length, max == null ? bytes.length : max);
    var s = "";
    for (var i = 0; i < n; i++) {
      if (i) s += " ";
      s += bytes[i].toString(16).padStart(2, "0");
    }
    if (n < bytes.length) s += " …";
    return s;
  }

  /* 时间戳格式化。resolution: 'us' | 'ns' */
  function formatTs(tsSec, tsFrac, resolution) {
    var base = Number.isFinite(tsSec) ? tsSec : 0;
    var d = new Date(base * 1000);
    var dateStr =
      d.getFullYear() +
      "-" +
      String(d.getMonth() + 1).padStart(2, "0") +
      "-" +
      String(d.getDate()).padStart(2, "0") +
      " " +
      String(d.getHours()).padStart(2, "0") +
      ":" +
      String(d.getMinutes()).padStart(2, "0") +
      ":" +
      String(d.getSeconds()).padStart(2, "0");
    var frac;
    if (resolution === "ns") {
      frac = String(tsFrac).padStart(9, "0");
    } else {
      frac = String(tsFrac).padStart(6, "0");
    }
    return dateStr + "." + frac;
  }

  /*
   * Worker 生命周期令牌箱：
   * 每次导入新文件或取消都换一个 token；旧 Worker 的迟到结果凭 token 判定丢弃。
   */
  function tokenBox() {
    var current = null;
    return {
      next: function () {
        current = {};
        return current;
      },
      cancel: function () {
        current = null;
        return null;
      },
      isCurrent: function (t) {
        return t !== null && t === current;
      },
      active: function () {
        return current !== null;
      },
    };
  }

  return {
    base64Encode: base64Encode,
    bytesToHex: bytesToHex,
    formatTs: formatTs,
    tokenBox: tokenBox,
  };
});
