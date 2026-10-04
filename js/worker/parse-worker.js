/*
 * 解析 Worker：接收 {file:{name,lastModified}, buffer, token}，
 * 在 Worker 内完成 解析 -> 重组 -> 冻结结果，回发 {type, token, ...}。
 * 文件大小 / 包数限制在主线程预拦一次，Worker 内再拦一次（信任边界以 Worker 为准）。
 */
importScripts(
  "../core/util.js",
  "../core/pcap.js",
  "../core/fragments.js",
  "../core/reassemble.js",
  "../core/viewmodel.js",
);

self.onmessage = function (ev) {
  var msg = ev.data;
  if (!msg || msg.type !== "parse") return;
  var token = msg.token;
  function progress(done) {
    self.postMessage({ type: "progress", token: token, done: done });
  }
  try {
    Core_ensureSize(msg.buffer.byteLength);
    var analysis = self.PcapCore.analyzePcap(msg.buffer, {
      onProgress: progress,
    });
    var result = self.PcapReassemble.reassemble(analysis);
    result.fileMeta = {
      name: msg.file.name,
      lastModified: msg.file.lastModified,
    };
    // 冻结：后续导出始终引用此刻这个对象
    self.postMessage({ type: "done", token: token, result: result });
  } catch (e) {
    if (e && e.name === "PcapFatalError") {
      self.postMessage({
        type: "fatal",
        token: token,
        code: e.code,
        message: e.message,
      });
    } else {
      self.postMessage({
        type: "fatal",
        token: token,
        code: "internal",
        message: "解析器内部错误: " + (e && e.message),
      });
    }
  }
};

function Core_ensureSize(size) {
  // 与 core/pcap.js 的常量保持一致（双保险，正常主线程已拦）
  var MAX = 8 * 1024 * 1024;
  if (size > MAX) {
    var err = new Error("文件超过 8 MB 上限");
    err.name = "PcapFatalError";
    err.code = "file_too_large";
    throw err;
  }
}
