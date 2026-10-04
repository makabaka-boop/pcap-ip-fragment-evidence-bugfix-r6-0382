/* 主线程：文件导入、Worker 生命周期（token 防迟到结果）、界面渲染、导出。 */
(function () {
  "use strict";

  var state = {
    worker: null,
    box: PcapUtil.tokenBox(),
    result: null, // 当前冻结结果；导出始终引用它
    pendingFileName: null,
    selectedConn: null,
    selectedDir: 0,
    tab: "packets",
    viewMode: "text",
  };

  var els = {
    fileInput: document.getElementById("file-input"),
    cancelBtn: document.getElementById("cancel-btn"),
    exportJson: document.getElementById("export-json"),
    exportTxt: document.getElementById("export-txt"),
    fileInfo: document.getElementById("file-info"),
    connList: document.getElementById("conn-list"),
    fragList: document.getElementById("frag-list"),
    connPlaceholder: document.getElementById("conn-placeholder"),
    detail: document.getElementById("detail"),
    status: document.getElementById("status"),
    dropZone: document.getElementById("drop-zone"),
  };

  /* ---------------- Worker 生命周期 ---------------- */

  function importFile(file) {
    if (!file) return;
    // 大小闸门（Worker 内还有一道）
    if (file.size > PcapCore.MAX_FILE_SIZE) {
      showStatus(
        "fatal",
        "文件 " +
          file.name +
          " 为 " +
          formatBytes(file.size) +
          "，超过限定版 8 MB 上限，未读取任何字节。",
      );
      return;
    }
    // 取消旧 Worker：换 token + terminate，旧 Worker 迟到的回发永远进不来，
    // 即便极端情况下消息已排队，token 校验也会丢弃它。
    teardownWorker();
    var token = state.box.next();
    state.pendingFileName = file.name;
    setControls(true);
    showStatus("info", "正在读取并解析 " + file.name + " …");

    var reader = new FileReader();
    reader.onload = function () {
      if (!state.box.isCurrent(token)) return; // 读取期间被取消/替换
      var worker = new Worker("js/worker/parse-worker.js");
      state.worker = worker;
      worker.onmessage = function (ev) {
        var msg = ev.data;
        if (msg.token !== token || !state.box.isCurrent(token)) return; // 旧 Worker 迟到结果：丢弃
        if (msg.type === "progress") {
          showStatus(
            "info",
            "正在解析 " + file.name + "：已处理 " + msg.done + " 个包…",
          );
        } else if (msg.type === "done") {
          state.result = msg.result; // 冻结
          state.selectedConn = msg.result.connections[0]
            ? msg.result.connections[0].id
            : null;
          state.selectedDir = 0;
          state.tab = "packets";
          finishOk();
        } else if (msg.type === "fatal") {
          teardownWorker();
          state.box.cancel();
          state.result = null;
          setControls(false);
          els.fileInfo.textContent = file.name;
          renderConnections();
          renderFragmentGroups();
          els.detail.innerHTML = "";
          els.detail.appendChild(placeholder("文件被整份拒绝：" + msg.message));
          showStatus("fatal", msg.message);
        }
      };
      worker.onerror = function (e) {
        if (!state.box.isCurrent(token)) return;
        showStatus("fatal", "Worker 错误: " + e.message);
        teardownWorker();
        state.box.cancel();
        setControls(false);
      };
      worker.postMessage(
        {
          type: "parse",
          token: token,
          file: { name: file.name, lastModified: file.lastModified },
          buffer: reader.result,
        },
        [reader.result],
      );
    };
    reader.onerror = function () {
      if (!state.box.isCurrent(token)) return;
      showStatus(
        "fatal",
        "读取失败: " + (reader.error && reader.error.message),
      );
      state.box.cancel();
      setControls(false);
    };
    reader.readAsArrayBuffer(file);
  }

  function teardownWorker() {
    if (state.worker) {
      state.worker.onmessage = null;
      state.worker.onerror = null;
      state.worker.terminate();
      state.worker = null;
    }
  }

  function cancelParse() {
    teardownWorker();
    state.box.cancel();
    state.pendingFileName = null;
    setControls(false);
    showStatus("info", "已取消。当前保留的仍是上一份冻结结果（若有）。");
    if (state.result) {
      els.fileInfo.textContent =
        state.result.fileMeta.name + "（冻结结果保留）";
    }
  }

  function finishOk() {
    teardownWorker();
    setControls(false);
    var r = state.result;
    var st = r.stoppedTruncated;
    els.fileInfo.textContent =
      r.fileMeta.name +
      " · " +
      formatBytes(r.fileSize) +
      " · " +
      r.stats.packetCount +
      " 包 · " +
      r.stats.connectionCount +
      " 连接";
    var msgs = [];
    if (st) {
      msgs.push(
        "⚠ 在第 " +
          st.packetIndex +
          " 个记录（文件偏移 " +
          st.fileOffset +
          "）遇到截断：" +
          st.detail +
          "。已保留位置证据，该记录之后不再解析。",
      );
    }
    msgs.push(
      "解析完成：数据 " +
        r.stats.totalDataBytes +
        " 字节，缺口 " +
        r.stats.totalGapBytes +
        " 字节，冲突 " +
        r.stats.totalConflictBytes +
        " 字节。",
    );
    (r.fragmentGroups || []).forEach(function (g) {
      msgs.push(
        "IP 分片组 " +
          g.key +
          "：" +
          g.status +
          (g.detail ? "（" + g.detail + "）" : ""),
      );
    });
    showStatus(st ? "fatal" : "info", msgs.join(" "));
    renderConnections();
    renderFragmentGroups();
    renderDetail();
  }

  /* IP 分片组证据：与导出共用同一份冻结结果，常驻侧栏（不随状态条消失） */
  var FRAG_STATUS_TEXT = {
    complete: "完整",
    incomplete: "不完整",
    conflict: "重叠冲突",
    length_mismatch: "终止长度不一致",
    invalid_fragment: "分片不合法",
    invalid_tcp: "TCP 无效",
  };

  function renderFragmentGroups() {
    els.fragList.innerHTML = "";
    if (!state.result) return;
    var groups = state.result.fragmentGroups || [];
    if (!groups.length) return;
    var hdr = document.createElement("div");
    hdr.className = "frag-hdr";
    hdr.textContent = "IP 分片组（" + groups.length + "）";
    els.fragList.appendChild(hdr);
    groups.forEach(function (g) {
      var ok = g.status === "complete";
      var div = document.createElement("div");
      div.className = "frag " + (ok ? "ok" : "bad");
      var html =
        "<b>" +
        esc(g.srcIp) +
        " → " +
        esc(g.dstIp) +
        "</b> · id " +
        g.ipId +
        ' · <span class="badge ' +
        (ok ? "ok" : "gap") +
        '">' +
        esc(FRAG_STATUS_TEXT[g.status] || g.status) +
        "</span><br>" +
        '<span class="kv">成员包 ' +
        g.indexes
          .map(function (i) {
            return "#" + i;
          })
          .join(" ") +
        (g.totalLen != null ? " · 总长 " + g.totalLen : "") +
        (g.carrierIndex != null ? " · 载体包 #" + g.carrierIndex : "") +
        (g.dupBytes ? " · 重复字节 " + g.dupBytes : "") +
        "</span>";
      if (g.holes && g.holes.length) {
        html +=
          '<br><span class="kv">缺口 ' +
          g.holes
            .map(function (h) {
              return h.start + ".." + h.end;
            })
            .join(", ") +
          "</span>";
      }
      if (g.conflicts && g.conflicts.length) {
        html +=
          '<br><span class="kv">冲突 ' +
          g.conflicts
            .map(function (c) {
              return c.start + ".." + c.end;
            })
            .join(", ") +
          "</span>";
      }
      if (g.detail) html += '<br><span class="kv">' + esc(g.detail) + "</span>";
      div.innerHTML = html;
      els.fragList.appendChild(div);
    });
  }

  function setControls(parsing) {
    els.cancelBtn.disabled = !parsing;
    var has = !!state.result;
    els.exportJson.disabled = !has;
    els.exportTxt.disabled = !has;
  }

  /* ---------------- 渲染：连接列表 ---------------- */

  function renderConnections() {
    els.connList.innerHTML = "";
    els.connPlaceholder.style.display =
      state.result && state.result.connections.length ? "none" : "block";
    if (!state.result) return;
    state.result.connections.forEach(function (c) {
      var div = document.createElement("div");
      div.className = "conn" + (c.id === state.selectedConn ? " active" : "");
      var marks = [];
      c.dirs.forEach(function (d) {
        if (!d.present) return;
        if (d.stats.gapBytes)
          marks.push(
            '<span class="badge gap">缺口 ' + d.stats.gapBytes + "</span>",
          );
        if (d.stats.conflictBytes)
          marks.push(
            '<span class="badge conflict">冲突 ' +
              d.stats.conflictBytes +
              "</span>",
          );
      });
      var complete = c.dirs.every(function (d) {
        return !d.present || d.complete;
      });
      marks.unshift(
        complete
          ? '<span class="badge ok">完整</span>'
          : '<span class="badge gap">不完整</span>',
      );
      div.innerHTML =
        '<div class="ep">' +
        esc(c.endpointA) +
        "</div>" +
        '<div class="ep">⇅ ' +
        esc(c.endpointB) +
        "</div>" +
        '<div class="meta"><span>#' +
        c.order +
        " · " +
        c.pktIndexes.length +
        " 包</span>" +
        marks.join(" ") +
        "</div>";
      div.addEventListener("click", function () {
        state.selectedConn = c.id;
        state.selectedDir = 0;
        renderConnections();
        renderDetail();
      });
      els.connList.appendChild(div);
    });
  }

  /* ---------------- 渲染：详情 ---------------- */

  function selectedConn() {
    if (!state.result || !state.selectedConn) return null;
    return state.result.connections.find(function (c) {
      return c.id === state.selectedConn;
    });
  }

  function renderDetail() {
    var c = selectedConn();
    if (!c) {
      els.detail.innerHTML = "";
      els.detail.appendChild(placeholder("该文件中没有可显示的 TCP 连接"));
      return;
    }
    els.detail.innerHTML = "";

    // 连接标题 + 方向切换
    var hdr = document.createElement("div");
    hdr.className = "toolbar";
    hdr.innerHTML =
      "<div><b>连接 #" +
      c.order +
      "</b> " +
      '<span class="dirseg">' +
      esc(c.endpointA) +
      " ⇄ " +
      esc(c.endpointB) +
      "</span></div>";
    var dirSel = document.createElement("select");
    c.dirs.forEach(function (d, di) {
      var opt = document.createElement("option");
      opt.value = String(di);
      var label = di === 0 ? "A → B" : "B → A";
      var parts = [];
      parts.push(d.present ? d.stats.dataBytes + " 字节" : "无包");
      if (d.stats.gapBytes) parts.push("缺口 " + d.stats.gapBytes);
      if (d.stats.conflictBytes) parts.push("冲突 " + d.stats.conflictBytes);
      opt.textContent = label + "（" + parts.join("，") + "）";
      dirSel.appendChild(opt);
    });
    dirSel.value = String(state.selectedDir);
    dirSel.addEventListener("change", function () {
      state.selectedDir = Number(dirSel.value);
      renderDetail();
    });
    hdr.appendChild(dirSel);
    els.detail.appendChild(hdr);

    // tabs
    var tabs = document.createElement("div");
    tabs.className = "tabs";
    [
      ["packets", "包"],
      ["stream", "重组文本 / HEX"],
      ["gaps", "缺口"],
      ["conflicts", "冲突"],
    ].forEach(function (t) {
      var s = document.createElement("div");
      s.className = "tab" + (state.tab === t[0] ? " active" : "");
      s.textContent = t[1];
      s.addEventListener("click", function () {
        state.tab = t[0];
        renderDetail();
      });
      tabs.appendChild(s);
    });
    els.detail.appendChild(tabs);

    var d = c.dirs[state.selectedDir];
    if (!d.present) {
      els.detail.appendChild(placeholder("该方向上没有抓到任何 TCP 包"));
      return;
    }
    if (state.tab === "packets") renderPackets(c);
    else if (state.tab === "stream") renderStream(c, d);
    else if (state.tab === "gaps") renderGaps(c, d);
    else renderConflicts(c, d);
  }

  function pktEndpoints(p) {
    return (
      esc(p.srcIp || "?") +
      ".<b>" +
      (p.srcPort ?? "?") +
      "</b> → " +
      esc(p.dstIp || "?") +
      ".<b>" +
      (p.dstPort ?? "?") +
      "</b>"
    );
  }

  function renderPackets(c) {
    var indexes = new Set(c.pktIndexes);
    var note = document.createElement("div");
    note.className = "note";
    note.innerHTML =
      '标记：<span class="m-retrans">重传去重</span> ' +
      '<span class="m-ooo">乱序到达</span> ' +
      '<span class="m-conflict">字节冲突</span> ' +
      '<span class="m-trunc">抓包截断</span>。序号列为「相对序号」（无 SYN 时以该方向首字节为 0）。';
    els.detail.appendChild(note);

    var wrap = document.createElement("div");
    wrap.style.maxHeight = "70vh";
    wrap.style.overflow = "auto";
    var table = document.createElement("table");
    table.innerHTML =
      "<thead><tr><th>#</th><th>时间</th><th>方向</th><th>源 → 目的</th>" +
      "<th>标志</th><th>seq(rel)</th><th>ack</th><th>载荷 cap/decl</th><th>标记/原因</th></tr></thead>";
    var tbody = document.createElement("tbody");
    state.result.packets.forEach(function (p) {
      if (p.connId !== c.id) return;
      var tr = document.createElement("tr");
      tr.className = "pkt-row";
      var marks = "";
      if (p.isRetrans)
        marks += '<span class="m-retrans">重传×' + p.dupBytes + "</span>";
      if (p.outOfOrder) marks += '<span class="m-ooo">乱序</span>';
      if (p.conflictBytes)
        marks += '<span class="m-conflict">冲突×' + p.conflictBytes + "</span>";
      if (p.payloadTruncated) marks += '<span class="m-trunc">载荷截断</span>';
      if (p.snapTruncated && !p.payloadTruncated)
        marks += '<span class="m-trunc">snap截断</span>';
      if (p.fragmentIndexes && p.fragmentIndexes.length)
        marks +=
          '<span class="m-frag">分片重组×' +
          p.fragmentIndexes.length +
          "</span>";
      var last = p.discardReason
        ? '<span class="discard">' + esc(p.discardReason) + "</span>"
        : marks;
      tr.innerHTML =
        "<td>" +
        p.index +
        "</td>" +
        "<td>" +
        esc(p.tsText) +
        "</td>" +
        "<td>" +
        (p.dir === 0 ? "A→B" : "B→A") +
        "</td>" +
        "<td>" +
        pktEndpoints(p) +
        "</td>" +
        "<td>" +
        esc(p.flagText) +
        "</td>" +
        "<td>" +
        (p.relSeq == null ? "-" : p.relSeq) +
        (p.seq == null
          ? ""
          : ' <span class="kv">(' + u32hex(p.seq) + ")</span>") +
        "</td>" +
        "<td>" +
        (p.ack == null ? "-" : u32hex(p.ack)) +
        "</td>" +
        "<td>" +
        p.payloadCapturedLen +
        "/" +
        p.payloadDeclaredLen +
        "</td>" +
        '<td class="marks">' +
        last +
        "</td>";
      tr.addEventListener("click", function () {
        tr.classList.toggle("selected");
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    els.detail.appendChild(wrap);
  }

  var RENDER_MAX = 256 * 1024;

  function renderStream(c, d) {
    var bar = document.createElement("div");
    bar.className = "toolbar";
    bar.innerHTML =
      '<span class="pill ' +
      (d.complete ? "badge ok" : "badge gap") +
      '">' +
      (d.complete
        ? "该方向重组完整，无缺口"
        : "该方向存在缺口（见「缺口」页）") +
      "</span>" +
      '<span class="kv">数据 <b>' +
      d.stats.dataBytes +
      "</b> 字节 · 缺口 <b>" +
      d.stats.gapBytes +
      "</b> · 冲突 <b>" +
      d.stats.conflictBytes +
      "</b></span>" +
      '<label class="btn"><input type="radio" name="viewmode" value="text"' +
      (state.viewMode === "text" ? " checked" : "") +
      "> 文本（有损 UTF-8）</label>" +
      '<label class="btn"><input type="radio" name="viewmode" value="hex"' +
      (state.viewMode === "hex" ? " checked" : "") +
      "> 十六进制</label>";
    bar.querySelectorAll("input").forEach(function (inp) {
      inp.addEventListener("change", function () {
        state.viewMode = inp.value;
        renderDetail();
      });
    });
    els.detail.appendChild(bar);

    if (state.viewMode === "text") renderText(d);
    else renderHex(d);
  }

  function renderText(d) {
    var tm = PcapView.buildTextTokens(d, { maxBytes: RENDER_MAX });
    var pre = document.createElement("pre");
    pre.className = "stream";
    tm.tokens.forEach(function (tk) {
      if (tk.t === "text") {
        pre.appendChild(document.createTextNode(tk.str));
      } else if (tk.t === "gap") {
        var sp = document.createElement("span");
        sp.className = "tok-gap";
        sp.textContent =
          "⟦缺口 " +
          (tk.start - d.origin) +
          ".." +
          (tk.end - d.origin) +
          "（" +
          tk.length +
          " 字节缺失，未填充）⟧";
        pre.appendChild(sp);
      } else {
        var cf = document.createElement("span");
        cf.className = "tok-conflict";
        cf.textContent =
          "⟦冲突 " +
          (tk.range.start - d.origin) +
          ".." +
          (tk.range.end - d.origin) +
          "⟧";
        cf.title = tk.range.entries
          .map(function (e) {
            return (
              "rel" +
              (e.pos - d.origin) +
              ": " +
              Object.keys(e.byPkt)
                .map(function (pi) {
                  return (
                    "pkt" +
                    pi +
                    "=0x" +
                    e.byPkt[pi].toString(16).padStart(2, "0")
                  );
                })
                .join(", ")
            );
          })
          .join("\n");
        pre.appendChild(cf);
      }
    });
    els.detail.appendChild(pre);
    var note = document.createElement("div");
    note.className = "note";
    note.textContent =
      "文本按 UTF-8 有损解码（非法序列显示为 �）；缺口/冲突位置的字节不参与解码，" +
      "不会与相邻字节拼出伪造字符。" +
      (tm.truncated ? " 渲染已截断至 256 KiB，完整内容请用导出。" : "");
    els.detail.appendChild(note);
  }

  function renderHex(d) {
    var hm = PcapView.buildHexRows(d, { maxBytes: RENDER_MAX });
    var table = document.createElement("table");
    table.className = "hex-table";
    var tbody = document.createElement("tbody");
    hm.rows.forEach(function (row) {
      var tr = document.createElement("tr");
      var off = document.createElement("td");
      off.className = "off";
      off.textContent = String(row.offset).padStart(8, "0");
      tr.appendChild(off);
      var cells = document.createElement("td");
      row.cells.forEach(function (cell) {
        var span = document.createElement("span");
        if (cell.gap) {
          span.className = "hex-cell-gap";
          span.textContent = "·· ";
        } else if (cell.conflict) {
          span.className = "hex-cell-conflict";
          span.textContent = cell.byte.toString(16).padStart(2, "0") + " ";
          span.title =
            "冲突位置；首持字节来自 pkt" + cell.pktIndex + "，详见冲突页";
        } else {
          span.textContent = cell.byte.toString(16).padStart(2, "0") + " ";
          span.title = "pkt" + cell.pktIndex;
        }
        cells.appendChild(span);
      });
      tr.appendChild(cells);
      var asc = document.createElement("td");
      asc.className = "hex-ascii";
      asc.textContent = row.ascii;
      tr.appendChild(asc);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    els.detail.appendChild(table);
    var note = document.createElement("div");
    note.className = "note";
    note.innerHTML =
      '黄 <span class="hex-cell-gap">··</span> = 缺失字节（缺口）；红底 = 冲突位置（' +
      "显示首持字节，悬停看包号；所有候选字节见冲突页）。偏移为相对数据起点。" +
      (hm.truncated ? " 渲染已截断至 256 KiB，完整内容请用导出。" : "");
    els.detail.appendChild(note);
  }

  function renderGaps(c, d) {
    if (!d.gaps.length) {
      els.detail.appendChild(placeholder("该方向没有缺口。"));
      return;
    }
    d.gaps.forEach(function (g) {
      var div = document.createElement("div");
      div.className = "item gap";
      var kindText =
        { internal: "内部缺口", leading: "首部缺口", trailing: "尾部缺口" }[
          g.kind
        ] || g.kind;
      div.innerHTML =
        "<b>" +
        kindText +
        "</b> · 相对区间 <code>" +
        (g.start - d.origin) +
        " .. " +
        (g.end - d.origin) +
        "</code> · <b>" +
        (g.end - g.start) +
        "</b> 字节缺失<br>" +
        '<span class="kv">重组器在此区间没有任何抓到的字节，已显式留空；不会用任何内容填充。</span>';
      els.detail.appendChild(div);
    });
  }

  function renderConflicts(c, d) {
    if (!d.conflictRanges.length) {
      els.detail.appendChild(placeholder("该方向没有重叠字节冲突。"));
      return;
    }
    var intro = document.createElement("div");
    intro.className = "note";
    intro.textContent =
      "重叠位置出现了不一致的字节。重组结果在冲突位置不选边覆盖；" +
      "下列每个候选字节（按包号）都保留，可与缺口一起在文本/HEX 页查看位置。";
    els.detail.appendChild(intro);
    d.conflictRanges.forEach(function (r) {
      var div = document.createElement("div");
      div.className = "item conflict";
      var html =
        "<b>冲突区间 rel " +
        (r.start - d.origin) +
        " .. " +
        (r.end - d.origin) +
        "</b>（" +
        (r.end - r.start) +
        " 字节）<br>";
      r.entries.forEach(function (e) {
        var cand = Object.keys(e.byPkt)
          .map(Number)
          .sort(function (a, b) {
            return a - b;
          })
          .map(function (pi) {
            return (
              "pkt" +
              pi +
              "=<code>0x" +
              e.byPkt[pi].toString(16).padStart(2, "0") +
              "</code>"
            );
          })
          .join("，");
        html += "rel" + (e.pos - d.origin) + "：" + cand + "<br>";
      });
      div.innerHTML = html;
      els.detail.appendChild(div);
    });
  }

  /* ---------------- 导出（引用冻结结果） ---------------- */

  function download(name, mime, text) {
    var blob = new Blob([text], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(function () {
      URL.revokeObjectURL(a.href);
    }, 4000);
  }

  function doExport(kind) {
    if (!state.result) return; // 导出按钮在无冻结结果时本就禁用
    var base = (state.result.fileMeta.name || "capture").replace(
      /\.pcap$/i,
      "",
    );
    if (kind === "json") {
      download(
        base + ".reassembly.json",
        "application/json",
        PcapView.exportJson(state.result),
      );
    } else {
      download(
        base + ".reassembly.txt",
        "text/plain;charset=utf-8",
        PcapView.exportText(state.result),
      );
    }
  }

  /* ---------------- 杂项 ---------------- */

  function showStatus(kind, msg) {
    els.status.className = "show " + kind;
    els.status.textContent = msg;
    if (kind === "info" && state.result && !state.worker) {
      clearTimeout(showStatus._t);
      showStatus._t = setTimeout(function () {
        els.status.className = "";
      }, 4000);
    }
  }

  function placeholder(text) {
    var d = document.createElement("div");
    d.className = "placeholder";
    d.textContent = text;
    return d;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (ch) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[ch];
    });
  }
  function u32hex(n) {
    return "0x" + (n >>> 0).toString(16).padStart(8, "0");
  }
  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1024 / 1024).toFixed(2) + " MB";
  }

  els.fileInput.addEventListener("change", function () {
    var f = els.fileInput.files && els.fileInput.files[0];
    importFile(f);
    els.fileInput.value = "";
  });
  els.cancelBtn.addEventListener("click", cancelParse);
  els.exportJson.addEventListener("click", function () {
    doExport("json");
  });
  els.exportTxt.addEventListener("click", function () {
    doExport("txt");
  });

  ["dragenter", "dragover"].forEach(function (ev) {
    els.dropZone.addEventListener(ev, function (e) {
      e.preventDefault();
      els.dropZone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    els.dropZone.addEventListener(ev, function (e) {
      e.preventDefault();
      els.dropZone.classList.remove("dragover");
    });
  });
  els.dropZone.addEventListener("drop", function (e) {
    var f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) importFile(f);
  });
})();
