/*
 * 冻结结果 -> 文本 / 十六进制视图模型，以及导出对象。
 * 文本视图对非法 UTF-8 使用 U+FFFD 替换（显示即注明“有损解码”，原始字节始终在
 * data/gap/conflict 结构中可查可导出，不存在伪造内容的问题）。
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(
      require("./reassemble"),
      require("./util"),
      require("./pcap"),
    );
  } else
    root.PcapView = factory(root.PcapReassemble, root.PcapUtil, root.PcapCore);
})(typeof self !== "undefined" ? self : this, function (R, Util, Core) {
  "use strict";

  var GAP_TEXT = "␣"; // ␣ 风格占位，由 CSS 高亮

  /*
   * 返回有序 token：
   *  {t:'text', str}                 —— 重组出的真实字节（可能含 U+FFFD 替换符）
   *  {t:'gap', start,end,length}
   *  {t:'conflict', range:{start,end,entries}}
   */
  function buildTextTokens(dir, opts) {
    opts = opts || {};
    var makeDecoder = function () {
      if (typeof TextDecoder !== "undefined")
        return new TextDecoder("utf-8", { fatal: false });
      return null;
    };
    var decoder = makeDecoder();
    var tokens = [];
    var budget = opts.maxBytes == null ? Infinity : opts.maxBytes;
    var used = 0;
    var truncated = false;
    var pending = [];
    var textBuf = "";

    // 缺口/冲突是字节流中的真实断裂：先 flush（悬挂的半个多字节序列 -> U+FFFD），
    // 再换新解码器，绝不能让缺口两侧的字节拼成一个字符。
    function boundary() {
      if (decoder && pending.length) {
        textBuf += decoder.decode(concat(pending), { stream: false });
      } else if (!decoder && pending.length) {
        pending.forEach(function (bytes) {
          for (var i = 0; i < bytes.length; i++)
            textBuf += String.fromCharCode(bytes[i]);
        });
      }
      pending = [];
      if (textBuf) {
        tokens.push({ t: "text", str: textBuf });
        textBuf = "";
      }
      decoder = makeDecoder();
    }
    dir.chunks.forEach(function (ch) {
      if (ch.kind === "gap") {
        boundary();
        tokens.push({
          t: "gap",
          start: ch.start,
          end: ch.end,
          length: ch.end - ch.start,
        });
        return;
      }
      if (ch.kind === "conflict") {
        boundary();
        tokens.push({
          t: "conflict",
          range: { start: ch.start, end: ch.end, entries: ch.entries },
        });
        return;
      }
      var take = ch.bytes.length;
      if (used + take > budget) {
        take = Math.max(0, budget - used);
        truncated = true;
      }
      if (take > 0) {
        var bytes =
          take === ch.bytes.length ? ch.bytes : ch.bytes.slice(0, take);
        pending.push(bytes);
        used += take;
      }
    });
    boundary();
    return { tokens: tokens, truncated: truncated };
  }

  function concat(arrs) {
    var n = 0;
    arrs.forEach(function (a) {
      n += a.length;
    });
    var out = new Uint8Array(n);
    var o = 0;
    arrs.forEach(function (a) {
      out.set(a, o);
      o += a.length;
    });
    return out;
  }

  /*
   * 十六进制 + ASCII 行模型（16 字节/行）：
   * {offset, cells:[{byte|gap:true|conflict:true, pktIndex?}], ascii:'...'}
   */
  function buildHexRows(dir, opts) {
    opts = opts || {};
    var maxBytes = opts.maxBytes == null ? Infinity : opts.maxBytes;
    var rows = [];
    var origin = dir.origin;
    var hasSyn = dir.synAbs != null;
    var startBase = origin + (hasSyn ? 1 : 0);

    var posMap = buildPosMap(dir);
    var extent = dir.extentEnd;
    if (extent == null) {
      extent = dir.chunks.reduce(function (m, ch) {
        return Math.max(m, ch.end);
      }, startBase);
    }
    var endBase = extent;
    if (startBase >= endBase && dir.chunks.length === 0)
      return { rows: [], truncated: false, startBase: startBase };

    var used = 0;
    var truncated = false;
    for (var base = startBase; base < endBase; base += 16) {
      var cells = [];
      var ascii = "";
      for (var k = 0; k < 16; k++) {
        var pos = base + k;
        if (pos >= endBase) break;
        if (used >= maxBytes) {
          truncated = true;
          break;
        }
        used++;
        var m = posMap[pos];
        if (!m) {
          cells.push({ gap: true });
          ascii += " ";
        } else if (m.conflict) {
          cells.push({ conflict: true, byte: m.byte, pktIndex: m.pktIndex });
          // ASCII 区用 ✗ 提示冲突
          ascii += "✗";
        } else {
          cells.push({ byte: m.byte, pktIndex: m.pktIndex });
          ascii +=
            m.byte >= 0x20 && m.byte < 0x7f ? String.fromCharCode(m.byte) : ".";
        }
      }
      rows.push({ offset: base - startBase, cells: cells, ascii: ascii });
      if (truncated) break;
    }
    return { rows: rows, truncated: truncated, startBase: startBase };
  }

  /* pos -> {byte, pktIndex, conflict?}，冲突位置取首个持有字节并标 conflict */
  function buildPosMap(dir) {
    var map = Object.create(null);
    var conflictSet = new Set();
    dir.conflictRanges.forEach(function (r) {
      for (var p = r.start; p < r.end; p++) conflictSet.add(p);
    });
    dir.chunks.forEach(function (ch) {
      if (ch.kind !== "data") return;
      for (var i = 0; i < ch.bytes.length; i++) {
        var pos = ch.start + i;
        map[pos] = { byte: ch.bytes[i], pktIndex: ch.owner[i] };
      }
    });
    conflictSet.forEach(function (p) {
      if (map[p]) map[p].conflict = true;
    });
    return map;
  }

  function conflictHexList(range, packets) {
    return range.entries.map(function (e) {
      var byPkt = Object.keys(e.byPkt)
        .map(function (idx) {
          return {
            packetIndex: Number(idx),
            byte: e.byPkt[idx],
            hex: e.byPkt[idx].toString(16).padStart(2, "0"),
          };
        })
        .sort(function (a, b) {
          return a.packetIndex - b.packetIndex;
        });
      return { pos: e.pos, byPacket: byPkt };
    });
  }

  /* ---------------- 导出 ---------------- */

  function buildExport(result, opts) {
    opts = opts || {};
    var conns = result.connections.map(function (c) {
      return {
        id: c.id,
        endpointA: c.endpointA,
        endpointB: c.endpointB,
        packetIndexes: c.pktIndexes,
        directions: c.dirs.map(function (d, di) {
          return {
            direction: di === 0 ? "A->B" : "B->A",
            originAbsoluteSeq: d.origin,
            complete: d.complete,
            stats: d.stats,
            gaps: d.gaps.map(function (g) {
              return relGap(g, d);
            }),
            conflicts: d.conflictRanges.map(function (r) {
              return {
                startRel: r.start - d.origin,
                endRel: r.end - d.origin,
                length: r.end - r.start,
                bytes: r.entries.map(function (e) {
                  var by = {};
                  Object.keys(e.byPkt).forEach(function (pi) {
                    by[pi] = e.byPkt[pi];
                  });
                  return { relOffset: e.pos - d.origin, byPacket: by };
                }),
              };
            }),
            chunks: d.chunks.map(function (ch) {
              if (ch.kind === "gap") {
                return {
                  kind: "gap",
                  startRel: ch.start - d.origin,
                  endRel: ch.end - d.origin,
                  length: ch.end - ch.start,
                };
              }
              if (ch.kind === "conflict") {
                return {
                  kind: "conflict",
                  startRel: ch.start - d.origin,
                  endRel: ch.end - d.origin,
                };
              }
              return {
                kind: "data",
                startRel: ch.start - d.origin,
                endRel: ch.end - d.origin,
                length: ch.end - ch.start,
                sourcePackets: ownerSummary(ch.owner),
                base64: Util.base64Encode(ch.bytes),
              };
            }),
          };
        }),
      };
    });

    return {
      tool: "browser-local-pcap-reassembly",
      formatVersion: 1,
      note: "导出引用解析完成时冻结的重组结果；随后重新导入/取消不会改变本内容。",
      frozenAt: result.frozenAt,
      file: {
        sizeBytes: result.fileSize,
        globalHeader: result.header,
        stoppedTruncated: result.stoppedTruncated,
      },
      stats: result.stats,
      packets: result.packets,
      connections: conns,
      // 分片证据（含不完整 / 冲突 / 不合法的组）与页面展示同源，一并冻结导出
      fragmentGroups: result.fragmentGroups || [],
    };
  }

  function relGap(g, d) {
    return {
      startRel: g.start - d.origin,
      endRel: g.end - d.origin,
      length: g.end - g.start,
      kind: g.kind,
    };
  }

  function ownerSummary(owner) {
    var counts = {};
    for (var i = 0; i < owner.length; i++) {
      var k = owner[i];
      counts[k] = (counts[k] || 0) + 1;
    }
    return Object.keys(counts)
      .map(Number)
      .sort(function (a, b) {
        return a - b;
      })
      .map(function (pi) {
        return { packetIndex: pi, bytes: counts[pi] };
      });
  }

  function exportJson(result) {
    return JSON.stringify(buildExport(result), null, 2);
  }

  /*
   * 纯文本导出：连接 -> 方向 -> 重组文本（有损，显式标注缺口/冲突），
   * 后面附包表。原始字节的无损版本见 JSON 导出的 base64。
   */
  function exportText(result) {
    var lines = [];
    lines.push(
      "Browser-local PCAP reassembly — text view (lossy; base64 of every chunk is in the JSON export)",
    );
    lines.push("FrozenAt: " + result.frozenAt);
    lines.push(
      "File: " +
        result.fileSize +
        " bytes, packets: " +
        result.stats.packetCount +
        ", connections: " +
        result.stats.connectionCount,
    );
    if (result.stoppedTruncated) {
      lines.push(
        "PARSING STOPPED at truncated record: " +
          JSON.stringify({
            packetIndex: result.stoppedTruncated.packetIndex,
            fileOffset: result.stoppedTruncated.fileOffset,
            reason: result.stoppedTruncated.reason,
            detail: result.stoppedTruncated.detail,
          }),
      );
    }
    lines.push("");

    result.connections.forEach(function (c) {
      lines.push(
        "=== Connection " +
          c.id +
          "  " +
          c.endpointA +
          "  <->  " +
          c.endpointB +
          " ===",
      );
      c.dirs.forEach(function (d, di) {
        if (!d.present) return;
        var label =
          di === 0
            ? c.endpointA + " -> " + c.endpointB
            : c.endpointB + " -> " + c.endpointA;
        lines.push(
          "--- Direction " +
            label +
            "  data=" +
            d.stats.dataBytes +
            " gap=" +
            d.stats.gapBytes +
            " conflict=" +
            d.stats.conflictBytes +
            (d.complete ? "  [COMPLETE]" : "  [INCOMPLETE]") +
            " ---",
        );
        var tm = buildTextTokens(d);
        tm.tokens.forEach(function (tk) {
          if (tk.t === "text") lines.push(tk.str);
          else if (tk.t === "gap") {
            lines.push(
              "\n[[GAP rel " +
                (tk.start - d.origin) +
                ".." +
                (tk.end - d.origin) +
                " (" +
                tk.length +
                " bytes missing, NOT reconstructed)]]\n",
            );
          } else {
            lines.push(
              "\n[[CONFLICT rel " +
                (tk.range.start - d.origin) +
                ".." +
                (tk.range.end - d.origin) +
                ": " +
                conflictSummary(tk.range, d.origin) +
                "]]\n",
            );
          }
        });
        lines.push("");
      });
      lines.push("");
    });

    var fragGroups = result.fragmentGroups || [];
    if (fragGroups.length) {
      lines.push("=== IPv4 Fragment Groups ===");
      fragGroups.forEach(function (g) {
        lines.push(
          "group " +
            g.key +
            "  status=" +
            g.status +
            "  members=[" +
            g.indexes.join(",") +
            "]" +
            (g.totalLen != null ? "  totalLen=" + g.totalLen : "  totalLen=unknown") +
            (g.decodedPacket != null ? "  decodedPacket=" + g.decodedPacket : "") +
            (g.duplicateBytes ? "  duplicateBytes=" + g.duplicateBytes : ""),
        );
        (g.reasons || []).forEach(function (r) {
          lines.push("  reason: " + r);
        });
        (g.holes || []).forEach(function (h) {
          lines.push(
            "  HOLE " +
              h.start +
              ".." +
              h.end +
              " (" +
              (h.end - h.start) +
              " bytes missing, NOT reconstructed)",
          );
        });
        (g.conflicts || []).forEach(function (cf) {
          var parts = Object.keys(cf.byPkt).map(function (pi) {
            return (
              "pkt" + pi + "=0x" + cf.byPkt[pi].toString(16).padStart(2, "0")
            );
          });
          lines.push("  CONFLICT offset " + cf.pos + ": " + parts.join(", "));
        });
        (g.segments || []).forEach(function (s) {
          lines.push("  segment " + s.start + ".." + s.end + " <- pkt" + s.pktIndex);
        });
      });
      lines.push("");
    }

    lines.push("=== Packets ===");
    lines.push(
      [
        "idx",
        "time",
        "src->dst",
        "flags",
        "seq(rel)",
        "ack",
        "cap/decl",
        "marks",
        "discard",
      ].join("\t"),
    );
    result.packets.forEach(function (p) {
      var marks = [];
      if (p.isRetrans) marks.push("retrans");
      if (p.outOfOrder) marks.push("ooo");
      if (p.conflictBytes) marks.push("conflict:" + p.conflictBytes);
      if (p.payloadTruncated) marks.push("payload-trunc");
      lines.push(
        [
          p.index,
          p.tsText,
          (p.srcIp || "?") +
            "." +
            (p.srcPort ?? "?") +
            "->" +
            (p.dstIp || "?") +
            "." +
            (p.dstPort ?? "?"),
          p.flagText,
          p.relSeq ?? "-",
          p.ack ?? "-",
          p.payloadCapturedLen + "/" + p.payloadDeclaredLen,
          marks.join(","),
          p.discardReason || "",
        ].join("\t"),
      );
    });
    return lines.join("\n");
  }

  function conflictSummary(range, origin) {
    return range.entries
      .map(function (e) {
        var parts = Object.keys(e.byPkt).map(function (pi) {
          return "pkt" + pi + "=0x" + e.byPkt[pi].toString(16).padStart(2, "0");
        });
        return "rel" + (e.pos - origin) + ":[" + parts.join(", ") + "]";
      })
      .join(" ");
  }

  return {
    buildTextTokens: buildTextTokens,
    buildHexRows: buildHexRows,
    buildPosMap: buildPosMap,
    conflictHexList: conflictHexList,
    buildExport: buildExport,
    exportJson: exportJson,
    exportText: exportText,
  };
});
