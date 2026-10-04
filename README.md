# 浏览器本地 PCAP 重组器（限定版）

纯前端、**文件不上传**：选择/拖入后，浏览器在 Web Worker 中完成解析与 TCP 流重组，
结果在解析完成时**冻结**，页面查看与导出始终引用这一份冻结结果。

## 限定范围

| 项 | 支持 / 拒绝 |
| --- | --- |
| 文件大小 | ≤ **8 MB**，超过整份拒绝（读取前即拦截） |
| 包数量 | ≤ **2000** 个，超过整份拒绝 |
| 文件格式 | 小端经典 PCAP（magic `0xa1b2c3d4` 微秒 / `0xa1b23c4d` 纳秒）。大端、pcapng 整份拒绝 |
| 链路层 | 仅以太网（LINKTYPE_ETHERNET=1），其他链路类型整份拒绝 |
| 网络层 | 仅 IPv4（非 IPv4 / 非 TCP / 分片只丢该包并注明原因） |
| 传输层 | 仅 TCP |

## 重组语义（关键安全约束）

- 按**双向四元组 + 方向 + TCP 序号**重组，绝不按抓包到达顺序拼接；
- **相同字节的重传 → 去重**；
- 重叠位置**字节不一致 → 冲突**：保留每个候选字节及其来源包号，不选边覆盖；
- **缺失区间显式留空**（internal / leading / trailing gap），绝不用 0、后续包或想象内容填充；
- 32 位序号**回绕**：以已观测区间为参考做有符号差换算；
- snaplen / 抓包截断的段：只落入实际抓到的前缀，声明而缺失的尾部仍为缺口；
- 文本视图在缺口/冲突边界重置 UTF-8 解码器，缺口两侧字节不会拼成伪造字符。

## 错误处理

- 全局头错误（魔数、链路类型、长度）→ **整份拒绝**；
- 记录头/帧体在文件层被截断 → 保留**位置证据**（包序号、文件偏移、残存字节 hex），
  并**停止该文件后续解析**（截断点后无法可靠定位记录，继续读等于猜测）；
- IP/TCP 层畸形 → 只丢弃该包（`discardReason`），不影响后续包。

## Worker 生命周期

每次导入换新 token 并 `terminate()` 旧 Worker；旧 Worker 的迟到回发经 token 校验丢弃，
**重新导入或取消后，旧结果不可能替换当前文件**。取消时保留上一份冻结结果。

## 运行

```bash
# 需经 HTTP 提供（file:// 下 Worker 可能被浏览器策略阻止）
python3 -m http.server 8000
# 浏览器打开 http://localhost:8000/index.html
```

生成一份含乱序/重传/缺口/冲突的演示样本：

```bash
node tests/make-sample.js     # 写出 sample-disorder.pcap
```

## 测试（对拍）

```bash
node --test tests/
```

- `tests/pcap-builder.js` 手工拼 PCAP 字节的夹具（独立于生产代码）；
- `tests/reference.js` 独立参考重组器（绝对位置 Map，逐字节裁定）；
- `pcap.test.js` 覆盖文件头拒绝、截断停止、乱序、回绕、重传去重、冲突留证、
  缺口（含无 FIN 不判首尾缺口）、snaplen 截断、双向多连接、2000 上限、
  跨缺口桥接回归、tokenBox，以及 **300 轮随机对拍**（覆盖区间/缺口/冲突/逐字节）。

## 导出

- **JSON（无损）**：每个 data chunk 的 base64 原始字节、来源包、缺口、冲突候选字节、
  包表、截断证据；
- **TXT（有损）**：重组文本（非法 UTF-8 显示为 �），缺口/冲突显式标注 + 包表。

## IPv4 fragment evidence
IPv4 TCP fragments are assembled before TCP stream analysis. Datagram identity comprises source address, destination address, protocol and IP ID. Exact duplicate fragment bytes do not add TCP bytes; gaps and contradictory overlaps remain explicit evidence and cannot become readable stream content. A complete datagram must include its first fragment, one consistent final length and every declared byte. `fragmentGroups` and packet `fragmentIndexes` are included in the frozen export, including incomplete/conflicting groups. Ordinary nonfragmented parsing is unchanged.
