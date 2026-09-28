# SDK 信号接入调查 RAG

本轮固定基线：Agent `85d0abc4fbdd53ecdf945945a7b8db1ff3668b54`；SDK
`5a401c95bcd257406da9745d717766e90ac9cd4d`。

协议来源是 SDK 的
[`RiskReport.swift`](https://github.com/1494389516/cloudphone-risk-detector/blob/5a401c95bcd257406da9745d717766e90ac9cd4d/RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/RiskReport.swift)
中 `Payload`、`RiskSignal`、`RiskSignalState` 的 Codable CodingKeys。
这次验证是 Python 合成线格式与运行时集成测试，未执行 Swift 编码器或真机测试。

## 数据路径

Collector 先验证原始载荷的 MAC、绑定、时间和重放，再用服务端配置的映射还原字段。
`agent/sdk_signal_evidence.py` 只解析恢复后的 compact keys，不猜字段别名：

| Wire key | 解释 | 调查投影 |
|---|---|---|
| `sv` | 签名载荷内 SDK 版本 | `sdk_version`（三段数字格式） |
| `sg` | 信号数组 | `signals`，最多前 32 条 |
| `i` | 信号 ID | `signal_id` |
| `s` | 客户端信号分数 | `client_score`，不是欺诈概率 |
| `st.t` | 状态类别 | hard / soft / serverRequired / unavailable / tampered |
| `st.d` | hard 状态检测值 | 严格布尔，保留 false |
| `st.c` | soft 状态置信度 | 有限数值，范围 [0,1] |

`st` 缺失或 null 保留为 `unspecified`，不会从分数推断状态。未知状态、类型错误或
非有限数值不能生成该项信号引用。分数绝对值限制为 1e6 是解码合理性预算，不是风控阈值。
每条有效信号保留原数组下标，引用形如 `sdk:<evidence_id>:signal:<index>`。
引用指向保存了原始签名载荷和摘要的 evidence 行；证据图节点保留 `client_reported` 信任标签。

投影和原始报告在同一事务中保存，索引重建不重解释历史载荷；幂等重放不升级旧投影。
改变 decoder 或字段映射后，旧记录仍保留当时投影。旧记录没有投影时返回
`legacy_unavailable`，本轮不做静默回填。

## 缺口和信任语义

- `available` 只表示数组已完整投影，不代表检测真实有效。
- `empty`、`missing`、`invalid`、`partial`、`legacy_unavailable` 都不能证明设备安全。
- `invalid_count` 统计前 32 条内被拒绝的记录；`omitted_count` 单独统计超预算未读取的记录。
- MAC 验证只证明配置安装密钥的来源。`client_score` 和状态仍是客户端陈述。
- `ev`、摘要、客户端聚合结论、自由文本不进入投影；原字节仅留在原始证据存储。
- LLM 只看到四个已有公开知识资料覆盖的信号名称：sensor_replay_detected、
  emulator_behavior、app_team_identifier_mismatch、app_identifier_bundle_mismatch。
  其他 ID 保留本地原值，出站转换为不透明 token；新增公开名称需要审查代码中的静态白名单。
- 继承现有租户/app、绑定事件和 recorded-time PIT 过滤，模型无权直接读取原始载荷。
- 本轮不把信号投影接入规则评分，不改变 Decision Plane 的判定结果或阈值。

## 验证

```bash
python -m eval.rag_sdk_evidence_regressions
```

覆盖签名上报、递归字段映射、各状态、畸形/缺失/空数组、数量预算、跨租户、未来证据、
旧记录、隐私投影、逐信号引用，以及 scripted generator 驱动的调查 worker：
Collector → evidence → 知识检索 → 结构化报告审计 → 持久化证据图 → 已完成任务读取。

测试生成器是显式模拟，不调用真实 LLM；通过表示接口闭环成立，不表示真实模型理解准确、
误杀下降或原生检测有效。下一步用复核案件与真实生成器评估检索和结论质量。
