# SDK 检测载荷接入与验收边界

本轮基于 Agent main `26dfaa7cad851fcf5f7463bc96a9856a684fa83a`（PR #24 合并），
逐文件校验本地基线与远端树一致。SDK 源码固定为
`c481b109df31f950cb07c11297dd7f92756cd972`，其 `Version.current` 为 `7.3.0`。
版本字符串是客户端声明，不是构建真实性证明。

## 优先补这个缺口的原因

原 Collector 验证并保存原始载荷，但只识别通用 `hardware_attributes`，
字段恢复只在顶层进行；SDK 实际使用短字段与可选递归混淆。
因此调查工具拿不到具体检测状态，检索到检测文档也无法可靠关联本次观测。
本轮先打通可确定验证的“验签→解码→本地证据→冻结任务→模型安全投影”。

## 两端字段对照

源文件均位于上述 SDK 提交的 `RiskDetectorApp/Sources/CloudPhoneRiskKit/`。

| SDK 源码/字段 | Wire | 本轮处理 |
| --- | --- | --- |
| `Risk/RiskReport.swift` Payload.sdkVersion/reportId | `sv/ri` | 与已验签载荷绑定；ri 与 envelope.report_id 必须一致，sv 与上传元数据一致 |
| Payload.timestamp | `ts`（秒） | `client_timestamp`；与 envelope.ts 的毫秒单位区分，不宣称是独立可信时间 |
| Payload.signals | `sg` | 最多256项，重复ID或任一非法项导致整组不可用于检测分析 |
| RiskSignal.id/category/score/evidence | `i/ca/s/ev` | 本地保存 signal_id/category/client_score/evidence |
| RiskSignal.state/layer | `st/l` | 保留类型化状态与层号；不存在的状态为 unknown |
| RiskSignalState.type/detected/confidence | `t/d/c` | hard 布尔、soft 置信度，以及 serverRequired/unavailable/tampered |
| Payload.score/isHighRisk | `sc/hr` | client_score/client_is_high_risk；仅是客户端结论 |
| `Device/DeviceFingerprint.swift` | `dv.m/sv/sw/sh` | model/os_version/screen_width/screen_height；不使用 IDFV 作身份 |
| Payload.server | `sr` | 不进入服务端聚合、特征或最终标签 |
| `Risk/PayloadFieldObfuscator.swift` | `v/m/ds/ea` | 服务端配置驱动恢复；支持 topLevel/all、有效期、冲突拒绝 |

当前只解释已核对的 `7.3.0` 子集，不是完整 Payload 的反序列化器。
不解释压缩信号摘要、挑战探针、文本段哈希或所有设备/行为字段。
新增字段留在原始证据中，不自动变成服务端特征。

## 配置混淆映射

认证记录 `field_mappings` 可直接存 SDK 格式配置。SDK 的 m 方向是
“输入 JSON 字段名→混淆字段名”；这里的输入字段是 Codable 编码后的短字段，
不是 Swift 属性名称。例如：

```json
{
  "field_mappings": {
    "nested-1": {
      "v": "nested-1",
      "m": {"sg": "wire_signals", "i": "wire_id", "st": "wire_state", "t": "wire_type"},
      "ds": "all",
      "ea": 1893456000000
    }
  }
}
```

省略 ds 与 SDK 一致，采用 topLevel。旧 Collector 平面配置仍然支持，
其方向为“wire→恢复字段”，只处理顶层。重复目标、实际载荷键碰撞、未知版本、
过期配置都拒绝入库。有效期按已签名 envelope.ts 检查，同时保留300秒新鲜度检查。
入库保存 decoder_version、field_mapping_version 和配置摘要，不保存额外映射密钥。
配置不得从上传载荷读取，也不能让 Agent 选择。

会话派生映射只有在运维已提供对应的最终映射表时才能恢复。
本轮没有推导会话密钥，也不复用 HMAC base key 猜测映射密钥。

## 状态、存储与模型边界

- envelope MAC、会话、作用域、重放以及服务端要求的 App Attest 校验通过后才解码。
- 原始 envelope/payload 字节和原有摘要继续保留；解码不参与重签名，不改变验签输入。
- 不支持的版本/格式、元数据冲突、缺失/非法信号：保留收到的来源证据，
  `sdk_detection.status` 明确失败，`signal_count=null`，不给出部分成功或“未命中”。
- `decoded` 只表示本轮字段投影成功。合法 `sg=[]` 是客户端提交的空列表，
  不是所有检测完成或设备安全的证明。
- 同一上报的幂等重放返回原回执，配置轮换后也不重新解释旧证据。
- 新任务冻结最多10个已关联 SDK 观测和缺失引用；其内容参与 snapshot_id。
  后续配置/数据库变化不改变这次任务的 SDK 事实。旧任务保持原查询路径。
- 旧 observation 没有 sdk_detection 时，模型投影视为 legacy_not_decoded，
  本轮不回填历史记录。重新上报用于新事件，不用新解码器改写历史调查。
- 模型只看到有限的状态、数值和已核对公开信号名；原始 ev、category、summary、
  客户端账号和本地路径不经新通道出站。未知信号名转为不透明token并标记 signal_id_known=false。
  当前公开信号名只有 sensor_replay_detected、emulator_behavior、
  app_team_identifier_mismatch、app_identifier_bundle_mismatch；新增名称需审核词表。
- 每份报告模型最多看到20个信号，另有 signal_count/omitted_signal_count。
  原始本地证据保留完整的已接受信号列表。实时规则、评分与处置没有新增客户端输入。

## 必须保留的上线阻塞项

1. **SDK 高层安全上报默认 armor 与 Collector 尚未贯通。**
   `Core/CPRiskKitReporting.swift` 默认 requireArmor=true，活动状态使用 v2a；
   非强制回退使用 v2d。Collector 仍只允许 v2/v2h/v3。
   不能把本轮称作默认生产 SDK 的端到端验收，更不能通过放开 v2a 白名单绕过运行时密钥授权。
2. `CPRiskReport.securePayload()` 的 Keychain AES-GCM 本地密文不是此 HTTP JSON 合同的 payload_json；
   安全 envelope 构造路径用 unencryptedPayloadData 后做混淆与签名。
   本轮不解密 Keychain 密文，非 JSON 仍由原契约拒绝。
3. 尚无当前 Swift 编码器实跑产物、真机采集包或真实 Apple 证明链联调。
   fixture 是源码对齐的合成数据，不是假称真机样本。
4. 真实 LLM/embedding 质量、误杀收益以及“引用语义支持结论”仍未验证。

## 可复现检查

```bash
python -m pip install -r requirements.txt pytest pytest-subtests
python -m pytest -q tests/test_sdk_payload.py
python -m pytest -q
python -m eval.rag_eval
git diff --check
```

`tests/fixtures/sdk_payload/provenance.json` 保存固定提交、源码文件 SHA256 和提取的 CodingKeys。
compact/nested 是人工构造、相互独立的协议样例；上游 report_vectors 原样保存20组签名向量。
测试验证上游签名输入逐字节兼容、嵌套映射、非法状态、空/缺失差异、版本边界、
MAC先于解码、幂等、跨租户权限、脱敏、截断和冻结调查链路。
对 v2a/v2d 的参考验签向量测试不代表 Collector 允许这些版本。
