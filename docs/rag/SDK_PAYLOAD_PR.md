# feat: 接入已验签 SDK 检测载荷与冻结调查证据

## 为什么需要

PR #24 后，调查能检索检测知识，但 Collector 没有解码 SDK 实际使用的短字段和嵌套混淆信号。
缺少本次检测状态时，RAG 文档无法补成事件事实。

## 变更

- 固定 SDK c481b109 的 7.3.0 字段子集；解码信号、显式状态与客户端分数。
- 兼容旧顶层反向表，支持 SDK 格式的 topLevel/all 映射与过期/冲突拒绝。
- 保留原始签名字节、摘要、decoder/mapping provenance；重放不重新解码。
- 新调查任务冻结 SDK 观测；模型看到受控状态和公开信号名，原始自由文本留在本地。
- 未支持版本、缺失/非法信号明确标记未知；不把客户端 sr、分数或标签加入实时决策。

## 验证

- 基线：Agent main 26dfaa7cad851fcf5f7463bc96a9856a684fa83a；本地文件逐一匹配远端 blob。
- `python -m pytest -q`：222 passed，151 subtests passed。
- `python -m pytest -q tests/test_sdk_payload.py`：40 passed。
- 20组上游签名向量逐字节兼容检查纳入上述测试。
- `python -m eval.rag_eval`：30/30 合成检索查询通过。
- `git diff --check`：通过。
- 验证环境：Python 3.12、Linux；使用合成载荷与离线 Agent 替身。

## 仍未验证 / 上线阻塞

- SDK 高层默认 armor v2a，降级 v2d；Collector 仍只允许 v2/v2h/v3。
  需独立补运行时密钥授权，不能将这次解码验收当作默认生产上报已贯通。
- 没有 Swift 实跑编码输出、真机载荷或真实 App Attest 联调；合成数据不代表检测有效性。
- 只支持已核对版本的部分字段；4个已审核信号名可明文进入模型，其余为未知词表项。
- 真实 LLM/embedding 质量、引用语义支持与误杀收益仍未验证。

完整字段对照、部署配置和回退行为见 [SDK_PAYLOAD.md](SDK_PAYLOAD.md)。
