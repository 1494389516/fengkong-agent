# Prepared stacked pull requests

Target repository: `1494389516/fengkong-agent`. The user subsequently authorized direct main delivery. All 12 stages were uploaded to main on 2026-10-04, ending at `5d0ecf0ec1596ee326e8df765e0a609d774ee8a3`; no PRs were opened. The hashes below describe the original local staging history, whose trees match the uploaded commits.

## 01-storage-contract: 部署与状态隔离

- Head: `feat/vnext-01-storage-contract`
- Base: `main`
- Commit: `de62a52`

分离 Agent 状态/审计目录，补控制器容量契约。

验收边界：真实容器权限验收在最终集成阶段补入。

## 02-async-projector: 异步案件投影

- Head: `feat/vnext-02-async-projector`
- Base: `feat/vnext-01-storage-contract`
- Commit: `9fe5bda`

移除 HTTP 同步消费，独立投影进程和状态库。

验收边界：旧库迁移与源替换检测由最终集成阶段补齐。

## 03-case-revisions: 案件修订与证据快照

- Head: `feat/vnext-03-case-revisions`
- Base: `feat/vnext-02-async-projector`
- Commit: `d34c708`

新增不可变修订和局部证据构建，保留旧任务。

验收边界：辅助依赖历史版本不足，不能视为完整历史复现。

## 04-durable-runtime: 持久步骤与 fencing

- Head: `feat/vnext-04-durable-runtime`
- Base: `feat/vnext-03-case-revisions`
- Commit: `a20a708`

模型和工具调用边界落账；已提交步骤可重放；旧 worker 拒绝提交。

验收边界：heartbeat/attempt 记录由最终集成阶段补齐；模糊外部调用不自动重试。

## 05-provider-budget: 统一模型预算

- Head: `feat/vnext-05-provider-budget`
- Base: `feat/vnext-04-durable-runtime`
- Commit: `9ba5076`

verifier/embedding 接入持久预留和实际/估算结算。

验收边界：无真实付费调用与金额账单测试。

## 06-tool-contracts: 工具参数与证据视图

- Head: `feat/vnext-06-tool-contracts`
- Base: `feat/vnext-05-provider-budget`
- Commit: `6be6ebf`

校验请求及有效参数；保全 SDK/RAG 证据；失败审计闭合。

验收边界：保留保守授权；完整字段依赖图与分页尚未实现。

## 07-claim-eligibility: 事件断言与结论资格

- Head: `feat/vnext-07-claim-eligibility`
- Base: `feat/vnext-06-tool-contracts`
- Commit: `556eef3`

确定性校验标量断言；完成状态与可采用性分开。

验收边界：自然语言语义仍须独立复核。

## 08-group-projections: 消费组与图批处理

- Head: `feat/vnext-08-group-projections`
- Base: `feat/vnext-07-claim-eligibility`
- Commit: `035c761`

独立消费回执及 DLQ；dirty-device 复用范围读和基础图。

验收边界：非所有图路径已批处理；无生产性能结论。

## 09-bounded-plan: 受限调查计划

- Head: `feat/vnext-09-bounded-plan`
- Base: `feat/vnext-08-group-projections`
- Commit: `1af175c`

固定 DAG 和角色/工具/实体授权交集，集合步骤持久化。

验收边界：反证沿用有界检索；无独立多专家模型收益验证。

## 10-artifact-chain: 候选策略产物链

- Head: `feat/vnext-10-artifact-chain`
- Base: `feat/vnext-09-bounded-plan`
- Commit: `6cba7fc`

绑定调查结论、人审和既有挖掘评估，贯穿 bundle。

验收边界：哈希只绑定内容，不替代独立审批或自动转换规则。

## 11-review-workbench: 独立人审工作台

- Head: `feat/vnext-11-review-workbench`
- Base: `feat/vnext-10-artifact-chain`
- Commit: `13413ee`

独立 UI/API，修订/摘要绑定、标签来源和成熟时间。

验收边界：未进行浏览器视觉验收；标签训练回灌及仲裁未接线。

## 12-acceptance: 集成与验收边界

- Head: `feat/vnext-12-acceptance`
- Base: `feat/vnext-11-review-workbench`
- Commit: `HEAD`

补迁移、心跳、归档、真实 HTTP 检查和 Docker CI。

验收边界：Docker 本地不可用；业务/真实模型实验待提供数据与授权。

Final validation and exact remaining scope: [IMPLEMENTATION_20261004.md](IMPLEMENTATION_20261004.md).
