# 特征计算准入与运行预算

Proposal 在进入 Shadow 前，必须通过确定性的计算准入和独立角色提交的性能证据。
Agent 不能自行声明成本、放宽平台上限或提交任意 Python/SQL/图计划作为在线特征。

## 当前实现范围

当前唯一允许的执行器是 `account_history_v1`，对应 featurelib 的账号历史聚合。
仅允许目录中 `source=account_features` 的特征依赖；未知特征、图展开、会话分析等
尚未注册有界执行器的依赖会被拒绝。这个版本没有实现新图特征、物化特征服务或 Flink。
特征依赖仍是声明，不能仅靠登记名称向现有规则添加执行逻辑。

`feature` 组件只能包含 `catalog_version` 和 `compute_contract`。契约完整示例：

```json
{
  "version": 1,
  "operator": "account_history_v1",
  "fallback": "review",
  "max_history_events": 10000,
  "max_account_events": 1000,
  "max_history_bytes": 8388608,
  "max_event_bytes": 16384,
  "max_feature_calls": 2,
  "deadline_ms": 50,
  "max_sql_steps": 200000
}
```

这些是平台硬上限，提案只能收紧。布尔值、负值、浮点限额、未知字段均拒绝。
历史条数限制作用于该次租户历史快照，账号限制作用于过滤时间窗**之前**的账号历史。
超过限制会降级，不会截断后继续把不完整数据当成完整证据。
当前仍使用全租户历史，数据增长到上限后会持续降级；大规模部署应先建设有界索引读取或
物化特征服务，不能直接增大这些常量宣称问题已解决。

## 发布链路

1. `ReleaseController.propose` 自动生成 `compute_admission`，绑定完整 bundle 摘要、
   特征实现文件摘要、契约和工作量代理上界。该上界不是毫秒估计，也不是严格 WCET 证明。
2. `Validated` 在 Shadow 前要求隔离性能验证报告；`Shadow`、`Active` 再次要求相同格式证据。
3. 所有阶段重新核对准入结果和运营方容量配置，防止改完参数复用旧证据。
4. 发布器复查历史证据并把准入记录纳入签名 manifest；运行时核对执行代码和契约。
5. 回滚也检查当前执行代码和容量；不支持在不同执行代码下盲目加载旧策略包。

控制器构造必须传入 `compute_capacity`；CLI 必须传入 `--compute-capacity PATH`。
该文件与凭据一样，由运营方管理，不能接受 Agent 提案覆盖。

容量配置示例（仅示例，不是该项目已达到的容量）：

```json
{
  "target_qps": 1000,
  "cpu_cores": 4,
  "max_utilization": 0.6,
  "max_rss_bytes": 268435456,
  "max_p99_ms": 50
}
```

`proof.evidence.compute_performance` 必须包含：

- `admission_digest`：控制器返回的 compute_admission 的 canonical SHA256；
- `capacity_digest`：上述运营方容量对象的 canonical SHA256；
- `scenarios`：`cold_cache`、`hot_key`、`max_input`、`full_trigger`、`overload`、
  `dependency_failure` 六个场景的测量记录。

每个场景需要 `sample_count`（至少 1000）、`offered_qps`、`completed_qps`、
`cpu_ms_per_request`、`p99_ms`、`peak_rss_bytes`、`timeout_rate`、`degraded_rate`、
`bounded_resources=true`、`fallback_verified=true`。CPU 是完整请求的 CPU 时间，
RSS 是整个受测进程的峰值，完成量包括成功返回的明确降级响应。过载场景输入至少为
两倍目标 QPS；正常场景不允许靠降级达到吞吐要求。超时必须为零；显式快速降级不算超时。
P99 必须在契约与容量阈值以内，CPU×目标 QPS 不得超过可用核数×利用率预算。

报告使用现有 `evidence_digest`、bundle 摘要、scope、expiry、角色鉴权链路。
部署必须把 validator/shadow_runner 凭据交给独立的真实压测程序；摘要并不能证明压测实际
发生过。本改动没有伪造生产测量、自动授予 Agent 验证权限，也没有内置生产压测平台。

## 运行时限制

- 特征执行使用单进程 16 个非阻塞并发槽位；满时立即降级，不在此处排队。
- 历史读取有行数、总序列化字节数、单事件字节数限制。JSON 文件先有界读再解析。
- SQLite SELECT 在 VM progress handler 中检查步骤预算和剩余 deadline，取消后清除 handler。
  在线库增加租户/应用/事件顺序索引，避免历史排序；超大 body 在传到 Python 前被拒绝。
  升级时先离线调用 online_store.connect() 建索引，避免大库首次请求承担索引迁移成本。
- 有预算的请求不复用无预算环境构建的账号索引，避免热缓存绕过更严格限制。
- 账号聚合检查调用次数与输入条数；请求退出再次检查 deadline。嵌套调用共享并收紧预算。
- 超限返回 `action=review`、`degraded=true`、`FEATURE_COMPUTE_BUDGET_EXCEEDED`。
  不把缺失值替换为零，不回源重算。读取失败时 `feature_snapshot_id=null`。
- 回测遇到这种降级会拒绝出具成功指标，不缓存为候选策略收益。远程 batch 保留批量调用。

deadline 是内置有界计算的协作检查，不是任意 Python 的抢占式终止。线程并发限制不是
跨进程/跨机器配额；序列化字节上限不是 Python 对象 RSS 上限。数据库写锁等待、写事务、
其他模型/名单服务、任务积压及人工审核容量仍需部署层限流、隔离和监控。HTTP 剩余时间
会传给客户端 socket timeout，但这不等于远端执行已取消，也不是整个 HTTP 流的硬截止。
发布前的压力验证与运行时限制须同时存在，不能据此承诺整个风控服务永不超时。

## 兼容与迁移

缺少 compute_contract / compute_admission 的旧生产包会 fail closed；上线执行代码前，
必须协调重新准入、真实性能验证、发布及已验证回滚包，不能先替换代码再等旧包自动通过。
publisher 对历史 activation 保留其已绑定的代码摘要，只要求当前 active 与当前执行代码匹配；
没有本版本准入记录的旧 journal 需迁移到新的受控发布目录，保留旧目录供旧执行版本回滚，
不能补写或篡改旧审批记录。
开发环境无签名包时采用平台默认契约；旧策略依赖也会在 validate/promote/replay/active
重新检查。`strategy_register` 可提供完整 compute_contract，缺省使用平台上限。
旧 threshold-only 工具沿用固定内置特征实现；影子回放仍受运行预算限制。生产审批仍只能
由独立控制器执行。

## 本次验证

临时验证脚本检查 39 项，包括无界/未知特征拒绝、类型与范围校验、角色校验、容量超限、
完整状态迁移、签名发布/读取、代码/契约/容量摘要绑定、历史条数和字节数限制、SQL 中断、
热缓存绕过、回测拒绝降级收益、远程批量调用、降级事务提交与重复请求幂等。
未向仓库加入测试文件；发布协议验证使用合成指标，不代表真实生产压测通过。

共享开发环境两轮各 1000 次本地样本调用，分别出现 1 次和 3 次 50ms deadline 降级，
均明确返回 review；第二轮 P99 约 25.15ms、最大约 71.17ms。正常样本 Shadow 回归通过。
这也验证了协作式检查不能保证抢占调度：实际返回时间可能超过 deadline。
这些观测不足以通过要求正常场景零降级的生产容量门禁，应在部署资源上重新压测。
