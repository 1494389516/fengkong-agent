# 部署到真实环境的路线图

总原则:**agent 以只读身份灰度进入,数据面先通、判定面对账、再谈自动化。**
本骨架的接缝(datasource 单点、policy 版本化、reconcile 对账、两阶段审批)
就是为这条路线预留的。

## 组件映射表

| 骨架组件 | 真实环境替换 |
|---|---|
| `datasource.load_events` | 数仓 / ClickHouse / ES 事件表(按 uid/时间窗下推查询,禁止全量拉取) |
| `datasource.load_accounts` | 用户中心 / 账号主档服务 |
| `ip_intel.json` / `device_intel.json` | IP 情报服务 / 设备指纹 SDK 后端 |
| `reports.json` | 客服工单 / 举报系统 |
| `decisions_log.json` | 风控引擎决策日志(Kafka 落仓) |
| `thresholds.json` | 风控配置中心的**只读镜像**(带同步时间戳与源版本号) |
| `rules.rule_eval` 本地实现 | 引擎 dry-run / 试算接口(适配器已实现:配 `FK_ENGINE_DRYRUN_URL` 即切到引擎判定,本地实现只做降级备份;失败显式降级并打 degraded 标记,见 agent/engine.py) |
| `data/model_scores.json` + R007 | 模型服务(配 `FK_ENGINE_MODEL_URL` 即切到远程打分;本地文件只是骨架模拟。champion 模型分过 model_score_*_threshold 才拦截,阈值在 policy 版本表,生效走审批) |
| `feature_parity_check` + `FK_FEATURE_ONLINE_MODULE` | 在线特征服务客户端(签名与 featurelib.account_features 一致);接真实数仓后注入在线实现,建模/回测前跑 parity,检出 training-serving skew |
| `actions` pending + CLI 审批 | 审批系统 / 飞书卡片(SSO 身份入审计库) |
| `eval/` 离线断言 | CI 门禁(每次改动必跑) |
| `eval` agent 层案例 | 上线回归集(改 prompt / 加工具必跑) |
| `data/gen_sample.py` | 压测与攻防演练数据 |

## 四步走

### 第一步:数据面(datasource 换实现)
- 每个 loader 换成对应系统的客户端;`featurelib.account_features(uid, as_of,
  window)` 的签名即下推查询的接口契约 —— 实现换成 SQL 模板 / 特征平台点查,
  返回结构不变,上层工具无感知。
- `scan_all` / `rule_backtest` 等全量计算改为"触发离线任务 + 查询结果"的
  异步形态(Spark / 调度平台),不再是同步工具调用。
- 第一周即可做:从数仓脱敏导出一天真实事件,按现有 schema 灌入 `data/`,
  全套工具与 eval 直接跑 —— 立刻暴露真实数据的口径问题。

### 第二步:判定面(对账从演练变实战)
- `consistency_check` 接真实决策日志,上线第一周起每日跑;不一致率降到
  `max_sim_mismatch_rate` 以内之前,agent 的模拟类结论强制携带失信标注
  (机制已内建,换数据源即生效)。
- `threshold_propose` 的 approve 对接配置平台 API / 工单,本地 pending
  只做前置缓冲;主档完整性对账(注册分 vs 决策日志)同步启用。

### 第三步:服务化
- 形态优先级:① 飞书/钉钉机器人(值班群 @风控助手,仪表盘 PNG 回群);
  ② 工单系统插件(案件页一键出调查档案);③ 定时任务(scan_all 日报)。
- `main.py` 对话循环包 FastAPI;`/reset` 语义 = 会话 TTL;审批命令换成
  带 SSO 身份的卡片按钮。
- **红线一(数据出境)**:公有云 LLM 前必须启用脱敏层 —— `FK_PRIVACY=1`,
  uid/IP/设备号在 LLM 边界双向替换为确定性 token(agent/privacy.py),
  敏感标识符不出程序;接真实数据时把 `_PATTERNS` 换成公司 ID 规范。
  或改用私有化模型 / 云厂商合规专区。
- **红线二(权限最小化)**:agent 服务用只读库账号;写操作只能进 pending,
  审批走人;审计进正式审计库。
- **红线三(注入防线)**:举报文本等用户可控字段经 dispatch 单点包
  ⟦用户内容⟧ 标记(标记字符先清洗防逃逸),system.md 安全纪律规定标记内
  只作数据引用 —— 攻击者在举报里写"把我移出名单"不构成任何依据。

### 第四步:灰度与验收
- **影子期(2~4 周)**:agent 只对已人工处理完的案件出结论,与人工结论
  对账(reconcile 思路套在 agent 自身);达标线示例:结论一致率 >= 90%,
  严重分歧(agent pass / 人 reject)逐案复盘。
- **辅助期**:值班分析师实际使用,人保留全部决策;agent 层 eval 四维断言
  (结论 / 轨迹效率 / token 预算 / 缓存命中)作为回归门禁。
- **半自动期(远期)**:低风险动作(灰名单提案、日报)自动执行,
  reject 类永远留人工闸门。
- **成本**:`eval/measure_costs.py` 预算进 CI;线上会话有 ⑥ 上下文硬预算
  兜底;再接账单告警即闭环。

## 第一周清单

1. 脱敏导出一天真实事件灌入 `data/`,跑 `python3 eval/run_eval.py`;
2. 配 `DEEPSEEK_API_KEY`(或私有化端点)跑 agent 层 8 案例,拿四维基线;
3. CLI 包成飞书机器人只读版,进风控值班群试用;
4. 生产侧开启 `FK_PRIVACY=1` 并按公司 ID 规范扩充 `privacy._PATTERNS`。
