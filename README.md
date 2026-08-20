# 电商风控分析 Agent

基于 DeepSeek Function Calling 的电商风控分析工具，用于账号调查、团伙分析、规则回测和策略调参。

系统分为两个相互隔离的部分：

- **Agent Plane**：负责取证、分析、回测和生成变更提案；
- **Decision Plane**：负责在线判定，是决策结果的唯一来源。

涉及名单、阈值等状态的修改必须提交审批，Agent 不能直接使变更生效。仓库使用合成数据，适合本地研究、功能验证和二次开发，不应直接作为生产系统部署。

## 主要功能

- 账号、设备、IP 和关联团伙调查；
- 时间切分候选规则挖掘、成本约束 OR 搜索、规则试穿与阈值校准；
- 特征 IV、KS、AUC、Lift 和 PSI 评估；
- 特征漂移、规则漂移和对抗行为监控；
- 黑、灰、白名单及申诉处理；
- 模型、策略、特征和标签版本管理；
- 决策血缘、生产日志对账和事故跟踪；
- 写操作两阶段审批和全程审计；
- 离线回归测试、Agent 黄金案例和成本预算。

## 快速开始

安装依赖：

```bash
pip install -r requirements.txt
```

启动交互式 CLI：

```bash
export DEEPSEEK_API_KEY=sk-...
python3 main.py
```

常用 CLI 命令：

```text
/reset                  开始新案例
/pack                   切换工具包
/pending                查看待审批项
/approve <id>           批准提案
/deny <id>              拒绝提案
exit                    退出
```

运行离线评估：

```bash
python3 eval/run_eval.py
```

生成较大规模的合成数据并运行：

```bash
python3 data/gen_sample.py
FK_DATASET=gen python3 main.py
```

执行接数检查、回测、对账和门禁：

```bash
python3 eval/day1.py
```

启动决策服务：

```bash
python3 serve.py --port 8080
```

服务提供以下接口：

- `POST /decide`：执行风险判定；
- `GET /health`：查看服务及生产就绪状态；
- `GET /brief`：获取值班摘要。

## 架构

系统按"唯一事实源 + 镜像"切开：Decision Plane 是判定的唯一事实源，Agent Plane 只是它的镜像，而镜像必须对账。下图按数据流自上而下排列——数据与特征在最上，Agent 取证分析居中，审批与策略资产夹在中间，在线判定在下，留痕与对账收尾。Agent 的提案必须穿过人工审批和策略资产才可能影响判定，这段纵深就是隔离本身。

```mermaid
flowchart TB
    RES["风控研究员"]
    BIZ["业务流量<br/>前置网关负责鉴权与限流"]
    SRC["datasource 业务数据源"]
    FEAT["featurelib 统一特征层"]

    subgraph AP["Agent Plane · 取证与分析（镜像，无判定权）"]
        direction TB
        CLI["main.py 交互式 CLI"]
        LOOP["core.Agent 主循环<br/>工具包裁剪 · 上下文预算"]
        LLM["DeepSeek<br/>只做编排与解释"]
        CAP["capability.py 权限闸<br/>read · simulate · propose · execute"]
        T_READ["取证工具<br/>档案 · 关联图 · 设备与 IP 情报"]
        T_SIM["分析工具<br/>回测 · 校准 · 漂移 · 影子策略"]
        T_PROP["提案工具<br/>名单 · 阈值 · 模型与策略晋升"]
    end

    QUEUE["actions 待审批队列"]
    HUMAN["人工审批 /approve · /deny<br/>不注册为工具"]
    ASSET["策略资产<br/>policy 阈值版本 · active 策略 · champion 模型"]

    subgraph DP["Decision Plane · 在线判定（唯一事实源）"]
        direction TB
        SERVE["serve.py POST /decide"]
        IDEMP["idemp_store 幂等表<br/>指纹去重，重放不写血缘"]
        ENTRY["engine.evaluate_event<br/>判定唯一入口"]
        REMOTE["生产引擎 dry-run<br/>FK_ENGINE_DRYRUN_URL"]
        LOCAL["local_rules R001-R006<br/>骨架替身兼降级备份"]
        R007["R007 champion 模型信号<br/>FK_ENGINE_MODEL_URL 或本地分数表"]
        VERDICT["处置 pass · review · reject<br/>reason_codes · degraded"]
    end

    AUDIT["audit · lineage 审计与决策血缘"]
    DLOG["生产决策日志<br/>serve_decisions.jsonl · decisions_log.json"]
    RECON["reconcile 镜像对账<br/>本地模拟 vs 生产决策日志"]
    DISTRUST["失信标记<br/>不一致超阈值则回测与校准结论<br/>不得作为变更依据"]

    RES --> CLI
    RES -->|人类专用通道| HUMAN
    SRC --> FEAT
    SRC --> T_READ
    FEAT --> T_READ
    FEAT --> T_SIM
    FEAT --> LOCAL

    CLI --> LOOP
    LOOP -->|脱敏后出网| LLM
    LLM -->|tool_calls| CAP
    CAP --> T_READ
    CAP --> T_SIM
    CAP --> T_PROP
    CAP -.->|越权调用审批类能力即拒绝并留痕| AUDIT

    T_PROP --> QUEUE
    QUEUE --> HUMAN
    HUMAN -->|批准后才生效| ASSET
    HUMAN --> AUDIT
    ASSET --> ENTRY
    T_SIM -->|同一判定入口| ENTRY

    BIZ --> SERVE
    SERVE --> IDEMP
    IDEMP --> ENTRY
    ENTRY -->|优先| REMOTE
    REMOTE -.->|失败超时或熔断，显式打 degraded| LOCAL
    ENTRY -.->|未配置远程或 what-if 覆盖生效| LOCAL
    LOCAL --> R007
    REMOTE --> VERDICT
    LOCAL --> VERDICT
    R007 --> VERDICT

    VERDICT --> AUDIT
    VERDICT --> DLOG
    DLOG --> RECON
    RECON -.->|机器强制，非提示词约束| DISTRUST
```

图上三条边界是代码约束，不只是文档约定：

- **LLM 不在判定路径上**：`serve.py` 到 `engine.evaluate_event` 的整条判定链不引用任何 LLM，`agent/engine.py` 里没有一处模型客户端；DeepSeek 只在 Agent Plane 负责编排工具与解释结论。
- **Agent 的写操作只能生成提案**：`capability.py` 在 dispatch 单点按 `read`、`simulate`、`propose`、`execute` 查等级，`approve` 与 `admin` 不注册为工具，模型根本没有可调用的审批入口，越权尝试会被拒绝并写入安全审计。
- **降级必须显式**：远程引擎失败或熔断时回退 `local_rules`，同时打 `degraded` 标记。静默降级会让对账退化成"本地对本地"，口径漂移就此隐身。

判定路径每次调用重新解析，优先级依次是：what-if 覆盖生效时永远走本地，因为假想阈值不该拿去对账；配置了 `FK_ENGINE_DRYRUN_URL` 时远程 dry-run 优先，调用失败则降级并标记；两者都不成立时使用本地 `local_rules`。

对账方向容易记反：`reconcile` 不是用生产日志校准 agent，而是拿 agent 的本地模拟去比生产日志。不一致率超过 `max_sim_mismatch_rate` 时，`rule_backtest`、`shadow_backtest` 和 `threshold_calibrate` 的返回会自动附上失信标记——模拟器失准时，用它算出的指标不能作为变更依据。

生产接入方式见 [DEPLOY.md](DEPLOY.md)。

## 核心模块

```text
agent/
  core.py             对话与工具调用主循环
  llm.py              DeepSeek 客户端
  privacy.py          敏感标识符脱敏
  prompts/            Agent 提示词
  tools/
    datasource.py     数据源适配层
    featurelib.py     统一特征计算
    rules.py          风控规则
    backtest.py       规则回测
    calibrate.py      阈值校准
    profile.py        账号调查档案
    graph.py          账号、设备和 IP 关联图
    drift.py          特征与规则漂移监控
    adversary.py      对抗行为监控
    risk.py           特征风险评估
    feedback.py       申诉与反馈处理
    capability.py     工具权限控制
data/                 样本数据和数据生成器
eval/                 离线评估与黄金案例
serve.py              在线决策服务
DEPLOY.md              部署与生产接入说明
```

## 决策规则

内置规则覆盖以下场景：

- 名单命中；
- 高频领券和 IP 轮换；
- 大额订单及领券后小额下单；
- 新账号高额交易；
- 高风险注册账号；
- 模拟器、Root 和 Hook 环境；
- 已审批上线的模型风险信号。

规则阈值通过策略版本解析，不直接写死在业务流程中。名单和阈值变更需要先生成提案，再由人工审批。

## 数据与评估

`data/` 中的手工样本包含正常账号、刷券脚本、套现团伙和盗号等案例。`data/gen_sample.py` 可生成约 250 个账号的可复现数据集，用于回测和压力测试。

离线评估不调用 LLM，覆盖规则、特征、漂移监控、审批流程、版本管理、对账、安全边界和成本预算。需要 API Key 时，还可以运行 Agent 黄金案例，检查分析结论、取证路径、工具调用效率和 token 消耗。

<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-START -->
## 系统快照(自动生成,勿手改;`python3 eval/run_eval.py --report` 刷新)

| 项 | 值 |
|---|---|
| git commit | `dfc2dde` |
| 工具数 | 86 |
| 工具 schema | 39384 chars |
| system prompt | 5636 chars |
| 数据指纹 | `028ccc9fef784b6b` |
| 离线断言数 | 490 |
| agent 黄金案例 | 24 |
| 最近刷新(UTC) | 2026-08-20T10:10:27Z |

<!-- AUTO-SYNC:FK-DOC-SNAPSHOT-END -->

## 环境变量

| 变量 | 作用 |
|---|---|
| `DEEPSEEK_API_KEY` | 调用 DeepSeek；离线评估不需要 |
| `FK_DATASET=gen` | 使用生成数据集 |
| `FK_DATA_DIR=/path` | 指定数据目录，优先级高于 `FK_DATASET` |
| `FK_PRIVACY=1` | 启用敏感标识符脱敏 |
| `FK_OPERATOR` | 设置审批人标识 |
| `FK_AGENT_RUN_LOG=1` | 记录 Agent 运行指标 |
| `FK_ENGINE_DRYRUN_URL` | 配置外部决策引擎试算接口 |
| `FK_ENGINE_DRYRUN_TIMEOUT` | 设置决策引擎调用超时 |
| `FK_ENGINE_MODEL_URL` | 配置模型评分服务 |
| `FK_FEATURE_ONLINE_MODULE` | 注入在线特征实现 |
| `FK_TOOL_PACK` | 选择工具包，默认 `analyst` |
| `FK_TZ_OFFSET_HOURS` | 设置业务时区偏移，默认 `+8` |

公有云环境建议启用脱敏：

```bash
FK_PRIVACY=1 python3 main.py
```

## 安全边界

- LLM 不参与在线判定；
- Agent 无权执行审批；
- 写操作必须进入待审批队列；
- 工具按 `read`、`simulate`、`propose` 和 `execute` 分级；
- 审批和管理能力不注册为 Agent 工具；
- 敏感标识符可在 LLM 边界进行确定性脱敏；
- 决策、变更和执行操作保留审计记录。

白名单用于降低处置等级，不会跳过全部检查。回测、影子策略和反事实重放不会修改生产状态。

## 当前限制

- 仓库数据为合成数据，评估结果不能直接代表真实业务效果；
- 默认使用本地规则引擎，接入生产引擎后需要持续进行一致性对账；
- 未配置有效的 champion 模型和 active strategy 时，生产就绪检查会返回 `BLOCKED`；
- 部分批量任务目前仍为同步执行，大数据量场景需要接入独立任务系统；
- 在线特征、数仓、身份认证和审批系统需要按实际环境接入。

生产部署、数据源替换和外部系统接入参见 [DEPLOY.md](DEPLOY.md)。
