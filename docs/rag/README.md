# 风控调查 RAG 第一版

这版把知识检索接入已有异步调查任务，不改变实时决策与审批通道。

## 已实现

- `get_event_evidence(event_id)`：按认证租户/app读取业务事件、已落库决策和关联SDK观测；任务中只能访问绑定事件。
- `search_risk_knowledge(...)`：中文/英文BM25、可选真实embedding、RRF融合，再经过可解释领域rerank；返回内容哈希、来源、适用范围、误报条件和`[K:chunk_id]`。
- 每个数据集独立SQLite索引，沿用现有认证与数据目录路由；模型不能指定索引路径或租户。
- `python -m agent.rag ingest` 是运维入库入口，不注册为Agent写工具。全量替换事务保证删除/撤回生效，失败保留原索引；相同内容复用向量。
- 检索过滤草稿、撤回、模拟资料、未来知识、自身案件复盘以及不适用的版本。版本限定文档在请求版本未知时不返回。
- 新调查任务绑定索引内容指纹和事件时间；检索时间由服务端覆盖，不能由模型向未来移动。
- 调查结果保存引用来源及未检索到的引用ID，并生成`claim_support_audit`：对知识型claim做保守词汇桥接筛查。无词汇桥接会标红；有重合仍只标记需要语义复核，不宣称已验证蕴含或排除矛盾。
- 调查采用有界纠错检索：先读事件事实，再按用途检索；无匹配可改写，最多3次，知识参与结论时检查反证检索。最终报告逐条绑定事件证据和知识引用。详见 [有界纠错检索](AGENTIC_WORKFLOW.md)。

## 快速运行：离线检索

在仓库根目录执行：

```bash
python -m pip install -r requirements.txt
export FK_DATA_DIR=/absolute/path/to/your-dataset
python -m agent.rag ingest knowledge
python -m agent.rag search 'sensor_replay_detected 是真实传感器回放证据吗' --platform ios
python -m eval.rag_eval
```

`ingest`会替换该数据集整个知识索引；目录应包含该数据集全部要保留的知识。撤回资料把`status`改成`withdrawn`后重建。源文件的增删改不会自动刷新运行时索引。

默认没有向量请求，不需要LLM/embedding密钥。索引初始未建或没有匹配时返回`no_match`，不会凭空生成依据。

## 接入现有异步调查

1. 在目标租户的数据目录运行入库，随后再创建新调查任务。
2. 在**服务端认证配置**的调查worker记录中保留`cases.run`权限，并按需向`tools`追加`get_event_evidence`、`search_risk_knowledge`。这些不是模型可授予自己的权限。
3. 照常运行`agent.investigations.run_task(task_id, context)`。worker授权工具与任务快照的allowed_tools取交集。
4. 读取结果中的`investigation_report`、`claim_evidence_audit`、`retrieval_audit`、
   `knowledge_citation_audit`、`claim_entailment_audit`、`knowledge_index_digest`和`budget_used`。`summary`保留模型原始输出供审计。

交互Agent的`investigate`和默认`analyst`工具包也包含新工具。调用`get_event_evidence`需要已有认证租户/app上下文；它不回退到无认证全表查询。

旧任务没有知识指纹，保持原能力，不能凭空增加RAG权限。索引更新后旧快照的知识检索会明确失败，不能静默使用新版本；第一版没有历史索引服务或任务重发接口。处理方式是在处理队列前完成知识发布，运行期间固定索引；需要恢复旧任务时由运维恢复原语料/模型索引。不能修改时间字段来绕过历史边界。

### RAG Scorecard

`python -m eval.rag_scorecard --gate --output out/rag_scorecard.json` 会把评估拆成三层：

- `retriever`：Hit@1/5、MRR@5、负例拒绝率、hard-case section Top-1，以及 PIT 未来知识和跨平台泄漏探针；
- `grounding_evaluator_contract`：用 synthetic good/bad claims 验证未知事件引用、未知知识引用和明显 citation/claim 脱节能被评估器抓到；
- `generator_grounding`：默认不宣称任何 Agent 生成质量。只有显式传入 `--investigations <jsonl>` 时，才统计真实调查结果的报告解析率、引用有效率、结构化 grounding、反证流程完整率、词汇桥接率和 unsupported claim rate。

这套指标借鉴 claim-level RAG 评估的拆分思路，但不是 RAGChecker 的复刻，也没有引入其模型依赖。当前 `semantic_entailment_verified_rate` 应保持为 0，直到独立的 entailment/contradiction evaluator 经标注集验证后接入。

## 可选：独立 Claim-Evidence Entailment Gate

调查生成器不会给自己打分。需要语义蕴含/矛盾判断时，单独配置 evaluator：

```bash
export FK_RAG_ENTAILMENT_ENABLED=1
export FK_RAG_ENTAILMENT_BASE_URL=https://your-evaluator.example/v1
export FK_RAG_ENTAILMENT_MODEL=your-pinned-entailment-model
# 在部署密钥管理中设置 FK_RAG_ENTAILMENT_API_KEY
```

evaluator 只输出 `SUPPORTED / CONTRADICTED / INSUFFICIENT`。配置缺失、调用失败、材料缺失、
矛盾或证据不足全部 fail-closed 为 `grounding_gate=REVIEW`，不会修改 Decision Plane verdict。
即使模型返回 `SUPPORTED`，也只有在该 evaluator 已用人工复核标注集完成校准并显式设置
`FK_RAG_ENTAILMENT_CALIBRATED=1` 后，才允许
`semantic_entailment_verified=true`。

仓库内 `eval/rag/entailment_cases.jsonl` 明确标记为 `simulated=true`，只用于合同/冒烟验证，
不冒充真实攻击或误杀样本。真实验收应把去标识化、人工复核的 attack/false-positive 案例按现有
`attack_case/false_positive_case + case_id + reviewed_at + review_basis` 合同入库，并使用：

```bash
python -m eval.rag_entailment_calibration --cases /path/to/reviewed_entailment.jsonl --gate
```

只有真实复核集达到你设定的门槛后，部署侧才应打开 `FK_RAG_ENTAILMENT_CALIBRATED=1`。

## 可选：真实向量混合检索

只在需要且允许将公开语料与查询发送到配置的embedding服务时开启。可以配置自托管的兼容服务。不会自动复用聊天模型密钥。

```bash
export FK_RAG_EMBED_ENABLED=1
export FK_RAG_EMBED_BASE_URL=https://your-embedding-service.example/v1
export FK_RAG_EMBED_MODEL=your-embedding-model
# 在部署密钥管理中设置 FK_RAG_EMBED_API_KEY，不提交到仓库。
python -m agent.rag ingest knowledge
python -m agent.rag search '合法调试是否会命中断点检测' --platform ios
python -m eval.rag_eval --hybrid
```

先重建索引才能匹配新模型；模型标识包含服务地址和模型名。请求超时15秒、无SDK自动重试。嵌入失败或模型不匹配时显式回退BM25，不把伪随机/hash向量当成语义检索。更换同名模型实际权重后应变更模型版本名并重建。

检索查询应只含检测项与待解释现象，不含用户、设备或网络标识。开启远端embedding意味着查询也会出站，配置方需选择合适的部署边界。

## 可选：本地 Cross-Encoder 二阶段重排

默认仍使用仓库内确定性的领域 reranker，不增加模型依赖。需要评估 Cross-Encoder 时单独安装：

```bash
python -m pip install -r requirements-reranker.txt
export FK_RAG_RERANK_ENABLED=1
export FK_RAG_RERANK_MODEL=/absolute/path/to/pinned-reranker
python -m eval.rag_reranker_compare --gate-no-regression
```

Cross-Encoder 只处理 BM25/vector 已召回且经过领域重排的前20个候选，不会为 `no_match` 查询凭空制造命中。模型分数不与现有 relevance 生硬相加，而是与确定性领域排序做 RRF rank fusion，避免不同模型 logit 标度改变策略。推理失败会显式 warning 并回退原排序。

默认 `local_files_only=True` 且 `trust_remote_code=False`。如确需从模型仓库下载，必须显式设置 `FK_RAG_RERANK_ALLOW_DOWNLOAD=1`，并建议同时设置 `FK_RAG_RERANK_REVISION=<immutable revision>`；生产部署应固定模型文件/修订版本。当前仓库不把 `sentence-transformers` 放进默认服务依赖，避免未启用 RAG reranker 的部署被迫安装 Torch/Transformers。

当前 checked-in synthetic benchmark 已经饱和，Cross-Encoder 是否真正提升质量不能由这40条满分样本证明。合入运行时 adapter 只证明接线、回退和安全边界；模型选型必须继续用更难的标注 query-document/ranking 集以及真实调查输出做 before/after。

## 知识格式与公开边界

参见`knowledge/detectors/*.json`。每条文档包括：

- `knowledge_id/type/title/platform/detector_ids`
- `source/known_at/reviewed_at/review_basis`
- `status`: `draft/reviewed/withdrawn`
- `simulated`: 必填布尔值，模拟资料不进入Agent检索。
- `export_policy`: 必填`public_reference`或`local_only`。
- `sdk_version_min/sdk_version_max`: 数字三段版本或null。null表示无经验证的发布版本边界，不代表所有版本都有效；`applicability`必须说明限制。
- `caveats`: 每个片段都携带的误报/能力边界。
- `sections`: 每节`heading/text`，正文最多600字符；超长必须人工按语义拆分，避免截断掉否定条件。
- 案例类型`attack_case/false_positive_case`必须有原始`case_id`，用于排除调查自身复盘。

`public_reference`是运维明确允许提供给LLM的参考资料分类，不能给原始客户案例随便打这个标记。知识工具只返回此类资料，隐私投影只为这类已reviewed的内容保留语义文本，仍用不可信数据标记包裹。`local_only`仅能本地CLI检索，不能发送给embedding端点。私有案例若要进入第一版Agent，需先生成核验过的去标识化公开参考摘要。

五份种子资料来自公开SDK的固定源码提交，标注为**AI辅助源码核对**，不是人工现场复核或实测效果认证。未伪造攻击案例、误杀样本或SDK版本覆盖率。其中SensorReplayDetector目前读取计时器/调度代理信号，没有直接采集加速度计/陀螺仪流，资料明确区分实现与注释承诺。

## 评估与边界

```bash
python -m eval.rag_eval
```

`eval/rag/cases.jsonl`包含30条基础合成检索查询；`eval/rag/hard_cases.jsonl`额外覆盖误报/能力边界、实现细节、平台负例和提示注入式查询。`eval/rag_quality_regressions.py`要求hard case的Top-1知识与section同时正确，并检查claim支持筛查不会把词汇重合误称为语义蕴含。评估使用临时数据目录，不替换生产索引；这些结果仍不证明真实风控收益、误杀降低或模型答案正确。

当前限制：

- 小规模单机索引，最多1000文档/10000片段；BM25与向量扫描在Python内执行，不是大规模向量服务。
- 当前reranker是确定性的领域metadata/意图重排，不是cross-encoder；尚未接入历史索引版本服务、自动审核或GraphRAG。
- 未调用真实LLM/embedding服务验证质量；混合检索路径用明确标记的测试向量验证契约、缓存及失败处理。
- Collector 验签并按受信任配置还原字段后，新增有界 SDK 信号投影；调查工具按租户、app 和任务时间读取并注册逐信号引用。原始 evidence 自由文本不出站，旧记录显式标记缺口。详见 [SDK 信号证据](SDK_EVIDENCE.md)。
- 报告使用结构化 claim 合同、保守词汇筛查和可选独立 entailment evaluator；未配置或未校准 evaluator 时语义验证保持 fail-closed，不能宣称已验证。
- 后续真实效果验收需要有复核标签的历史事件，对比无RAG、BM25和混合检索，排除未来资料与自身复盘。
