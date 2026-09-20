# 风控调查 RAG 第一版

这版把知识检索接入已有异步调查任务，不改变实时决策与审批通道。

## 已实现

- `get_event_evidence(event_id)`：按认证租户/app读取业务事件、已落库决策和关联SDK观测；任务中只能访问绑定事件。
- `search_risk_knowledge(...)`：中文/英文BM25、可选真实embedding、RRF融合，返回内容哈希、来源、适用范围、误报条件和`[K:chunk_id]`。
- 每个数据集独立SQLite索引，沿用现有认证与数据目录路由；模型不能指定索引路径或租户。
- `python -m agent.rag ingest` 是运维入库入口，不注册为Agent写工具。全量替换事务保证删除/撤回生效，失败保留原索引；相同内容复用向量。
- 检索过滤草稿、撤回、模拟资料、未来知识、自身案件复盘以及不适用的版本。版本限定文档在请求版本未知时不返回。
- 新调查任务绑定索引内容指纹和事件时间；检索时间由服务端覆盖，不能由模型向未来移动。
- 调查结果保存引用来源及未检索到的引用ID。引用存在检查不等于语义蕴含检查，不宣称已验证结论。
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
   `knowledge_citation_audit`、`knowledge_index_digest`和`budget_used`。`summary`保留模型原始输出供审计。

交互Agent的`investigate`和默认`analyst`工具包也包含新工具。调用`get_event_evidence`需要已有认证租户/app上下文；它不回退到无认证全表查询。

旧任务没有知识指纹，保持原能力，不能凭空增加RAG权限。索引更新后旧快照的知识检索会明确失败，不能静默使用新版本；第一版没有历史索引服务或任务重发接口。处理方式是在处理队列前完成知识发布，运行期间固定索引；需要恢复旧任务时由运维恢复原语料/模型索引。不能修改时间字段来绕过历史边界。

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

`eval/rag/cases.jsonl`包含30条人工编写的合成检索查询：25条预期命中、5条预期无匹配/平台不匹配。评估使用临时数据目录，不替换生产索引。结果仅证明小语料检索与过滤行为，不证明真实风控收益、误杀降低或模型答案正确。

当前限制：

- 小规模单机索引，最多1000文档/10000片段；BM25与向量扫描在Python内执行，不是大规模向量服务。
- 未接入reranker、历史索引版本服务、自动审核或GraphRAG。
- 未调用真实LLM/embedding服务验证质量；混合检索路径用明确标记的测试向量验证契约、缓存及失败处理。
- 现有collector观测接口不包含解码后的检测信号正文。新证据工具返回业务事件与SDK来源/硬件观测，不擅自解码可能混淆的原始载荷；这会作为调查缺口提示。
- 报告使用结构化 claim 合同，检查事件证据和知识引用是否来自本任务；仍未验证文字结论与来源之间的语义蕴含。
- 后续真实效果验收需要有复核标签的历史事件，对比无RAG、BM25和混合检索，排除未来资料与自身复盘。
