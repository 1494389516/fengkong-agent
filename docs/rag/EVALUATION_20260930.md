# RAG 对比评估：2026-09-30

## 结论

当前基线 `05e8bbc34d7ab1965855a64f152a12e7e78d2cfe` 的离线检索与安全契约通过，但还不能回答「RAG 是否降低真实误杀/漏判」或「混合检索是否优于 BM25」。本次未调用 LLM、embedding 或独立语义判定服务，未推送或发布代码。

- 语料：5 份公开 SDK 固定源码参考，15 个片段；全部是 detector_doc，没有 attack_case/false_positive_case。review_basis 明确为 AI 辅助源码核对，不是人工现场复核。
- 检索集：30 条基础 + 10 条 hard 合成查询，共 34 条正例、6 条负例；9 条要求特定章节。另有 3 条上下文召回测试。
- 无 RAG：仅为空上下文控制，Hit@1/5=0，负例空返回=6/6；没有运行「不带 RAG 的模型回答」，此数值不衡量答案质量。
- BM25 + 现有确定性领域重排：Hit@1=34/34，Hit@5=34/34，MRR@5=1，负例空返回=6/6，指定章节 Top-1=9/9，上下文 Recall@5=1。
- 真实 hybrid：未运行，无真实 embedding 执行配置与本次出站授权；结果保留 null，不用测试向量代替语义检索。
- 误杀率、漏判率、模型受注入成功率：未测，保留 null。合成检索满分只说明这个小基准已经饱和。

`data/labels.json` 自述需换真实数据后按人工审核结论回填，`data/gen_sample.py` 是合成数据生成器。没有找到满足当前目标的、可核验来源及人工复核记录的真实案件集。

## 安全验证范围

现有 38 项 RAG/SDK 证据/检索工作流/准入回归全部通过；未来知识和跨平台泄漏探针通过。新增测试验证：新恶意文档或已准入文档被篡改导致入库失败时，旧索引指纹及原检索结果保持不变。

这只覆盖「攻击者能改语料，但不能改独立 admission manifest」的边界。它不证明审核人/manifest 被攻陷后的抗投毒能力，也不证明生成模型会忽略恶意证据。hard 集中的注入式查询只验证检索到正确章节，不是 end-to-end 注入测试。

## 仍需专门验证的风险

- hybrid 语义召回使用 cosine > 0，没有经标注集校准的无关查询拒绝阈值（`agent/rag/store.py`）。这并不直接证明真实 embedding 会误报，但不能将 BM25 的负例满分外推到 hybrid；应加入无关、近主题、无 detector identifier 的负例/改写查询。
- 结构化引用通过与词汇重合不等于语义支持；含否定反转的句子也可能有很高词汇重合。独立 entailment 门只评价含知识引用的 claim，跳过 event-only claim，因此不能代替整起案件的人工事实判定。

## 评估器修正

本地评估代码存在缺失审计被当作成功的问题：原来 `investigation_metrics([{}])` 会得到引用有效率=1、反证流程完成率=1、unsupported rate=0。这样的输入实际不可评价。

本次只改评估层：缺失/未知/部分缺失审计状态不获得成功分，增加可评价分母；不合法或重复的 unsupported 索引不进入统计；这些比例为逐报告宏平均，非全体 claim 池化比例；显式未检索反证不算流程完成；语义验证指标从实际独立 entailment 审计读取，避免错误读取永远不作语义认证的词汇筛查结果。新增回归测试覆盖这些情形。没有改变运行时检索、决策或审批逻辑。

新增 `eval/rag_ablation.py`：逐条保留检索命中、实际执行模式、warning、输入 SHA-256，默认不产生外部请求；hybrid 回退时明确标为 partial_with_fallback 并返回非零退出码。可用同一输入集复跑。输出中的 BM25 指生产默认检索+领域重排，不是纯 BM25 分数排序。

最终组合回归共 58 项通过（原有 38 项 + 新增 20 项），scorecard gate 通过；CI 中其余 12 个编译/架构/治理/图管线/预算/基础检索检查命令全部退出 0。详细命令与原始日志在交付包 `results/`。这不是全量生产或真实模型验收。

## 复现

交付包内 `rag-evaluation.patch` 基于上述提交，可先在干净检出上执行 `git apply --check rag-evaluation.patch`，确认后再 `git apply rag-evaluation.patch`。`source/` 保留四个评估源码文件，`results/` 保留逐条输出、环境版本和测试日志。

在仓库根目录、Python 3.12 环境安装 `requirements.txt` 后：

```bash
export FK_RAG_EMBED_ENABLED=0 FK_RAG_RERANK_ENABLED=0 FK_RAG_ENTAILMENT_ENABLED=0
python -m eval.rag_ablation --output out/rag_ablation.json
python -m eval.rag_scorecard --gate --output out/rag_scorecard.json
python -m unittest eval.rag_ablation_regressions eval.rag_scorecard_regressions -v
python -m unittest eval.rag_sdk_evidence_regressions eval.rag_quality_regressions eval.rag_entailment_regressions eval.rag_cross_encoder_regressions eval.rag_retrieval_grader_regressions eval.claim_evidence_graph_regressions eval.rag_poisoning_regressions eval.adaptive_router_regressions eval.investigation_memory_regressions -v
```

只有确认 embedding 服务、模型版本、数据发送范围及费用后，才配置 `FK_RAG_EMBED_*` 并显式使用 `--hybrid`。本次没有执行此步骤。

## 真正三路效果验收需要什么

1. 去标识化案件：case_id、事件时间、平台/SDK版本、当时可获得的结构化事实与逐条证据；保留原始 client_reported 边界，签名验证不能升级为事实真实性证明。
2. 独立人工复核标签：正常/确认攻击/证据不足；复核时间、判定依据、争议仲裁记录。不能用现有规则 verdict 自己当 gold。
3. 案件对应 gold 知识/证据引用与必要反证；按时间冻结知识，排除案件自身复盘与未来资料。按案件实体分组隔离训练/调参与留出集，避免同一事件改写泄漏。
4. 三路在同一留出案件上运行同一固定生成模型、提示词、工具权限及预算，只改变检索；no-RAG 路径彻底禁用知识工具；记录模型/embedding版本及调用预算。未跑模型时不得把空检索控制说成 no-RAG 生成基线。
5. 同时报告每类分母、混淆矩阵、误报/漏报、复核/弃答率、引用支持率、反证遗漏率与配对置信区间。固定人审 rubric，盲审模型输出；独立语义评估器需先校准。
6. 对同一案件做干净/投毒配对：查询注入、证据自由文本注入、未准入知识篡改、已准入但内容恶意等威胁分别测，记录不安全结论、缺证强判、非法动作企图；不得把「恶意文档入库被拒」等同为全链路安全。

建议先用一批有复核依据、涵盖误报边界与确认攻击的案件验通流程，再按目标误差与业务风险确定正式留出集规模；不凭任意小样本宣称上线收益。
