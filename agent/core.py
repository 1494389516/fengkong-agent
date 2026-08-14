# -*- coding: utf-8 -*-
"""Agent 主循环:对话 + function calling 调度 + 上下文预算管理。

流程:用户输入 -> LLM -> (若有 tool_calls: 执行工具, 结果回填, 再问 LLM)* -> 最终回答。
MAX_TOOL_ROUNDS 防止模型陷入无限调工具的循环。

上下文工程(为什么需要):API 无状态,每轮 create 都要全量重发历史,
单会话 token 消耗是 O(T^2)。下面几个开关分别砍不同的爆炸源:
  ① 度量        —— 记录每次 resp.usage(含 DeepSeek 缓存命中/未命中),不测无法优化。
  ④ 工具裁剪    —— TOOL_KEEP_TURNS 之前的 tool 结果替换成占位符(结论已被 assistant 吸收)。
  ⑤ checkpoint  —— CHECKPOINT_EVERY 轮把旧历史压成一条摘要(代价最高,默认关)。
  ⑥ 硬预算兜底  —— 发送前粗估上下文,超 CONTEXT_EST_TOKEN_BUDGET 强制压缩(保险丝)。
  ⑦ 脱敏层      —— FK_PRIVACY=1 时,uid/IP/设备号在 LLM 边界双向替换(privacy.py),
                    敏感标识符不出程序,公有云 API 部署的合规前提。
(② 工具限幅在 tools/dispatch 单点做;③ 案例隔离用 reset(),由 CLI /reset 触发。)
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import tools
from .privacy import Tokenizer, privacy_enabled

MAX_TOOL_ROUNDS = 8

# ④ 工具消息裁剪:保留最近 N 个"用户轮次"的完整 tool 结果,更早的裁成占位符。
#   调大 = 保留更多细节但上下文更长;调小 = 更省但可能丢早期证据。用 ① 测出的
#   缓存命中率来调:裁剪会改动历史中段,打断 DeepSeek 缓存前缀,反而可能增加 miss 成本。
TOOL_KEEP_TURNS = 2
TRIM_PLACEHOLDER = "[已裁剪:早期工具结果,结论已并入后续分析]"

# ⑤ checkpoint 摘要:每积累 N 次 ask 压缩一次旧历史。0 = 关闭(默认)。
#   仅当"必须跨案例保留记忆、又不能 reset"时才开;否则优先用 ③ reset,更便宜也更缓存友好。
CHECKPOINT_EVERY = 0

# ⑥ 上下文硬预算兜底:发送前粗估上下文 token(json 字符数 / 2,中文约 1 token/字、
#   英文约 4 字符/token,取偏保守估计),超限强制压缩一次旧历史。
#   这是保险丝不是常规手段:正常应先被 ③ reset / ④ 裁剪控制住;触发说明单案例
#   对话已经过长,压缩虽会打断缓存前缀,但比撑爆上下文窗口或费用失控强。0 = 关闭。
CONTEXT_EST_TOKEN_BUDGET = 24000


def _extract_usage(resp) -> Dict[str, int]:
    """从一次 API 响应里抽 token 用量。兼容 DeepSeek 专有字段与 OpenAI 通用字段。

    DeepSeek 的 usage 顶层有 prompt_cache_hit_tokens / prompt_cache_miss_tokens
    (二者之和 == prompt_tokens);缓存命中的 token 计费远低于未命中(约 1/10 量级),
    所以缓存命中率是这个 agent 最关键的成本指标。字段缺失时回退到 OpenAI 的
    prompt_tokens_details.cached_tokens,再退化为全部 miss。
    """
    u = getattr(resp, "usage", None)
    if u is None:
        return {"prompt": 0, "completion": 0, "total": 0, "cache_hit": 0, "cache_miss": 0}
    prompt = getattr(u, "prompt_tokens", 0) or 0
    hit = getattr(u, "prompt_cache_hit_tokens", None)
    miss = getattr(u, "prompt_cache_miss_tokens", None)
    if hit is None:  # 非 DeepSeek:回退到 OpenAI 通用字段
        details = getattr(u, "prompt_tokens_details", None)
        hit = (getattr(details, "cached_tokens", 0) if details else 0) or 0
        miss = prompt - hit
    return {
        "prompt": prompt,
        "completion": getattr(u, "completion_tokens", 0) or 0,
        "total": getattr(u, "total_tokens", 0) or 0,
        "cache_hit": hit or 0,
        "cache_miss": (miss if miss is not None else 0) or 0,
    }


class Agent:
    def __init__(self):
        # 惰性导入:离线评估要单测 ⑤/⑥ 压缩逻辑(Agent.__new__ 构造),
        # 不能让"导入 core"就强依赖 openai 包
        from .llm import load_config, make_client
        self.cfg = load_config()
        self.client = make_client(self.cfg)
        self.model = self.cfg.get("model", "deepseek-v4-flash")
        self.strict_mode = bool(self.cfg.get("strict_mode"))
        self._system = (Path(__file__).parent / "prompts" / "system.md").read_text(encoding="utf-8")
        self.messages: List[Dict] = [{"role": "system", "content": self._system}]
        # ① 全会话累计用量(跨 reset 保留,方便看整场花了多少)
        self.session_usage: Dict[str, int] = {
            "prompt": 0, "completion": 0, "total": 0,
            "cache_hit": 0, "cache_miss": 0, "api_calls": 0,
        }
        self._asks_since_ckpt = 0
        # ⑦ 脱敏:token 映射跨轮复用(同值同 token,LLM 才能跨轮关联同一账号)
        self._privacy = privacy_enabled()
        self._tok = Tokenizer() if self._privacy else None
        # 运行日志(可选):FK_AGENT_RUN_LOG=1 时每次 ask 落一行
        # out/agent_runs.jsonl,供 eval/agent_metrics.py 聚合 agent 本体的
        # 运行指标(成本/缓存命中率/工具轮数/兜底触发)——监控体系的空白面。
        # 日志在本地落盘,失败不影响对话;问题原文会含 uid 等标识符,与
        # audit.jsonl 同级机密,接生产按同等权限管控。
        self._run_log_enabled = os.environ.get("FK_AGENT_RUN_LOG") == "1"
        self._run_log_path = Path(__file__).resolve().parent.parent / "out" / "agent_runs.jsonl"
        # P1-8:版本指纹(prompt/工具集/agent 策略),随运行日志落盘
        from .versioning import snapshot as _ver_snapshot
        self._versions = _ver_snapshot()

    # ③ 案例隔离:清空对话历史只留 system,让下一个案例在干净上下文里跑。
    #   session_usage 故意不清零 —— 度量要覆盖整场,不因换案例而丢失。
    def reset(self) -> None:
        self.messages = [{"role": "system", "content": self._system}]
        self._asks_since_ckpt = 0

    def cache_hit_rate(self) -> float:
        s = self.session_usage
        denom = s["cache_hit"] + s["cache_miss"]
        return (s["cache_hit"] / denom) if denom else 0.0

    def _accumulate(self, u: Dict[str, int]) -> None:
        for k in ("prompt", "completion", "total", "cache_hit", "cache_miss"):
            self.session_usage[k] += u[k]
        self.session_usage["api_calls"] += 1

    # ④ 发送前把"老于 TOOL_KEEP_TURNS 个用户轮次"的 tool 结果内容换成占位符。
    #   只改 content、保留 role 与 tool_call_id,so 与 assistant.tool_calls 的配对不破,
    #   API 不会因为缺 tool 响应而报错。幂等:已裁过的跳过,让缓存前缀尽快稳定。
    def _trim_tool_messages(self) -> None:
        if TOOL_KEEP_TURNS <= 0:
            return
        user_pos = [i for i, m in enumerate(self.messages) if m["role"] == "user"]
        if len(user_pos) <= TOOL_KEEP_TURNS:
            return
        cutoff = user_pos[-TOOL_KEEP_TURNS]  # 这个位置之前的 tool 消息全部裁剪
        for m in self.messages[:cutoff]:
            if m["role"] == "tool" and m["content"] != TRIM_PLACEHOLDER:
                m["content"] = TRIM_PLACEHOLDER

    # ⑥ 上下文粗估,按字符类分档:CJK ~0.7 token/字,其余 ~0.25 token/字。
    #   旧口径 chars/2 是 ASCII 假设,对中文重的证据链低估 25-30%,兜底会
    #   比预期晚触发 —— 保险丝晚炸不是保守是失效。仍是粗估:追求便宜和
    #   方向正确(宁可高估),精确对齐分词器不值得。
    def _estimate_context_tokens(self) -> int:
        total = 0.0
        for m in self.messages:
            s = json.dumps(m, ensure_ascii=False, default=str)
            cjk = sum(1 for ch in s if "\u4e00" <= ch <= "\u9fff")
            total += cjk * 0.7 + (len(s) - cjk) * 0.25
        return int(total)

    # ⑤/⑥ 共用:把 system 之后、最后一个用户轮次之前的历史压成一条摘要。
    #   保留最后一个用户轮次的完整尾巴 —— 兜底可能在工具循环中途触发,
    #   当前轮的 user/assistant(tool_calls)/tool 配对不能拆。
    def _checkpoint_now(self) -> bool:
        """把最后一个用户轮次之前的历史压成摘要。返回是否真的压缩了 ——
        单轮内工具结果自身撑爆时,可压的旧历史为空,调用方据此改走当前轮兜底。"""
        user_pos = [i for i, m in enumerate(self.messages) if m["role"] == "user"]
        cut = user_pos[-1] if user_pos else len(self.messages)
        body = self.messages[1:cut]
        if len(body) < 2:  # 没什么可压的,别浪费一次 LLM 调用
            return False
        convo = "\n".join(
            "%s: %s" % (m["role"], (m.get("content") or "")[:500]) for m in body
        )
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content":
                    "把下面的风控分析对话压成要点摘要,保留:关键结论、命中的名单/规则、"
                    "涉及的 uid/ip/设备及其风险判定;丢弃工具调用的过程细节。"},
                {"role": "user", "content": convo},
            ],
        )
        self._accumulate(_extract_usage(resp))
        summary = resp.choices[0].message.content or ""
        self.messages = [
            {"role": "system", "content": self._system},
            {"role": "assistant", "content": "【历史摘要】\n" + summary},
        ] + self.messages[cut:]
        return True

    # ⑥ 当前轮兜底:单轮内 tool 结果自身撑爆上下文时,checkpoint 压不动(全在
    #   最后一个用户轮之后),这里把当前轮除最近一条外的 tool 结果降级为占位符。
    #   只改 content、保留配对结构,不破坏 assistant.tool_calls/tool 契约。
    #   返回是否有改动。
    def _force_trim_current_turn(self) -> bool:
        live = [i for i, m in enumerate(self.messages)
                if m["role"] == "tool" and m["content"] != TRIM_PLACEHOLDER]
        if len(live) <= 1:  # 只剩一条工具结果,再压就没数据可用了
            return False
        for i in live[:-1]:  # 保留最近一条
            self.messages[i]["content"] = TRIM_PLACEHOLDER
        return True

    # ⑤ 周期触发:每 CHECKPOINT_EVERY 次 ask 压缩一次。
    def _maybe_checkpoint(self) -> None:
        if CHECKPOINT_EVERY <= 0:
            return
        self._asks_since_ckpt += 1
        if self._asks_since_ckpt < CHECKPOINT_EVERY or len(self.messages) <= 3:
            return
        self._asks_since_ckpt = 0
        self._checkpoint_now()

    def _log_ask(self, question: str, answer: str, ask_usage: Dict[str, int],
                 tools_used: List[str], compacted: bool,
                 latency: Dict[str, Any], tool_times: List[tuple]) -> None:
        """落一行运行日志(仅 FK_AGENT_RUN_LOG=1 时)。日志失败绝不能掀翻对话。
        latency: {total_ms, llm_ms, tool_ms};tool_times: [(工具名, 毫秒)]。"""
        if not self._run_log_enabled:
            return
        try:
            rec = {
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "model": self.model,
                "versioning": getattr(self, "_versions", {}),
                "question": question,
                "answer": (answer or "")[:2000],
                "tool_rounds": ask_usage["api_calls"],
                "tools_used": tools_used,
                "api_calls": ask_usage["api_calls"],
                "tokens": {k: ask_usage[k] for k in
                           ("prompt", "completion", "cache_hit", "cache_miss")},
                "latency_ms": {k: round(v, 1) for k, v in latency.items()},
                "tool_latency_ms": [[n, round(t, 1)] for n, t in tool_times],
                "budget_compacted": compacted,
            }
            self._run_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._run_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass

    def ask(self, user_input: str,
            on_tool: Optional[Callable] = None,
            on_usage: Optional[Callable] = None,
            on_notice: Optional[Callable] = None) -> str:
        """发送一轮用户输入,返回最终文本回答。

        on_tool(name, args)  —— CLI 实时展示工具调用。
        on_usage(usage_dict) —— ① 每次 API 响应后实时回调本轮 token 用量。
        on_notice(text)      —— ⑥ 兜底等内部动作的提示,CLI 可打印告知用户。
        """
        # ⑦ 用户输入里的真实 uid/IP/设备号在进 LLM 前替换成 token
        self.messages.append({"role": "user", "content":
                              self._tok.tokenize(user_input) if self._privacy else user_input})
        compacted_this_ask = False  # ⑥ 每轮 ask 最多强制压缩一次,防压缩循环
        ask_usage: Dict[str, int] = {"prompt": 0, "completion": 0,
                                     "cache_hit": 0, "cache_miss": 0,
                                     "api_calls": 0}
        tools_used: List[str] = []
        tool_times: List[tuple] = []
        latency = {"total_ms": 0.0, "llm_ms": 0.0, "tool_ms": 0.0}
        _t0 = time.monotonic()  # P1-7:延迟预算的计量起点
        for _ in range(MAX_TOOL_ROUNDS):
            self._trim_tool_messages()  # ④ 发送前裁剪
            if (CONTEXT_EST_TOKEN_BUDGET > 0 and not compacted_this_ask
                    and self._estimate_context_tokens() > CONTEXT_EST_TOKEN_BUDGET):
                compacted_this_ask = True
                # 先压旧历史;压不动(单轮工具结果自身撑爆)再降级当前轮工具结果。
                # 只在真的减了上下文时才通告,不谎报"已压缩"。
                did = self._checkpoint_now() or self._force_trim_current_turn()
                if did and on_notice:
                    on_notice("上下文估算超 %d tokens,已强制压缩(⑥ 兜底)"
                              % CONTEXT_EST_TOKEN_BUDGET)
            _llm_t0 = time.monotonic()
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                tools=tools.schemas(strict=self.strict_mode),
            )
            latency["llm_ms"] += (time.monotonic() - _llm_t0) * 1000
            usage = _extract_usage(resp)  # ①
            self._accumulate(usage)
            for k in ("prompt", "completion", "cache_hit", "cache_miss"):
                ask_usage[k] += usage[k]
            ask_usage["api_calls"] += 1
            if on_usage:
                on_usage(usage)
            msg = resp.choices[0].message
            if not msg.tool_calls:
                # ⑦ 历史里保持 token 形态(一致性),展示给人时反解
                self.messages.append({"role": "assistant", "content": msg.content})
                self._maybe_checkpoint()  # ⑤
                answer = msg.content or ""
                latency["total_ms"] = (time.monotonic() - _t0) * 1000
                self._log_ask(user_input, answer, ask_usage, tools_used,
                              compacted_this_ask, latency, tool_times)
                return self._tok.detokenize(answer) if self._privacy else answer
            # assistant 消息(含 tool_calls)必须原样入历史,否则下一轮 API 会拒绝 tool 消息
            self.messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [tc.model_dump() for tc in msg.tool_calls],
            })
            for tc in msg.tool_calls:
                name = tc.function.name
                args_str = tc.function.arguments or "{}"
                if self._privacy:  # ⑦ LLM 传来的 token 参数反解成真值再执行
                    args_str = self._tok.detokenize(args_str)
                try:
                    args = json.loads(args_str)
                except json.JSONDecodeError:
                    args = {}
                if on_tool:
                    on_tool(name, args)
                _tool_t0 = time.monotonic()
                result = tools.dispatch(name, args)  # ② 限幅在 dispatch 内统一做
                tool_ms = (time.monotonic() - _tool_t0) * 1000
                latency["tool_ms"] += tool_ms
                tool_times.append((name, tool_ms))
                tools_used.append(name)
                content = json.dumps(result, ensure_ascii=False, default=str)
                if self._privacy:  # ⑦ 工具结果回填历史前替换成 token
                    content = self._tok.tokenize(content)
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })
        answer = "[单轮工具调用已达上限 %d 次,强制停止]" % MAX_TOOL_ROUNDS
        latency["total_ms"] = (time.monotonic() - _t0) * 1000
        self._log_ask(user_input, answer, ask_usage, tools_used,
                      compacted_this_ask, latency, tool_times)
        return answer
