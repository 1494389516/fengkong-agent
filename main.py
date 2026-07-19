# -*- coding: utf-8 -*-
"""CLI 入口:python3 main.py 进入交互式对话。

命令:
  /reset       开一个干净案例(清空对话上下文,session token 计数保留)—— ③ 案例隔离
  exit / quit  退出(Ctrl-D 亦可)

工具调用与每轮 token 用量会实时打印,便于观察 agent 的取证过程与上下文成本。
"""
import sys

from agent.core import Agent


def _fmt_round_usage(u):
    """① 单轮用量:突出 DeepSeek 缓存命中/未命中(命中计费远低于未命中)。"""
    return "  [tokens] 本轮 prompt=%d(缓存命中 %d / 未命中 %d)· completion=%d" % (
        u["prompt"], u["cache_hit"], u["cache_miss"], u["completion"])


def _fmt_session_usage(agent):
    """① 全会话累计:含缓存命中率,这是本 agent 最关键的成本指标。"""
    s = agent.session_usage
    return "  [session] API %d 次 · prompt %d · completion %d · 总 %d · 缓存命中率 %.0f%%" % (
        s["api_calls"], s["prompt"], s["completion"], s["total"], 100.0 * agent.cache_hit_rate())


def main():
    agent = Agent()
    print("风控分析 agent(模型: %s)。" % agent.model)
    print("命令:/reset 开新案例 · exit 退出。工具调用与 token 用量会实时打印。")
    while True:
        try:
            user_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user_input:
            continue
        low = user_input.lower()
        if low in ("exit", "quit"):
            break
        if low == "/reset":  # ③ 案例隔离
            agent.reset()
            print("  [已重置] 开一个干净案例上下文;session token 计数保留。")
            continue
        answer = agent.ask(
            user_input,
            on_tool=lambda name, args: print("  [工具] %s(%s)" % (name, args)),
            on_usage=lambda u: print(_fmt_round_usage(u)),
        )
        print("\n%s" % answer)
        print(_fmt_session_usage(agent))


if __name__ == "__main__":
    sys.exit(main())
