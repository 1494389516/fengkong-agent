# -*- coding: utf-8 -*-
"""CLI 入口:python3 main.py 进入交互式对话。

命令:
  /reset        开一个干净案例(清空对话上下文,session token 计数保留)—— ③ 案例隔离
  /pending      查看 agent 提交的待审批处置(名单写入申请)
  /approve <id> 批准一条申请,写入名单库并记审计日志
  /deny <id>    驳回一条申请(同样留审计记录)
  exit / quit   退出(Ctrl-D 亦可)

工具调用与每轮 token 用量会实时打印,便于观察 agent 的取证过程与上下文成本。
审批命令是人类专用通道:agent 只能提交申请(blacklist_add),批准/驳回
不是注册工具,模型无法触达。
"""
import sys

from agent.core import Agent
from agent.tools import actions


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
    print("命令:/reset 开新案例 · /pending 待审批 · /approve|/deny <id> 审批 · exit 退出。")
    print("工具调用与 token 用量会实时打印。")
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
        if low == "/pending":
            try:
                items = actions.list_pending()
            except Exception as e:  # noqa: BLE001  队列文件损坏不该掀翻整个 CLI
                print("  [错误] 读取待审批队列失败:%s" % e)
                continue
            if not items:
                print("  [待审批] 队列为空。")
            for a in items:
                kind = a.get("kind", "blacklist_add")
                if kind == "threshold_change":
                    print("  [待审批] #%d 阈值变更 %s(现值 %s)| %s" % (
                        a["action_id"], a["values"], a.get("current", {}), a["reason"]))
                elif kind == "blacklist_remove":
                    print("  [待审批] #%d 移出%s名单 %s=%s | %s" % (
                        a["action_id"], a["list"], a["dimension"], a["value"], a["reason"]))
                elif kind == "appeal_resolve":
                    print("  [待审批] #%d 申诉决议 appeal#%d uid=%s -> %s | %s" % (
                        a["action_id"], a["appeal_id"], a["uid"], a["decision"], a["reason"]))
                elif kind == "blacklist_add":
                    print("  [待审批] #%d %s=%s -> %s名单%s | %s" % (
                        a["action_id"], a["dimension"], a["value"], a["list"],
                        "(观察期 %d 天)" % a["expires_days"] if a.get("expires_days") else "",
                        a["reason"]))
                else:  # 未知类型:宁可展示原始内容,不能让 CLI 崩掉
                    print("  [待审批] #%d %s | %s" % (
                        a["action_id"], kind, a.get("reason", a)))
            continue
        if low.startswith("/approve") or low.startswith("/deny"):
            approve = low.startswith("/approve")
            parts = user_input.split()
            if len(parts) != 2 or not parts[1].isdigit():
                print("  用法:/approve <id> 或 /deny <id>,id 见 /pending")
                continue
            try:
                a = actions.decide(int(parts[1]), approve=approve)
            except Exception as e:  # noqa: BLE001  落盘失败时申请仍留在队列,可重试
                print("  [错误] 审批未完成(申请仍在队列,可重试):%s" % e)
                continue
            if a is None:
                print("  查无此申请,/pending 查看当前队列。")
            elif a.get("kind", "blacklist_add") == "threshold_change":
                print("  [%s] #%d 阈值变更 %s(已记审计日志)" % (
                    "已批准,新策略版本生效" if approve else "已驳回",
                    a["action_id"], a["values"]))
            elif a.get("kind") == "blacklist_remove":
                # 移除申请不能复用"写入"文案:方向说反会让值班误判名单现状
                print("  [%s] #%d %s=%s 移出%s名单(已记审计日志)" % (
                    "已批准并移出" if approve else "已驳回",
                    a["action_id"], a["dimension"], a["value"], a["list"]))
            elif a.get("kind") == "appeal_resolve":
                print("  [%s] #%d 申诉决议 appeal#%d uid=%s -> %s(已记审计日志)" % (
                    "已批准并落盘" if approve else "已驳回",
                    a["action_id"], a["appeal_id"], a["uid"], a["decision"]))
            elif a.get("kind", "blacklist_add") == "blacklist_add":
                print("  [%s] #%d %s=%s -> %s名单(已记审计日志)" % (
                    "已批准并写入" if approve else "已驳回",
                    a["action_id"], a["dimension"], a["value"], a["list"]))
            else:
                print("  [%s] #%d %s(已记审计日志)" % (
                    "已批准" if approve else "已驳回", a["action_id"], a.get("kind")))
            continue
        answer = agent.ask(
            user_input,
            on_tool=lambda name, args: print("  [工具] %s(%s)" % (name, args)),
            on_usage=lambda u: print(_fmt_round_usage(u)),
            on_notice=lambda msg: print("  [上下文] %s" % msg),
        )
        print("\n%s" % answer)
        print(_fmt_session_usage(agent))


if __name__ == "__main__":
    sys.exit(main())
