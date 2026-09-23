"""Offline checks for structural and runtime Agent token budgets.

Run with: python -m eval.token_budget_regressions
"""
import json
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.core import Agent
from eval.agent_metrics import aggregate
from eval.measure_costs import (ANALYST_SCHEMA_BUDGET, SCHEMA_BUDGET,
                                SYSTEM_PROMPT_BUDGET, pack_structural_sizes)


class NoCallClient:
    def __init__(self):
        self.chat = self
        self.completions = self
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        raise AssertionError("oversized context was sent to the model")


class FakeClient:
    def __init__(self, usages):
        self.chat = self
        self.completions = self
        self.usages = list(usages)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        usage = self.usages.pop(0)
        return types.SimpleNamespace(
            usage=(types.SimpleNamespace(prompt_tokens=usage[0],
                                         completion_tokens=usage[1])
                   if usage is not None else None),
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(
                content="ok", tool_calls=None))],
        )


def fake_agent(usages, budget):
    agent = Agent.__new__(Agent)
    agent._ask_lock = threading.Lock()
    agent._system = "system"
    agent.messages = [{"role": "system", "content": "system"}]
    agent._scope_identity = None
    agent._privacy = False
    agent._tok = None
    agent.tool_pack = "investigate"
    agent._run_log_enabled = False
    agent._asks_since_ckpt = 0
    agent.model = "fake"
    agent.strict_mode = False
    agent.session_usage = {k: 0 for k in
                           ("prompt", "completion", "total", "cache_hit",
                            "cache_miss", "api_calls")}
    agent.case_token_budget = budget
    agent._case_tokens = 0
    agent.client = FakeClient(usages)
    return agent


class TokenBudgetRegressions(unittest.TestCase):
    def test_structural_budgets(self):
        packs = pack_structural_sizes()
        self.assertLessEqual(packs["full"]["schemas_chars"], SCHEMA_BUDGET)
        self.assertLessEqual(packs["analyst"]["schemas_chars"], ANALYST_SCHEMA_BUDGET)
        self.assertLessEqual(packs["full"]["system_chars"], SYSTEM_PROMPT_BUDGET)

    def test_oversized_current_turn_stops_before_model_call(self):
        agent = Agent.__new__(Agent)
        agent._ask_lock = threading.Lock()
        agent._system = "system"
        agent.messages = [{"role": "system", "content": "system"}]
        agent._scope_identity = None
        agent._privacy = False
        agent._tok = None
        agent.tool_pack = "investigate"
        agent._run_log_enabled = False
        agent.client = NoCallClient()
        with patch("agent.core.CONTEXT_EST_TOKEN_BUDGET", 100):
            with self.assertRaisesRegex(PermissionError, "context token budget"):
                agent.ask("x" * 1000)
        self.assertEqual(agent.client.calls, 0)

    def test_single_large_tool_result_fails_closed(self):
        agent = Agent.__new__(Agent)
        agent._system = "system"
        agent.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "investigate"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "call"}]},
            {"role": "tool", "content": "x" * 1000},
        ]
        with patch("agent.core.CONTEXT_EST_TOKEN_BUDGET", 100):
            with self.assertRaisesRegex(PermissionError, "context token budget"):
                agent._enforce_context_budget(allow_checkpoint=False)

    def test_case_budget_spans_asks_and_reset_starts_new_case(self):
        agent = fake_agent([(100, 10)] * 3, 250)
        with patch("agent.core.tools.schemas", return_value=[]):
            self.assertEqual(agent.ask("first"), "ok")
            self.assertEqual(agent.ask("second"), "ok")
            with self.assertRaisesRegex(PermissionError, "case token budget exhausted"):
                agent.ask("third")
            self.assertEqual(len(agent.client.calls), 2)
            agent.reset()
            self.assertEqual(agent.ask("new case"), "ok")
        self.assertEqual(agent._case_tokens, 110)
        self.assertEqual(agent.session_usage["api_calls"], 3)
        self.assertEqual(agent.session_usage["prompt"], 300)
        self.assertTrue(all(0 < call["max_tokens"] <= 2048
                            for call in agent.client.calls))

    def test_missing_usage_is_charged_and_cannot_repeat_for_free(self):
        agent = fake_agent([None], 150)
        with patch("agent.core.tools.schemas", return_value=[]):
            self.assertEqual(agent.ask("first"), "ok")
            self.assertEqual(agent._case_tokens, 150)
            with self.assertRaisesRegex(PermissionError, "case token budget exhausted"):
                agent.ask("second")
        self.assertEqual(len(agent.client.calls), 1)

    def test_provider_usage_over_cap_is_recorded_and_rejected(self):
        agent = fake_agent([(100, 10)], 100)
        with tempfile.TemporaryDirectory() as td:
            agent._run_log_enabled = True
            agent._run_log_path = Path(td) / "runs.jsonl"
            with patch("agent.core.tools.schemas", return_value=[]):
                with self.assertRaisesRegex(PermissionError, "case token budget exceeded"):
                    agent.ask("one")
            report = aggregate(agent._run_log_path)
        self.assertEqual(report["budget_violations"][0]["value"], 110)
        self.assertEqual(agent._case_tokens, 110)
        self.assertEqual(agent.session_usage["api_calls"], 1)

    def test_checkpoint_request_consumes_case_budget(self):
        agent = fake_agent([(60, 10)], 200)
        agent.messages += [
            {"role": "user", "content": "old question"},
            {"role": "assistant", "content": "old answer"},
            {"role": "user", "content": "new question"},
        ]
        self.assertTrue(agent._checkpoint_now())
        self.assertEqual(agent._case_tokens, 70)
        self.assertEqual(agent.session_usage["api_calls"], 1)
        self.assertLessEqual(agent.client.calls[0]["max_tokens"], 1024)

    def test_metrics_aggregate_multiple_asks_per_case(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "runs.jsonl"
            rows = [
                {"ts": "t1", "case_id": "a", "case_tokens": 70,
                 "case_token_budget": 100, "tokens": {"prompt": 60, "completion": 10}},
                {"ts": "t2", "case_id": "a", "case_tokens": 140,
                 "case_token_budget": 100, "tokens": {"prompt": 60, "completion": 10}},
                {"ts": "t3", "case_id": "b", "case_tokens": 20,
                 "case_token_budget": 100, "tokens": {"prompt": 15, "completion": 5}},
            ]
            log.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            report = aggregate(log)
        self.assertEqual(report["cases"], 2)
        self.assertEqual(report["avg_tokens_per_case"], 80)
        self.assertEqual(report["budget_violations"], [
            {"case": "t1", "kind": "token_budget", "value": 140, "budget": 100}])


if __name__ == "__main__":
    unittest.main()
