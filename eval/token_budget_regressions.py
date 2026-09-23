"""Offline checks for structural and runtime Agent token budgets.

Run with: python -m eval.token_budget_regressions
"""
import threading
import unittest
from unittest.mock import patch

from agent.core import Agent
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


if __name__ == "__main__":
    unittest.main()
