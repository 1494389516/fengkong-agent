"""Adaptive risk router regressions."""
import unittest
from agent.rag.router import route_query


class AdaptiveRouterRegression(unittest.TestCase):
    def test_history_goes_to_event_store(self):
        plan = route_query("最近7天登录事件有什么变化")
        self.assertEqual(plan["primary"], "event_store")
        self.assertFalse(plan["execute_allowed"])

    def test_detector_explanation_uses_knowledge(self):
        plan = route_query("DebuggerDetector 为什么会误报，检测原理是什么")
        self.assertEqual(plan["primary"], "knowledge_rag")

    def test_relationship_question_uses_existing_risk_graph(self):
        plan = route_query("这些账号是否共享设备和IP，有什么关联关系")
        self.assertEqual(plan["primary"], "risk_graph")

    def test_policy_question_uses_rule_engine(self):
        plan = route_query("当前规则为什么拒绝，这个策略阈值是什么")
        self.assertEqual(plan["primary"], "rule_engine")

    def test_unknown_defaults_to_fact_first_not_rag(self):
        plan = route_query("帮我调查一下这个情况")
        self.assertEqual(plan["primary"], "event_store")
        self.assertEqual([p["plane"] for p in plan["planes"]], ["event_store"])


if __name__ == "__main__":
    unittest.main()
