"""Retrieval grader regressions; no network/model dependency."""
import unittest

from agent.rag.grader import grade_retrieval


def hit(text, section="实现与信号含义", caveats=""):
    return {
        "title": "DebuggerDetector 调试器检测",
        "detector_ids": ["DebuggerDetector"],
        "section": section,
        "text": text,
        "caveats": caveats,
        "applicability": "iOS reviewed detector documentation",
    }


class RetrievalGraderRegression(unittest.TestCase):
    def test_passes_auditable_match(self):
        grade = grade_retrieval(
            "DebuggerDetector 调试器检测原理",
            [hit("DebuggerDetector 检查调试器附加状态。")])
        self.assertEqual(grade["status"], "pass")
        self.assertGreater(grade["query_term_coverage"], 0)
        self.assertFalse(grade["semantic_relevance_verified"])

    def test_no_match_requests_rewrite(self):
        grade = grade_retrieval("未知信号", [])
        self.assertEqual(grade["status"], "rewrite_required")
        self.assertEqual(grade["reason"], "no_match")

    def test_unrelated_hit_is_rejected(self):
        grade = grade_retrieval(
            "跨境洗钱团伙确认",
            [hit("DebuggerDetector 检查调试器附加状态。")])
        self.assertEqual(grade["status"], "rewrite_required")
        self.assertEqual(grade["reason"], "no_lexical_bridge")

    def test_counterevidence_requires_boundary_material(self):
        missing = grade_retrieval(
            "DebuggerDetector 调试器",
            [hit("DebuggerDetector 检查调试器附加状态。")],
            purpose="counterevidence")
        self.assertEqual(missing["reason"], "counterevidence_not_found")
        found = grade_retrieval(
            "DebuggerDetector 调试器",
            [hit("合法开发调试也可能命中。", section="误报与能力边界",
                 caveats="不能单独证明欺诈。")],
            purpose="counterevidence")
        self.assertEqual(found["status"], "pass")
        self.assertTrue(found["counterevidence_signal"])


if __name__ == "__main__":
    unittest.main()
