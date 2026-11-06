"""Tests for llm_tool_auditor. Run: python -m unittest test_auditor -v"""

import unittest

from llm_tool_auditor import audit_tool, audit_tools


class TestAuditor(unittest.TestCase):
    def test_shell_tool_is_critical(self):
        report = audit_tool({
            "name": "run_shell", "description": "Execute a shell command",
            "parameters": {"type": "object",
                           "properties": {"command": {"type": "string"}},
                           "required": ["command"]}})
        self.assertEqual(report.rating, "critical")

    def test_delete_tool_is_critical(self):
        report = audit_tool({
            "name": "delete_user_record", "description": "Delete a record",
            "parameters": {"type": "object",
                           "properties": {"account": {"type": "string"}},
                           "required": ["account"]}})
        self.assertEqual(report.rating, "critical")

    def test_constrained_tool_is_safe(self):
        report = audit_tool({
            "name": "get_weather", "description": "Get weather for a city",
            "parameters": {"type": "object",
                           "properties": {"city": {"type": "string",
                                                  "enum": ["Lahore"]}},
                           "required": ["city"]}})
        self.assertEqual(report.rating, "safe")
        self.assertEqual(report.score, 0)

    def test_unconstrained_email_is_flagged(self):
        report = audit_tool({
            "name": "send_email", "description": "Send an email",
            "parameters": {"type": "object",
                           "properties": {"email": {"type": "string"}},
                           "required": ["email"]}})
        self.assertEqual(report.rating, "high")
        self.assertGreaterEqual(report.score, 25)

    def test_overall_rating_is_worst_tool(self):
        report = audit_tools([
            {"name": "get_weather", "description": "Get weather",
             "parameters": {"type": "object",
                            "properties": {"city": {"type": "string",
                                                   "enum": ["Lahore"]}},
                            "required": ["city"]}},
            {"name": "run_shell", "description": "Run a shell command",
             "parameters": {"type": "object",
                            "properties": {"command": {"type": "string"}},
                            "required": ["command"]}},
        ])
        self.assertEqual(report["overall_rating"], "critical")
        self.assertEqual(report["tools_audited"], 2)


if __name__ == "__main__":
    unittest.main()
