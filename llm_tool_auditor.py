#!/usr/bin/env python3
"""LLM Tool Permission Auditor.

Audit the tools (function definitions) you hand to an LLM agent and flag
over-privileged ones *before* the agent ever runs. An agent is only as safe
as the tools it can call: one unconstrained ``run_shell`` or ``delete_file``
tool turns a prompt injection into a real incident.

The auditor reads tool definitions in the common OpenAI-style format:

    {"name": "search_docs", "description": "...",
     "parameters": {"type": "object", "properties": {...}}}

and produces a per-tool risk rating plus least-privilege fixes.

Standard library only. No network access, no API keys.

Usage:
    python llm_tool_auditor.py sample_tools.json
    python llm_tool_auditor.py sample_tools.json --json
    python llm_tool_auditor.py sample_tools.json --fail-on critical
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------- patterns

# (regex on tool name / description, severity, message, fix)
DANGEROUS_PATTERNS = [
    (r"\b(shell|bash|sh|cmd|exec|eval|subprocess|system)\b", "critical",
     "Executes arbitrary commands on the host.",
     "Remove this tool, or replace it with a narrow allow-listed command set."),
    (r"\b(delete|remove|drop|truncate|destroy|wipe|purge)\b", "critical",
     "Destructive operation (deletes data, tables, or files).",
     "Require human confirmation and restrict targets to an allow-list."),
    (r"\b(send|transfer|pay|charge|withdraw|purchase|order)\b", "high",
     "Moves money, messages, or goods to an external party.",
     "Add amount/recipient allow-lists and a confirmation step."),
    (r"\b(write|save|upload|publish|post|create|update|insert)\b", "medium",
     "Writes or publishes data outside the agent's own context.",
     "Scope writes to one directory, bucket, or channel and validate input."),
    # Read-only verbs (read/get/fetch/search) are intentionally NOT listed:
    # a read-only tool with constrained parameters is safe, and its risk
    # comes from unconstrained sensitive parameters, checked below.
]

# Parameter names that are sensitive when unconstrained (free-form string).
SENSITIVE_PARAMS = {
    "path": "filesystem path",
    "filepath": "filesystem path",
    "filename": "filesystem path",
    "url": "external URL",
    "email": "email address",
    "recipient": "recipient",
    "to": "recipient",
    "amount": "money amount",
    "account": "account identifier",
    "password": "credential",
    "token": "credential",
    "api_key": "credential",
    "query": "raw query (possible injection surface)",
    "sql": "raw SQL (injection surface)",
    "command": "raw command (injection surface)",
}

SEVERITY_SCORE = {"critical": 40, "high": 25, "medium": 10, "low": 3}


@dataclass
class Finding:
    severity: str
    message: str
    fix: str = ""


@dataclass
class ToolReport:
    name: str
    score: int = 0
    rating: str = "safe"
    findings: list = field(default_factory=list)

    def add(self, finding):
        self.findings.append(finding)
        self.score += SEVERITY_SCORE[finding.severity]


def _rating(score):
    if score >= 40:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    if score > 0:
        return "low"
    return "safe"


def audit_tool(tool):
    """Audit one tool definition dict; return a ToolReport."""
    name = tool.get("name", "<unnamed>")
    text = f"{name} {tool.get('description', '')}".lower()
    report = ToolReport(name=name)

    matched_danger = False
    for pattern, severity, message, fix in DANGEROUS_PATTERNS:
        if re.search(pattern, text):
            report.add(Finding(severity, message, fix))
            matched_danger = True
            break  # strongest matching category only

    params = tool.get("parameters") or {}
    properties = params.get("properties") or {}
    required = set(params.get("required") or [])

    if not properties:
        report.add(Finding(
            "medium",
            "Tool takes no declared parameters or an unconstrained payload.",
            "Declare typed parameters so the model cannot smuggle extra fields."))
    else:
        for param, spec in properties.items():
            spec = spec if isinstance(spec, dict) else {}
            key = param.lower()
            if key in SENSITIVE_PARAMS and spec.get("type") == "string" \
                    and "enum" not in spec and "pattern" not in spec:
                report.add(Finding(
                    "high" if key in ("command", "sql", "password", "token",
                                      "api_key") else "medium",
                    f"Unconstrained sensitive parameter '{param}' "
                    f"({SENSITIVE_PARAMS[key]}).",
                    f"Constrain '{param}' with an enum, pattern, or allow-list."))
            if param not in required and key in SENSITIVE_PARAMS:
                report.add(Finding(
                    "low",
                    f"Sensitive parameter '{param}' is optional, so the model "
                    "may omit or improvise it.",
                    f"Make '{param}' required, or drop it from the schema."))

    if not matched_danger and not report.findings:
        report.add(Finding(
            "low",
            "No dangerous verb or unconstrained sensitive parameter found, "
            "but every tool still deserves a scope review.",
            "Confirm the tool's backend enforces the same scope as its schema."))
        # A clean tool should not carry a penalty: keep the note, drop score.
        report.score = 0

    report.rating = _rating(report.score)
    return report


def audit_tools(tools):
    """Audit a list of tool definitions; return a report dict."""
    if isinstance(tools, dict):
        tools = tools.get("tools", [tools])
    reports = [audit_tool(t) for t in tools]
    total = sum(r.score for r in reports)
    worst = max((r.rating for r in reports),
                key=lambda r: ["safe", "low", "medium", "high",
                               "critical"].index(r),
                default="safe")
    return {
        "tools_audited": len(reports),
        "overall_rating": worst,
        "total_score": total,
        "tools": [
            {"name": r.name, "rating": r.rating, "score": r.score,
             "findings": [{"severity": f.severity, "message": f.message,
                           "fix": f.fix} for f in r.findings]}
            for r in reports
        ],
    }


def render_text(report):
    lines = [f"Tools audited: {report['tools_audited']}  |  "
             f"Overall: {report['overall_rating'].upper()}  |  "
             f"Total score: {report['total_score']}", ""]
    for tool in report["tools"]:
        lines.append(f"[{tool['rating'].upper()}] {tool['name']} "
                     f"(score {tool['score']})")
        for finding in tool["findings"]:
            lines.append(f"  - {finding['severity']}: {finding['message']}")
            if finding["fix"]:
                lines.append(f"    Fix: {finding['fix']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="JSON file with tool definitions "
                        "(a list, or an object with a 'tools' key)")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium",
                                              "low"],
                        help="Exit non-zero if any tool reaches this rating")
    args = parser.parse_args(argv)

    with open(args.file, encoding="utf-8") as handle:
        data = json.load(handle)
    report = audit_tools(data)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report), end="")

    if args.fail_on:
        order = ["safe", "low", "medium", "high", "critical"]
        if order.index(report["overall_rating"]) >= order.index(args.fail_on):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
