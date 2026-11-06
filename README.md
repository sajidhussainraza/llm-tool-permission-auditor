# LLM Tool Permission Auditor

An LLM agent is only as safe as the tools it can call. Hand an agent one
unconstrained `run_shell` or `delete_file` tool and a prompt injection
stops being a chatbot problem and becomes a real incident. This auditor
checks the tool definitions you give an agent **before** it ever runs, and
flags over-privileged tools with a risk rating and a least-privilege fix.

## What it checks

- **Dangerous capabilities** in a tool's name or description: arbitrary
  command execution, destructive operations (delete/drop/truncate),
  money or message movement (send/pay/transfer), and writes/publishes.
- **Unconstrained sensitive parameters**: free-form strings for paths,
  URLs, recipients, amounts, accounts, credentials, raw SQL, or raw
  commands, with no `enum`, `pattern`, or allow-list to bound them.
- **Optional sensitive parameters** that the model may omit or improvise.

Each tool gets a rating: `safe`, `low`, `medium`, `high`, or `critical`,
plus a score and a concrete fix for every finding.

## Usage

Standard library only. No network access, no API keys.

```bash
python llm_tool_auditor.py sample_tools.json
python llm_tool_auditor.py sample_tools.json --json
python llm_tool_auditor.py sample_tools.json --fail-on critical  # CI gate
```

`sample_tools.json` uses the common OpenAI-style function format:
`{"name": ..., "description": ..., "parameters": {"type": "object",
"properties": {...}, "required": [...]}}`. A list, or an object with a
`"tools"` key, both work.

## Example output

Auditing the included `sample_tools.json` (5 tools) gives an overall
`CRITICAL` rating: `run_shell` and `delete_user_record` are critical,
`send_email` is high, `search_docs` is medium (unconstrained `query`),
and the enum-constrained `get_weather` is safe. `--fail-on critical`
exits non-zero, so the check can gate a CI pipeline.

## As a library

```python
from llm_tool_auditor import audit_tools

report = audit_tools(json.load(open("my_tools.json")))
print(report["overall_rating"])  # e.g. "critical"
```

## Tests

```bash
python -m unittest test_auditor -v   # 5 tests, all passing
```

## Why this matters

Prompt-injection defences guard what the model is *told*. This guards
what the model is *allowed to do*. Least privilege for agent tools is
the cheapest AI-security control there is: audit the schema, shrink the
scope, and confirm the backend enforces the same limits the schema
promises.

## License

MIT.
