# Rule reference

Each rule has a page that says what it detects, a vulnerable and a fixed example, the
patterns it deliberately leaves alone, and its known limits. The pages describe the
scanner as it is, so each example on them is checked against the analyzer by
`tests/test_rule_docs.py` — the vulnerable snippet must produce that rule and the fixed
snippet must produce nothing at HIGH or CRITICAL.

| Rule | Severity | What it catches |
|---|---|---|
| [MCP001](MCP001.md) | HIGH / MEDIUM | Shell or dynamic code execution |
| [MCP002](MCP002.md) | HIGH | Tool poisoning: instructions aimed at the model |
| [MCP003](MCP003.md) | CRITICAL | Hardcoded secret in a known format |
| [MCP004](MCP004.md) | HIGH | Network transport without authentication |
| [MCP005](MCP005.md) | MEDIUM | Unrestricted file read or write in a tool |
| [MCP006](MCP006.md) | LOW | Unpinned dependency |
| [MCP007](MCP007.md) | HIGH | Overly broad filesystem scope |
| [MCP008](MCP008.md) | HIGH | Hidden Unicode characters |
| [MCP009](MCP009.md) | MEDIUM | Tool input controls an outbound request (SSRF) |
| [MCP010](MCP010.md) | HIGH / MEDIUM | SQL built from tool input |
| [MCP011](MCP011.md) | HIGH | Unsafe deserialization of tool input |
| [MCP012](MCP012.md) | HIGH | Hardcoded credential |
| [MCP013](MCP013.md) | MEDIUM | Obfuscated strings |
| [MCP014](MCP014.md) | MEDIUM | Unpinned package launched by a client config |

Severities of `MEDIUM` and below do not fail a scan by default; `--fail-on` changes the
gate. Suppressing one finding, or a whole rule, is described in the
[README](../../README.md#suppress-a-finding).
