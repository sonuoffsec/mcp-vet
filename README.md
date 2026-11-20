# mcp-vet

Static security scanner for **MCP (Model Context Protocol) servers**. Point it at a server's source or config and it flags the problems that let an attacker hijack an AI agent.

Zero dependencies. One command. Works in CI.

```text
$ mcp-vet examples/vulnerable-server

server.py
  CRITICAL MCP003  line 8   Hardcoded secret
  HIGH     MCP002  line 15  Possible tool poisoning / hidden instructions
  HIGH     MCP001  line 26  Shell or dynamic code execution
  MEDIUM   MCP005  line 32  Unrestricted file read in tool
  HIGH     MCP004  line 37  Network transport without authentication
mcp-config.json
  HIGH     MCP007  line 5   Overly broad filesystem scope

Summary: 1 CRITICAL, 6 HIGH, 1 MEDIUM, 3 LOW
```

## Why

An MCP server lets an AI take real actions: read files, run commands, call APIs. A weak server can leak data or run an attacker's instructions, and most people install them without reading the code. mcp-vet is a linter for that gap.

## Install

```bash
git clone https://github.com/sonuoffsec/mcp-vet && cd mcp-vet
pip install -e .              # needs Python 3.9+, no other dependencies
mcp-vet --version
```

Or run it without installing: `PYTHONPATH=src python -m mcp_vet ./my-server`.

## Use

```bash
mcp-vet ./my-server                      # human-readable report
mcp-vet ./my-server -f json -o out.json  # machine-readable
mcp-vet ./my-server -f sarif -o out.sarif  # GitHub code scanning
mcp-vet ./my-server --fail-on MEDIUM     # CI gate (default: HIGH)
mcp-vet --list-rules
```

Exit code is `1` when a finding at or above `--fail-on` exists, `2` on usage errors, otherwise `0`.

## Rules

| ID | Severity | What it catches |
|---|---|---|
| MCP001 | HIGH / MEDIUM | Shell or dynamic code execution. **Python:** HIGH only when a tool argument reaches `shell=True`, `os.system`, `eval` or chooses the program; MEDIUM if the command is non-constant but not tool-controlled; constants are ignored. **JS/TS:** pattern-based |
| MCP002 | HIGH | Tool poisoning: instructions aimed at the model hidden in descriptions or code |
| MCP003 | CRITICAL | Hardcoded secrets (AWS, GitHub, OpenAI/Anthropic-style keys, Slack, private keys). Output is redacted |
| MCP004 | HIGH | HTTP/SSE transport with no authentication anywhere in the project, especially when bound to `0.0.0.0` |
| MCP005 | MEDIUM | Tool argument controls a file path with no containment check (path traversal) |
| MCP006 | LOW | Unpinned dependencies (`requirements.txt`, `package.json`) |
| MCP007 | HIGH | MCP config granting access to `/`, `~` or a whole drive |
| MCP008 | HIGH | Hidden Unicode (zero-width, bidi, tag characters) that can conceal instructions. In `.md`/`.txt` only bidi overrides, tag characters and runs of 3+ zero-width characters count, so Persian, Thai and emoji text is not flagged |
| MCP009 | MEDIUM | Tool argument controls the URL of an outbound request (SSRF) |

## Suppress a finding

```python
os.system(cmd)  # mcp-vet: ignore MCP001
```

Omit the rule ID to suppress every rule on that line.

## GitHub Action

```yaml
- run: pip install git+https://github.com/sonuoffsec/mcp-vet
- run: mcp-vet . -f sarif -o mcp-vet.sarif --fail-on HIGH
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: mcp-vet.sarif }
```

## How it works

- **Python files are parsed into an AST** and checked with simple taint tracking. Values that come from a tool's parameters are "tainted". Taint follows assignments, and calls to functions named like `validate`, `sanitize`, `safe`, `check`, `allow` or `quote` (for example `shlex.quote`) clear it. A tool that runs a constant command is not flagged.
- **JS/TS and config files use patterns.** There is no JS parser yet, so JS findings are noisier than Python ones.
- **Authentication and path guards are looked for across the whole project**, not just in the file with the transport or the file read.
- Test files and test directories are skipped by default (`--include-tests` to scan them).

## Tested on real servers

The scanner was run, statically, on public repos: the official `modelcontextprotocol/servers` and `python-sdk`, `github/github-mcp-server`, and `punkpeye/awesome-mcp-servers`. The first pass produced 859 findings, 849 of them false positives (translated READMEs with Persian and emoji characters, a comment containing the word `eval`, a path-traversal *test*). Each one became a regression test. After the fixes, the remaining findings across those repos are 2 MEDIUM and 8 LOW, all low-risk (a developer-CLI `shell=True` call and unpinned dependency ranges). None were confirmed as vulnerabilities; this was a heuristic scan, not an audit. These repos are mostly well-maintained, so a low count is expected. It says little about how the tool does on a weaker server.

## Limits (read this)

- **Static analysis.** It does not run your server, so runtime-only bugs are missed.
- **Taint tracking is intra-function.** It does not follow a tool argument into another function. A helper that receives tainted data and runs it will not be flagged unless the helper itself looks dangerous. Sanitizer detection is name-based, so a function called `validate_path` that does not validate will be trusted.
- **No JS/TS parser.** Those checks are line patterns.
- **MCP004 and MCP005 trust any auth or guard code in the project.** One unrelated `Authorization` header elsewhere will silence MCP004.
- Only a small, hand-picked set of real servers has been tested, and it was mostly well-maintained code.
- A clean report is not a security guarantee.

## Develop

```bash
python -m unittest discover -s tests
python -m mcp_vet src    # the scanner scans itself
```

The `examples/` folder holds a deliberately vulnerable server and a clean one. Never deploy the vulnerable one.

## Roadmap

- Parse tool schemas and flag over-permissive inputs
- SSRF and unsafe-deserialization rules
- Dependency CVE lookup
- Dataset mode: batch-scan many public servers and emit aggregate statistics
- Prompt-injection guardrail benchmark (companion project)

## Responsible use

- Use mcp-vet on code you own, or code you are authorized to review. It only reads files; it never connects to or executes a server.
- If you find a vulnerability in someone else's project, report it privately to the maintainers and allow a reasonable time (commonly 90 days) before publishing details.
- Findings are heuristic signals, not proof of a vulnerability. Verify each one before acting on it or reporting it.
- Example files in `examples/` are intentionally insecure and use only documentation placeholder credentials. Never deploy them.

## Disclaimer

This is an independent open-source project. It is not affiliated with, endorsed by, or sponsored by Anthropic or the Model Context Protocol project. "MCP" and other names mentioned belong to their respective owners.

The software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A clean scan is not a guarantee that a server is secure.

Found a security problem in mcp-vet itself? See [SECURITY.md](SECURITY.md).

## License

MIT
