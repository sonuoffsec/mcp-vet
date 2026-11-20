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
- **HTTP route handlers count as entry points.** Python functions decorated like `@app.post("/mcp/call")` (FastAPI, Flask) are treated like tool handlers, so hand-rolled MCP-over-HTTP servers are analyzed too.
- **Authentication and path guards are looked for per app**: in the same folder, or any parent folder, that has its own `requirements.txt`, `package.json` or `Dockerfile`. One app's auth does not hide another app's gap.
- **Allowlist checks count.** A parameter tested with `if x not in ALLOWED: return/raise` is treated as validated.
- Test files and test directories are skipped by default (`--include-tests` to scan them).

## Tested on real servers

All runs were static: the code was cloned and read, never executed.

**Precision on 67 small community MCP servers** (about 29,600 files, Python and TypeScript/JavaScript):

- The first pass reported **715 HIGH or CRITICAL findings**. Almost all were false positives: emoji and Persian/Sinhala text flagged as hidden Unicode, code that *reads* `.env` flagged as tool poisoning, Playwright's `$eval` flagged as `eval`, security libraries that contain the very strings they block.
- Each cause was fixed and became a regression test. After tuning, **8 HIGH/CRITICAL findings remain, in 5 repos. I reviewed all 8 by hand and none is a vulnerability**: three are blocklists or defensive examples in security libraries, two are attack payloads in test data, one is defensive prompt text telling the model to treat such phrases as data, one is a test credential, and one is a zero-width character in a docstring.
- The Python path-handling findings (MCP005, MEDIUM) are the most useful tier. I read four in detail: three were real (a tool argument passed straight to `open()`, or only checked with `os.path.isfile`), and one was a false positive that is now fixed (the argument had been checked against an allowlist). Many of these servers are local developer tools where reading a user-supplied path is the point, so "real" here means the rule's condition holds, not that the server is exploitable.

**Recall on a deliberately vulnerable server.** DVAP's MCP lab contains an unauthenticated endpoint, an arbitrary file read and two SSRF calls. **The first version of this scanner found none of them.** It only understood the official SDK's decorators, and one app's auth elsewhere in the repo hid the missing auth. After adding route-handler support and per-app scoping, it finds all of them (plus a further SSRF in a second lab). That is one server, so treat it as a sanity check, not a measured recall rate.

**What this does not show.** The rules were tuned on this same sample, so the precision above is optimistic. None of the 67 servers was malicious, so I have not measured how well tool-poisoning detection (MCP002) works against real attacks beyond the patterns in the tests.

## Limits (read this)

- **Static analysis.** It does not run your server, so runtime-only bugs are missed.
- **Taint tracking is intra-function.** It does not follow a tool argument into another function. A helper that receives tainted data and runs it will not be flagged unless the helper itself looks dangerous. Sanitizer detection is name-based, so a function called `validate_path` that does not validate will be trusted.
- **No JS/TS parser.** Those checks are line patterns.
- **MCP004 and MCP005 trust any auth or guard code in the same app.** One unrelated `Authorization` header in the app will silence MCP004, and an existence check such as `os.path.isfile` is correctly *not* treated as a guard, but a badly written custom one named `validate_path` would be.
- **Recall is measured on one server** (DVAP's MCP lab) and precision on 67 servers that were also used to tune the rules. Expect different results on code that looks unlike these.
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
