<p align="center">
  <img src="assets/banner.svg" alt="mcp-vet: vet your MCP servers before your AI trusts them" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2DD4BF?style=flat-square"></a>
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-3B82F6?style=flat-square">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-0-2DD4BF?style=flat-square">
  <img alt="SARIF 2.1.0 output" src="https://img.shields.io/badge/output-text%20%7C%20JSON%20%7C%20SARIF-3B82F6?style=flat-square">
</p>

Static security scanner for **MCP (Model Context Protocol) servers**. Point it at a server's source or config and it flags the problems that let an attacker hijack an AI agent.

Zero dependencies. One command. Works in CI.

<p align="center">
  <img src="assets/terminal.svg" alt="Terminal output of mcp-vet scanning a deliberately vulnerable MCP server: one critical, five high, two medium and three low findings" width="760">
</p>

<sub>The image above is generated from the scanner's real output by <code>assets/build_terminal_svg.py</code>.</sub>

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
| MCP010 | HIGH / MEDIUM | SQL built from tool input: HIGH when a query that looks like SQL is assembled with f-strings, `+`, `%` or `.format`; MEDIUM when the caller passes the whole query. ORM statements such as `select(...).where(...)` are not flagged |
| MCP011 | HIGH | Tool argument passed to an unsafe deserializer (`pickle`, `marshal`, `dill`, `yaml.load` without a safe loader) |

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
- **Allowlist checks count.** A parameter tested with `if x not in ALLOWED: return/raise`, or looked up with `if registry.get(x) is None: raise`, is treated as validated. A filesystem existence check (`os.path.exists`, `isfile`) is not.
- **One hop into helpers.** If a tool passes a tool argument to a plain function defined in the same file, and that function runs a command, opens a path or makes a request, the tool's call is reported.
- **Wide sink coverage.** File operations include `open`, `Path(...).read_text/unlink/...`, `os.remove/listdir/rename`, `shutil.copy/rmtree/move` and `send_file`. Command execution includes `os.system`, `subprocess` with `shell=True`, a caller-chosen program (`cmd.split()`, `shlex.split`), `os.exec*` and `__import__('os').system`.
- Test files and test directories are skipped by default (`--include-tests` to scan them).

## Tested on real servers

All runs were static: the code was cloned and read, never executed.

**Precision on 67 small community MCP servers** (about 29,600 files, Python and TypeScript/JavaScript):

- The first pass reported **715 HIGH or CRITICAL findings**. Almost all were false positives: emoji and Persian/Sinhala text flagged as hidden Unicode, code that *reads* `.env` flagged as tool poisoning, Playwright's `$eval` flagged as `eval`, security libraries that contain the very strings they block.
- Each cause was fixed and became a regression test. After tuning, **8 HIGH/CRITICAL findings remain, in 5 repos. I reviewed all 8 by hand and none is a vulnerability**: three are blocklists or defensive examples in security libraries, two are attack payloads in test data, one is defensive prompt text telling the model to treat such phrases as data, one is a test credential, and one is a zero-width character in a docstring.
- The Python path-handling findings (MCP005, MEDIUM) are the most useful tier: **40 findings in 7 repos**. I read four of the first batch in detail (three real, one false positive, now fixed). When I widened coverage to more file operations (`os.remove`, `shutil.copy`, `Path.unlink`...), 19 more appeared; I checked the flagged line and enclosing function of each. 18 were a tool argument deciding where a file is written, copied, listed or deleted (`save_to`, `world_path`, `directory`, `session_id`), and 1 was a false positive (the argument was validated by a registry lookup), now fixed. I did not read every one of the 40 in full. Many of these servers are local developer tools where choosing a path is the point, so "real" here means the rule's condition holds, not that the server is exploitable.
- The SQL rule first reported 23 findings on one repo, **all false positives** (SQLAlchemy ORM statements, which are not injectable like raw SQL strings). It now only flags SQL built by string formatting, or a query passed in whole by the caller. On these 67 repos it reports nothing for SQL injection or unsafe deserialization.

**Recall on a deliberately vulnerable server.** DVAP's MCP lab contains an unauthenticated endpoint, an arbitrary file read and two SSRF calls. **The first version of this scanner found none of them.** It only understood the official SDK's decorators, and one app's auth elsewhere in the repo hid the missing auth. After adding route-handler support and per-app scoping, it finds all of them (plus a further SSRF in a second lab). That is one server, so treat it as a sanity check, not a measured recall rate.

**Recall suite.** `tests/recall_cases.py` holds 59 vulnerable snippets (each must trigger its rule) and 35 safe twins (none may produce a MEDIUM or higher finding). It runs with the tests, and `python tests/test_recall.py` prints a per-rule table. A lesson from building it: the first version of the suite scored 37 of 37, which proved little because I wrote the cases knowing how the scanner works. A follow-up probe with 18 harder variants (`os.remove`, `shutil.copy`, `subprocess.run(x.split())`, `pickle.loads`, a tainted value passed through a helper, `__import__('os').system`...) found that **13 of 18 were missed**. Those misses drove the file-operation, command-construction, helper-tracking, SQL and deserialization work, and every variant is now a permanent test case. The suite measures known bug classes and regressions, not unknown ones.

**What this does not show.** The rules were tuned on this same sample, so the precision above is optimistic. None of the 67 servers was malicious, so I have not measured how well tool-poisoning detection (MCP002) works against real attacks beyond the patterns in the tests.

## Limits (read this)

- **Static analysis.** It does not run your server, so runtime-only bugs are missed.
- **Taint tracking is shallow.** It follows assignments inside a function and one call into a helper defined in the same file. It does not follow data across files, through classes, or two helpers deep. Sanitizer detection is name-based (`validate`, `sanitize`, `safe`, `resolve_`, `quote`...), so a function called `validate_path` that does not validate will be trusted.
- **Not covered:** XSS, authorization logic, race conditions, prototype pollution, and logic flaws in how a tool uses the model's output. SQL injection and unsafe deserialization are covered for Python only.
- **No JS/TS parser.** Those checks are line patterns.
- **MCP004 and MCP005 trust any auth or guard code in the same app.** One unrelated `Authorization` header in the app will silence MCP004, and an existence check such as `os.path.isfile` is correctly *not* treated as a guard, but a badly written custom one named `validate_path` would be.
- **Recall is measured on one server** (DVAP's MCP lab) and precision on 67 servers that were also used to tune the rules. Expect different results on code that looks unlike these.
- A clean report is not a security guarantee.

## Develop

```bash
python -m unittest discover -s tests
python -m mcp_vet src    # the scanner scans itself
python assets/build_terminal_svg.py    # regenerate the terminal image above
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
