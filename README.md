![mcp-vet: vet your MCP servers before your AI trusts them](https://raw.githubusercontent.com/sonuoffsec/mcp-vet/main/assets/banner.png)

[![CI](https://github.com/sonuoffsec/mcp-vet/actions/workflows/ci.yml/badge.svg)](https://github.com/sonuoffsec/mcp-vet/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-2DD4BF?style=flat-square)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3B82F6?style=flat-square)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-2DD4BF?style=flat-square)
![Output: text, JSON, SARIF](https://img.shields.io/badge/output-text%20%7C%20JSON%20%7C%20SARIF-3B82F6?style=flat-square)

Static security scanner for **MCP (Model Context Protocol) servers** written in **Python, JavaScript and TypeScript**. Point it at a server's source or config and it flags the problems that let an attacker hijack an AI agent: tool poisoning, command injection, path traversal, SSRF, SQL injection, unsafe deserialization, leaked secrets and unauthenticated transports.

Zero dependencies. One command. Works in CI.

![Terminal output of mcp-vet scanning a deliberately vulnerable MCP server: one critical, five high, two medium and three low findings](https://raw.githubusercontent.com/sonuoffsec/mcp-vet/main/assets/terminal.png)

<sub>A stylised rendering of the report. The total (11 findings: 1 critical, 5 high, 2 medium, 3 low) comes from a real run on `examples/vulnerable-server`; the rule count (the tool now has 14), version number, scan time and clock time are illustrative. A real run always lists every critical and high finding, so it shows more rows than this image; `--limit 5` shortens the list for the weaker ones.</sub>

## Why

An MCP server lets an AI take real actions: read files, run commands, call APIs. A weak server can leak data or run an attacker's instructions, and most people install them without reading the code. mcp-vet is a linter for that gap.

## Install

```bash
pip install mcp-vet-scanner   # needs Python 3.9+, no other dependencies
mcp-vet --version             # the command is `mcp-vet`
```

The PyPI package is called `mcp-vet-scanner` because `mcp-vet` is too similar to an unrelated project already on PyPI. The command, the repository and the Python module are all `mcp-vet`.

From source:

```bash
git clone https://github.com/sonuoffsec/mcp-vet && cd mcp-vet
pip install -e .
```

### Run it without installing

```bash
uvx --from mcp-vet-scanner mcp-vet ./my-server           # with uv
pipx run --spec mcp-vet-scanner mcp-vet ./my-server      # with pipx
```

Both fetch the package into a temporary environment and run the `mcp-vet` command. (`pipx run mcp-vet-scanner` on its own does not work, because the package and the command have different names.) From a clone you can also run `PYTHONPATH=src python -m mcp_vet ./my-server`.

## Use

```bash
mcp-vet ./my-server                        # the report shown above
mcp-vet ./my-server -v                     # also show the offending code and how to fix each rule
mcp-vet ./my-server --all                  # list every finding (default: up to 10, never hiding critical or high)
mcp-vet ./my-server --limit 5              # shorter list of the weaker findings
mcp-vet ./my-server -f json -o out.json    # machine-readable
mcp-vet ./my-server -f sarif -o out.sarif  # GitHub code scanning
mcp-vet ./my-server --fail-on MEDIUM       # CI gate (default: HIGH)
mcp-vet --list-rules
```

The report is colourised on a terminal. Colour is off when the output is piped or written to a file, with `--no-color`, or when the `NO_COLOR` environment variable is set. JSON and SARIF output never change with these display options.

Exit code is `1` when a finding at or above `--fail-on` exists, `2` on usage errors, otherwise `0`.

### Scan the MCP servers you already use

Claude Desktop, Cursor, VS Code, Windsurf and Claude Code each keep a config file that says which MCP servers to launch. One command finds the ones on your machine and checks them:

```bash
mcp-vet --clients
```

It only **reads** those files and prints findings (secrets are masked, and your home folder is shown as `~`); nothing is sent anywhere. It flags servers launched with no version (`npx -y some-package` downloads and runs whatever is newest every time the client starts), filesystem servers given your whole disk, and credentials written into the config. You can also point it at one file: `mcp-vet ~/.cursor/mcp.json`.

### Configure it

Put a `.mcp-vet.toml` in the project (mcp-vet looks in the scanned folder and up to four folders above it):

```toml
fail_on = "MEDIUM"                 # exit 1 at or above this severity
min_severity = "LOW"               # hide findings below this
ignore = ["legacy/**", "vendor"]   # paths, as shown in the report
disable = ["MCP006"]               # rules to turn off
include_tests = false

[severity]
MCP009 = "LOW"                     # change a rule's severity, or "OFF"
```

Python projects can also use a `[tool.mcp-vet]` table in `pyproject.toml` with the same keys:

```toml
[tool.mcp-vet]
fail_on = "MEDIUM"
min_severity = "LOW"
ignore = ["legacy/**", "vendor"]
disable = ["MCP006"]
include_tests = false

[tool.mcp-vet.severity]
MCP009 = "LOW"
```

If both files exist in the same folder, `.mcp-vet.toml` wins.

Flags on the command line always win over the file. A typo is an error with a suggestion (`unknown setting 'fail-on' (did you mean 'fail_on'?)`), never silently ignored. `--config FILE` picks a file explicitly and `--no-config` ignores it.

### Adopt it on an existing project

A first scan of a mature codebase can be long. Record what is there today, then fail the build only on *new* findings:

```bash
mcp-vet . --write-baseline .mcp-vet-baseline.json   # accept everything that exists now
mcp-vet . --baseline .mcp-vet-baseline.json         # report and gate on new findings only
```

A finding's identity is its rule, file and offending code, not its line number, so moving code around does not bring accepted findings back, and fixing the code retires the entry. The report says how many accepted findings were hidden, so they are never forgotten silently.

## Rules

Each rule has a page under [docs/rules](docs/rules/index.md) with what it detects, a
vulnerable and a fixed example, the patterns it deliberately leaves alone and its known
limits. The examples are checked against the analyzer by `tests/test_rule_docs.py`.

| ID | Severity | What it catches |
|---|---|---|
| MCP001 | HIGH / MEDIUM | Shell or dynamic code execution. **Python:** HIGH only when a tool argument reaches `shell=True`, `os.system`, `eval` or chooses the program; MEDIUM if the command is non-constant but not tool-controlled; constants are ignored. **JS/TS:** HIGH when a tool argument reaches `exec`, `eval`, `new Function` or a shell `spawn`; MEDIUM when a command is non-constant |
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
| MCP012 | HIGH | Hardcoded credential: a secret-named variable or key given a literal that looks generated, a URL with a password, a bearer token or a JWT in code. Placeholders, labels, translations, environment-variable names, lock files, CI and compose files and test tooling are ignored. Output is masked |
| MCP013 | MEDIUM | Obfuscated strings: eight or more base64-encoded text strings in one file, a way of hiding URLs, tool names and payloads |
| MCP014 | MEDIUM | An MCP client config launches a package with no version (`npx -y pkg`, `uvx pkg`), so every start runs whatever is newest |

## Suppress a finding

```python
os.system(cmd)  # mcp-vet: ignore MCP001
```

Omit the rule ID to suppress every rule on that line.

## GitHub Action

```yaml
# .github/workflows/mcp-vet.yml
name: mcp-vet
on: [push, pull_request]
permissions:
  contents: read
  security-events: write        # only needed for upload-sarif
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sonuoffsec/mcp-vet@v1
        with:
          path: .
          fail-on: HIGH
          upload-sarif: true     # findings appear in the repository's Security tab
```

The step prints the report in the log, fails the job at `fail-on`, and writes a SARIF file. Inputs: `path`, `fail-on`, `min-severity`, `package` (pin a version, for example `mcp-vet-scanner==0.3.1`), `sarif-file`, `upload-sarif`, `extra-args`. The repository's own CI runs this action against both example servers and requires the vulnerable one to fail.

## How it works

- **Python files are parsed into an AST** and checked with simple taint tracking. Values that come from a tool's parameters are "tainted". Taint follows assignments, and calls to functions named like `validate`, `sanitize`, `safe`, `check`, `allow` or `quote` (for example `shlex.quote`) clear it. A tool that runs a constant command is not flagged.
- **JavaScript and TypeScript get their own analyzer**, with no dependencies. A tokenizer (strings, template literals, comments, regex literals) feeds a scope-aware pass that finds tool handlers (`server.tool`, `registerTool`, `setRequestHandler`) and HTTP routes (Express, Fastify), follows tool arguments through assignments and destructuring, and understands `import { a as b }`, `require`, `promisify(exec)`, `execa`, `shelljs` and Zod schemas that constrain an input (`z.enum`, `z.number`, `z.string().uuid()`). It also knows that a ternary's value comes only from its branches, that an equality test yields a boolean, and that `ORDERS[args.sort]` returns a value the caller does not control. It is a purpose-built analyzer, not a full JavaScript parser: a file it cannot tokenize falls back to line patterns, reported at lower confidence.
- **Config and manifest files** (`package.json`, `requirements.txt`, MCP client config) are checked with direct rules.
- **HTTP route handlers count as entry points.** Python functions decorated like `@app.post("/mcp/call")` (FastAPI, Flask) are treated like tool handlers, so hand-rolled MCP-over-HTTP servers are analyzed too.
- **Authentication and path guards are looked for per app**: in the same folder, or any parent folder, that has its own `requirements.txt`, `package.json` or `Dockerfile`. One app's auth does not hide another app's gap.
- **Allowlist checks count.** A parameter tested with `if x not in ALLOWED: return/raise`, or looked up with `if registry.get(x) is None: raise`, is treated as validated. A filesystem existence check (`os.path.exists`, `isfile`) is not.
- **One hop into helpers.** If a tool passes a tool argument to a plain function defined in the same file, and that function runs a command, opens a path or makes a request, the tool's call is reported.
- **Wide sink coverage.** File operations include `open`, `Path(...).read_text/unlink/...`, `os.remove/listdir/rename`, `shutil.copy/rmtree/move` and `send_file`. Command execution includes `os.system`, `subprocess` with `shell=True`, a caller-chosen program (`cmd.split()`, `shlex.split`), `os.exec*` and `__import__('os').system`.
- Test files and test directories are skipped by default (`--include-tests` to scan them).

## Tested on real servers

All runs were static: the code was cloned and read, never executed.

**Precision on 67 small community MCP servers** (about 29,500 files in Python, JavaScript and TypeScript):

- The first pass (v0.1) reported **715 HIGH or CRITICAL findings**. Almost all were false positives: emoji and Persian/Sinhala text flagged as hidden Unicode, code that *reads* `.env` flagged as tool poisoning, Playwright's `$eval` flagged as `eval`, security libraries that contain the very strings they block. Each cause was fixed and became a regression test.
- Today there are **12 HIGH or CRITICAL findings in 6 repos**. Eight of them I reviewed by hand and **none is a vulnerability**: blocklists and defensive examples in security libraries, attack payloads in test data, defensive prompt text, a test credential, and a zero-width character in a docstring. The other **4 are SQL findings (MCP010) in a single repo**, a low-code platform that executes SQL stored in its application configuration by design. I traced six more findings in that repo to code that is escaped (`pg.escapeIdentifier`) or parameterized and fixed the analyzer for those patterns. The remaining four run configured SQL, and the analyzer cannot tell configuration from request data once both pass through a context object, so I have **not** confirmed whether any of them is exploitable.
- The file-path findings (MCP005, MEDIUM) are the most useful tier: **40 findings in 8 repos**. I checked 24 of them (the flagged line and its enclosing function): 22 were a tool argument deciding where a file is read, written, copied, listed or deleted (`save_to`, `world_path`, `directory`, `filePath`, `session_id`), and 2 were false positives (validated by a registry lookup; guarded by the caller), both fixed. I did not read all 40. Many of these servers are local developer tools where choosing a path is the point, so "real" means the rule's condition holds, not that the server is exploitable.
- Two further JavaScript findings I read and confirmed: a tool that reads an arbitrary caller-supplied file path, and a tool that fetches a caller-supplied URL (`faucetUrl: z.string().url()` checks the format only).
- When the JS/TS analyzer was first enabled it reported **391 JS findings against 102 from the old patterns**. Nearly all of the 337 new ones were false positives: `/regex/.exec()` mistaken for `child_process.exec`, SQL fragments built from a ternary of constants, `ORDERS[args.sort]` allowlist lookups, query-builder helpers that return `?` placeholders, `items.map(() => '?')`, `pg.escapeIdentifier` under another name. Each was fixed and tested, and the JS/TS count is now **72**.
- The SQL rule first reported 23 findings on one Python repo, **all false positives** (SQLAlchemy ORM statements). It now only flags SQL built by string formatting, or a query passed in whole by the caller.
- The official `modelcontextprotocol/servers` repo (TypeScript) produces **no findings** other than four unpinned workspace dependencies, and the Python SDK produces two MEDIUM `shell=True` calls in its developer CLI.

**Recall on a deliberately vulnerable server.** DVAP's MCP lab contains an unauthenticated endpoint, an arbitrary file read and two SSRF calls. **The first version of this scanner found none of them.** It only understood the official SDK's decorators, and one app's auth elsewhere in the repo hid the missing auth. After adding route-handler support and per-app scoping, it finds all of them (plus a further SSRF in a second lab). That is one server, so treat it as a sanity check, not a measured recall rate.

**Recall on other people's attack code.** The cases I write myself prove little, so I also scanned four public, deliberately vulnerable projects: Invariant Labs' original tool-poisoning experiments, the Damn Vulnerable MCP Server (15 challenges), the appsecco vulnerable-servers lab (9 servers) and DVAP. I counted a result only when a finding matches the flaw the project says it teaches, not when it merely reports something incidental such as a demo password.

| Project | Caught | Partly | Not caught |
|---|---|---|---|
| Invariant Labs tool-poisoning attacks (3) | 3 | | |
| Damn Vulnerable MCP Server (15 challenges) | 8 | 2 | 5 |
| appsecco vulnerable servers (9) | 3 | 1 | 5 |

That is **14 of 27 designed vulnerabilities caught, 3 partly, 10 not**: about half. Testing against these projects is what found the hidden-instruction-in-an-HTML-comment gap, the hyphenated-key and generic-credential gaps, name-dispatched tool handlers and `python -c <code>`, and the obfuscated string table (each is now a rule or a test case). Before those fixes the counts were lower.

What it does **not** catch is consistent, and it is not a matter of tuning, because none of it is visible in source code: authorization flaws (a hidden `on_behalf_of` parameter, IDOR, privilege-escalation workflows), prompt injection that arrives in data a server fetches at runtime (a Wikipedia page, a retrieved document), tools that change behaviour after a number of calls, and supply-chain facts (a typosquatted package name, outdated dependencies with known CVEs, a misconfigured package resolver). Treat mcp-vet as one layer, not the whole review.

**Recall suite.** `tests/recall_cases.py` and `tests/recall_cases_js.py` hold 139 vulnerable snippets (each must trigger its rule) and 107 safe twins (none may produce a MEDIUM or higher finding), 67 and 51 of them JavaScript or TypeScript. It runs with the tests, and `python tests/test_recall.py` prints a per-rule table. A lesson from building it: the first version scored 37 of 37, which proved little, because I wrote the cases knowing how the scanner works. A probe with 18 harder Python variants (`os.remove`, `shutil.copy`, `subprocess.run(x.split())`, `pickle.loads`, a tainted value passed through a helper, `__import__('os').system`...) found that **13 of 18 were missed**, and a probe with 21 harder JS variants found 4 misses and 1 false positive. Those drove the file-operation, command-construction, helper-tracking, SQL, deserialization, alias-resolution and Zod work, and every variant is now a permanent test case. The suite measures known bug classes and regressions, not unknown ones.

**What this does not show.** The rules were tuned on this same sample, so the precision above is optimistic. None of the 67 servers was malicious. Tool-poisoning detection (MCP002) caught all of Invariant Labs' original attacks and the poisoning challenges in the other labs, but those are public, well-known examples, and a determined attacker can word instructions differently.

## Limits (read this)

- **Static analysis.** It does not run your server, so runtime-only bugs are missed.
- **Taint tracking is shallow.** It follows assignments inside a function and one call into a helper defined in the same file. It does not follow data across files, through classes, or two helpers deep. Sanitizer detection is name-based (`validate`, `sanitize`, `safe`, `resolve_`, `quote`...), so a function called `validate_path` that does not validate will be trusted.
- **Not covered:** XSS, authorization logic, race conditions, prototype pollution, and logic flaws in how a tool uses the model's output. Unsafe deserialization in JS/TS is limited to `node-serialize`.
- **The JS/TS analyzer is not a full parser.** It will miss taint that flows through classes, `.map` callbacks or dynamic property access, and it can be fooled by unusual code layout. Files over about 600 KB, `.d.ts` files and minified bundles are not analyzed.
- **MCP004 and MCP005 trust any auth or guard code in the same app.** One unrelated `Authorization` header in the app will silence MCP004, and an existence check such as `os.path.isfile` is correctly *not* treated as a guard, but a badly written custom one named `validate_path` would be.
- **Precision was measured on 67 servers that were also used to tune the rules**, and recall on a handful of public attack labs plus cases I wrote. Expect different results on code that looks unlike these.
- **The credential rule (MCP012) is a heuristic.** It looks for generated-looking values, so a short or word-like real password will be missed, and a random-looking constant that is not secret will be reported. Suppress those with `# mcp-vet: ignore MCP012`.
- A clean report is not a security guarantee.

## Develop

```bash
python -m unittest discover -s tests     # all tests, including the recall suite
python tests/test_recall.py              # per-rule recall table
python -m mcp_vet src                    # the scanner scans itself
```

The `examples/` folder holds a deliberately vulnerable server and a clean one. Never deploy the vulnerable one.

## Roadmap

Ideas, not promises:

- Taint tracking across files and through classes
- Dependency CVE lookup (for example against OSV)
- Flag tool responses that carry untrusted data without marking it as data
- More independent test projects, and publishing the recall corpus as a reusable benchmark

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). The most useful ones are false-positive and missed-vulnerability reports.

## Responsible use

- Use mcp-vet on code you own, or code you are authorized to review. It only reads files; it never connects to or executes a server.
- If you find a vulnerability in someone else's project, report it privately to the maintainers and allow a reasonable time (commonly 90 days) before publishing details.
- Findings are heuristic signals, not proof of a vulnerability. Verify each one before acting on it or reporting it.
- Example files in `examples/` are intentionally insecure and use only documentation placeholder credentials. Never deploy them.

## Disclaimer

This is an independent open-source project. It is not affiliated with, endorsed by, or sponsored by Anthropic or the Model Context Protocol project, and it is unrelated to the PyPI project `mcpvet`, which is a different tool. "MCP" and other names mentioned belong to their respective owners.

The software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A clean scan is not a guarantee that a server is secure.

Found a security problem in mcp-vet itself? See [SECURITY.md](SECURITY.md).

## License

MIT
