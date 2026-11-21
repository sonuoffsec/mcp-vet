# Changelog

## Unreleased

### Added
- Read settings from `[tool.mcp-vet]` table in `pyproject.toml`, with `.mcp-vet.toml` taking precedence when both exist in the same directory.

## 0.3.0

Driven by testing against other people's deliberately vulnerable MCP servers (Invariant Labs'
experiments, the Damn Vulnerable MCP Server, the appsecco lab), and by making the tool easier to
adopt.

### Added
- **`mcp-vet --clients`** finds the MCP client configs on your machine (Claude Desktop, Cursor,
  VS Code, Windsurf, Claude Code) and scans them. Files are only read; nothing leaves the machine.
- **`.mcp-vet.toml` config file:** `fail_on`, `min_severity`, `ignore`, `disable`, `include_tests`
  and per-rule `[severity]` overrides. Command-line flags win. Typos are errors with a suggestion.
- **Baselines:** `--write-baseline FILE` accepts today's findings and `--baseline FILE` reports only
  new ones, matching on rule, file and code (not line number).
- **GitHub Action** (`action.yml`): runs the scan, prints the report, writes SARIF, optionally uploads it
  to code scanning. The repository's CI tests it against both example servers.
- **MCP012** hardcoded credentials (secret-named literals that look generated, URLs with passwords,
  bearer tokens, JWTs). **MCP013** obfuscated base64 string tables. **MCP014** unpinned `npx`/`uvx`
  launchers in client configs.
- Hidden instructions in HTML comments and `SYSTEM INSTRUCTION:` payloads (MCP002); hyphenated
  `sk-...` style keys (MCP003).
- Python: tools dispatched by name (a function named after a tool in a schema is treated as a tool
  handler), `asyncio.create_subprocess_exec/shell`, and a fixed interpreter handed caller input
  (`["python", "-c", code]`, `spawn("node", ["-e", code])`).
- A fixed-host URL (`https://api.example.org/{id}`) is now LOW instead of MEDIUM for SSRF (MCP009):
  only the path is controlled.
- CONTRIBUTING guide, issue templates, `examples/README.md`.

### Fixed
- The credential rule first produced 284 false positives on 67 real repositories. It now looks for
  generated-looking values and skips translations, lock files, CI and compose files, test tooling,
  placeholders, labels, environment-variable names and comments (12 remain, reviewed by hand).

### Changed
- The vulnerable example's client config pins its package version so it still shows exactly the
  findings the examples guide describes.

## 0.2.2

### Changed
- **A redesigned terminal report.** The default text output now has a header, a summary of what
  was scanned (target, rules loaded, files, start time, duration), a findings summary by severity,
  a details table, a recommendation and a footer, matching the image in the README.
  Critical and high findings are always listed; `--limit N` (default 10) caps only the weaker ones
  and `--all` lists everything.
- The target is printed as typed, not as an absolute path, so pasted output does not reveal your
  directory layout.

### Added
- `-v` / `--verbose` shows the offending code for each finding and a "How to fix" section per rule.
- `--limit N`, `--all` and `--no-color` (the `NO_COLOR` variable is honoured too).
- New README banner and terminal images.

### Fixed
- The CLI no longer fails when its output stream cannot be reconfigured (captured or wrapped
  stdout).
- The README no longer describes JavaScript/TypeScript analysis as pattern-based.
- JSON and SARIF output are unchanged.

## 0.2.1

Precision fixes found by rescanning real servers. No new rules.

**Packaging:** published on PyPI as `mcp-vet-scanner` (`pip install mcp-vet-scanner`). The name `mcp-vet`
is blocked there as too similar to an unrelated project, so only the PyPI name differs: the
command is still `mcp-vet`, the Python module `mcp_vet`, and the repository `sonuoffsec/mcp-vet`.

- A helper that only calls other clean helpers is now clean (the "does it return its inputs?"
  analysis runs to a fixpoint), in both languages.
- JS/TS: `def.fields.map((f) => id(f.column))` is recognized when the callback escapes the
  element; `db.query({ text, values })` only treats `text` as SQL, so tainted values in the
  bound-values array no longer count.
- Python: list, set, dict comprehensions and generator expressions are tainted only when their
  element expression uses the loop variable without a sanitizer.
- The recall suite grew to 120 vulnerable expectations and 82 safe cases.

## 0.2.0

### Added
- **JavaScript and TypeScript analysis.** A dependency-free tokenizer and scope-aware analyzer
  replaces the old line patterns for `.js .mjs .cjs .ts .tsx .jsx .mts .cts`. It finds tool
  handlers (`server.tool`, `registerTool`, `setRequestHandler`) and HTTP routes (Express, Fastify),
  follows tool arguments through assignments, and reports command execution, file access,
  outbound requests and SQL built from input. It understands `import { a as b }`,
  `require`, `promisify(exec)`, `execa`, `shelljs`, and Zod schemas that constrain an input
  (`z.enum`, `z.number`, `z.string().uuid()`).
- **MCP010** SQL built from tool input, and **MCP011** unsafe deserialization (`pickle`,
  `marshal`, unsafe `yaml.load`, `node-serialize`).
- Python: HTTP route handlers (FastAPI, Flask) are treated as entry points; one-hop tracking into
  helper functions in the same file; many more file operations and command forms
  (`os.remove`, `shutil.*`, `subprocess.run(x.split())`, `["sh", "-c", x]`, `os.exec*`).
- Helper-function tracking in both languages: a helper's *return value* is analyzed (a query
  builder that returns `?` placeholders yields a clean value), and findings are reported per
  *parameter*, so a helper that receives a constant URL and a tainted body is not flagged.
- Recognized safe idioms: allowlist validation (`ALLOWED.includes(x)`, `x not in ALLOWED`) applies
  to derived names too; `items.map(() => '?')`, `'?'.repeat(n)`; identifier escapers under any
  name (`const id = pg.escapeIdentifier`); a ternary's value comes from its branches only.
- Per-app scoping of authentication and path-guard detection.
- A recall suite (`tests/recall_cases*.py`) with vulnerable snippets and safe twins, and CI.
- `--include-tests` flag. Test files and fixture directories are skipped by default.

### Fixed
- Hidden-Unicode rule no longer flags emoji sequences, right-to-left and Indic text, or code
  that strips zero-width characters.
- Placeholder secrets, reads of `.env`, `send_from_directory`, ORM statements and
  allowlist-validated inputs are no longer reported.
- Methods called on call-chained receivers such as `Path(x).read_text()` were being missed.

### Changed
- JS/TS file-read findings from the analyzer are MEDIUM (taint-verified). The older pattern
  fallback, used only when a file cannot be tokenized, stays LOW.
- A guard in a different file no longer silences a file-read finding.

## 0.1.0
- Initial release: eight rules, text / JSON / SARIF output, Python AST taint tracking.
