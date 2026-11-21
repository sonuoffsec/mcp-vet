# Changelog

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
