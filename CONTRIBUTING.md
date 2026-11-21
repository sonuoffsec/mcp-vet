# Contributing to mcp-vet

Thanks for helping. The most useful contributions are **false-positive and false-negative reports**, because they are how the rules get better.

## Reporting a wrong result

Open an issue using the *False positive* or *Missed vulnerability* template. A good report has:

- the smallest snippet that reproduces it (a few lines is ideal),
- the rule id (for example `MCP005`) and the severity,
- what you expected, and why.

Please **do not** post exploits against someone else's unpatched project. If you found a real vulnerability in a third-party server, tell its maintainers privately first. For a security problem in mcp-vet itself, see [SECURITY.md](SECURITY.md).

## Setting up

```bash
git clone https://github.com/sonuoffsec/mcp-vet && cd mcp-vet
python -m pip install -e .
python -m unittest discover -s tests     # all tests, including the recall suite
python tests/test_recall.py              # per-rule recall table
python -m mcp_vet src                    # the scanner must find nothing in its own source
```

There are no runtime dependencies, and a change should not add one. Python 3.9 must keep working, so avoid syntax newer than 3.9.

## Adding or changing a rule

1. Add the rule to `src/mcp_vet/rules.py` (id, title, severity, message, remediation).
2. Implement the detection: `pyast.py` for Python, `jsflow.py` for JavaScript and TypeScript, `checks.py` for config files and other file-level checks.
3. **Add cases to the recall suite** in `tests/recall_cases.py` or `tests/recall_cases_js.py`:
   - at least one *vulnerable* snippet that must trigger the rule, and
   - at least one *safe twin* that looks similar but must not produce a MEDIUM or higher finding.
4. Run the tests and the self-scan, then describe in the pull request how you checked for false positives on real code.

A rule without safe twins will not be merged. Detecting a bug is easy; staying quiet on correct code is the hard part, and it is what makes people keep a scanner turned on.

## Pull requests

- Keep them small and focused.
- Update `CHANGELOG.md` and the README if behaviour changes.
- Describe what you measured. "I scanned N repositories and the new rule reported M findings, of which K were real" is the most useful sentence you can write.

## Things that are out of scope

mcp-vet is a **static** scanner: it never runs the code it reads. Runtime fuzzing, dependency CVE lookups and authorization-logic review are different tools. The README lists what is and is not covered.
