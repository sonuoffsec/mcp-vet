"""Keep `docs/rules/*.md` honest: every example is checked against the analyzer.

Each page has a `## Vulnerable` and a `## Fixed` section. The first fenced block (or
blocks) of the vulnerable section must produce that page's rule, and the fixed section
must not. A page whose example drifts away from the analyzer fails here instead of
misleading a reader.

Placeholders stand in for values a documentation file should not contain — a working
token, a generated password, a hidden character. They are substituted before scanning.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_vet.models import severity_rank  # noqa: E402
from mcp_vet.scanner import scan_text  # noqa: E402

DOCS = ROOT / "docs" / "rules"

PLACEHOLDERS = {
    "{{ZERO_WIDTH}}": chr(0x200B),
    "{{KNOWN_FORMAT_SECRET}}": "TOKEN = '" + "ghp_" + "a1B2c3D4" * 4 + "ZZZZ'",
    "{{GENERATED_PASSWORD}}": "S3cur3P@ssw0rd!2024",
    "{{API_TOKEN}}": "abcdEFGH1234567890abcdefghij",
}

# Fence language -> the filename the analyzer sees. `text` blocks name their file in a
# leading comment, because a requirements or package manifest has to be recognised by name.
LANG_FILES = {
    "python": "a.py",
    "py": "a.py",
    "json": "mcp.json",
    "javascript": "a.js",
    "js": "a.js",
    "typescript": "a.ts",
    "ts": "a.ts",
}
NAME_HINT = re.compile(r"^[#/]+\s*([\w.-]+\.(?:txt|json|js|ts|py|md|ya?ml))\s*$")
FENCE = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
SECTION = re.compile(r"^## (Vulnerable|Fixed)\s*$", re.MULTILINE)


def _substitute(code: str) -> str:
    for token, value in PLACEHOLDERS.items():
        code = code.replace(token, value)
    return code


def _examples(page: Path) -> dict:
    text = page.read_text(encoding="utf-8")
    sections = [(m.group(1), m.start()) for m in SECTION.finditer(text)]
    out = {"Vulnerable": [], "Fixed": []}
    for index, (name, start) in enumerate(sections):
        end = sections[index + 1][1] if index + 1 < len(sections) else len(text)
        body = text[start:end]
        for lang, code in FENCE.findall(body):
            lines = code.splitlines(keepends=True)
            filename = LANG_FILES.get(lang.lower(), "snippet.py")
            if lines:
                hint = NAME_HINT.match(lines[0].strip())
                if hint:
                    filename = hint.group(1)
                    lines = lines[1:]
            out[name].append((filename, _substitute("".join(lines))))
    return out


def _pages() -> list:
    return sorted(DOCS.glob("MCP*.md"))


def _findings(filename: str, code: str) -> list:
    return scan_text(filename, code, filename)


class RuleDocs(unittest.TestCase):
    def test_every_rule_has_a_page(self):
        from mcp_vet.rules import RULES
        documented = {p.stem for p in _pages()}
        self.assertEqual(sorted(documented), sorted(RULES),
                         "each rule needs docs/rules/<id>.md")

    def test_page_shape(self):
        problems = []
        for page in _pages():
            text = page.read_text(encoding="utf-8")
            for heading in ("## Vulnerable", "## Fixed", "## Deliberately not flagged",
                            "## Known limits"):
                if heading not in text:
                    problems.append(f"{page.name}: missing '{heading}'")
            if not text.startswith(f"# {page.stem}: "):
                problems.append(f"{page.name}: title must start with '# {page.stem}: '")
        self.assertEqual(problems, [], "\n  ".join([""] + problems))

    def test_vulnerable_examples_are_detected(self):
        misses = []
        for page in _pages():
            rule = page.stem
            blocks = _examples(page)["Vulnerable"]
            if not blocks:
                misses.append(f"{rule}: no vulnerable example")
                continue
            for filename, code in blocks:
                if rule not in {f.rule_id for f in _findings(filename, code)}:
                    misses.append(f"{rule}: {filename} example did not produce {rule}")
        self.assertEqual(misses, [], "\n  ".join([""] + misses))

    def test_fixed_examples_are_quiet(self):
        noisy = []
        for page in _pages():
            rule = page.stem
            for filename, code in _examples(page)["Fixed"]:
                findings = _findings(filename, code)
                loud = [f"{f.rule_id} line {f.line}" for f in findings
                        if f.rule_id == rule or severity_rank(f.severity) >= severity_rank("HIGH")]
                if loud:
                    noisy.append(f"{rule}: {filename} fixed example reports {', '.join(loud)}")
        self.assertEqual(noisy, [], "\n  ".join([""] + noisy))

    def test_pages_contain_no_real_secret_or_hidden_character(self):
        from mcp_vet.rules import HIDDEN_CHARS
        dirty = []
        for page in _pages():
            text = page.read_text(encoding="utf-8")
            if HIDDEN_CHARS.search(text):
                dirty.append(f"{page.name}: contains a hidden character")
            for f in scan_text(page.name, text, page.name):
                if f.rule_id in ("MCP003", "MCP008"):
                    dirty.append(f"{page.name}: page itself reports {f.rule_id}")
        self.assertEqual(dirty, [], "\n  ".join([""] + dirty))


    def test_sarif_links_each_rule_to_its_page(self):
        import json

        from mcp_vet.models import ScanResult
        from mcp_vet.report import as_sarif

        sarif = json.loads(as_sarif(ScanResult(root=".", files_scanned=0, findings=[])))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            local = rule["helpUri"].rsplit("/", 1)[-1]
            self.assertEqual(local, f"{rule['id']}.md", rule["id"])
            self.assertTrue((DOCS / local).is_file(), f"{rule['id']} links to a missing page")


if __name__ == "__main__":
    unittest.main(verbosity=2)
