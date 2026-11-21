"""Config file, baseline and MCP client scanning."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_vet import baseline, clients, config  # noqa: E402
from mcp_vet.cli import main  # noqa: E402

VULN = ("import os\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
        "@mcp.tool()\ndef t(c: str):\n    os.system(c)\n")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def project(files, cfg=None):
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    if cfg is not None:
        (root / ".mcp-vet.toml").write_text(cfg, encoding="utf-8")
    return d, root


def report_files(root, *extra):
    code, out, _ = run(str(root), "-f", "json", *extra)
    data = json.loads(out)
    return code, sorted({f["file"] for f in data["findings"]}), data


class MiniToml(unittest.TestCase):
    def test_reads_the_supported_subset(self):
        data = config._mini_toml(
            '# a comment\nfail_on = "MEDIUM"  # trailing\nignore = ["a/**", \'b c\']\n'
            'disable = [\n  "MCP006",\n  "MCP009", # why\n]\ninclude_tests = true\nn = 3\n'
            '[severity]\nMCP009 = "LOW"\n')
        self.assertEqual(data["fail_on"], "MEDIUM")
        self.assertEqual(data["ignore"], ["a/**", "b c"])
        self.assertEqual(data["disable"], ["MCP006", "MCP009"])
        self.assertIs(data["include_tests"], True)
        self.assertEqual(data["n"], 3)
        self.assertEqual(data["severity"], {"MCP009": "LOW"})

    def test_hash_inside_a_string_is_not_a_comment(self):
        self.assertEqual(config._mini_toml('ignore = ["dir#1/**"]')["ignore"], ["dir#1/**"])

    def test_bad_syntax_is_an_error(self):
        with self.assertRaises(ValueError):
            config._mini_toml("this is not toml")
        with self.assertRaises(ValueError):
            config._mini_toml('ignore = ["never closed"')

    def test_reads_dotted_tables(self):
        data = config._mini_toml(
            '[tool.mcp-vet]\nfail_on = "MEDIUM"\n\n'
            '[tool.mcp-vet.severity]\nMCP001 = "LOW"\n'
        )
        self.assertEqual(data["tool"]["mcp-vet"]["fail_on"], "MEDIUM")
        self.assertEqual(data["tool"]["mcp-vet"]["severity"]["MCP001"], "LOW")


class ConfigParsing(unittest.TestCase):
    def test_valid_file(self):
        cfg = config.parse('fail_on = "medium"\nmin_severity = "LOW"\nignore = ["x"]\n'
                           'disable = ["MCP006"]\n[severity]\nMCP009 = "off"\n')
        self.assertEqual((cfg.fail_on, cfg.min_severity), ("MEDIUM", "LOW"))
        self.assertEqual(cfg.severity, {"MCP009": "OFF"})

    def test_typo_in_a_setting_suggests_the_right_one(self):
        with self.assertRaisesRegex(config.ConfigError, r"did you mean 'fail_on'"):
            config.parse('fail-on = "HIGH"')

    def test_valid_pyproject_toml(self):
        cfg = config.parse(
            '[project]\nname = "demo"\n\n'
            '[tool.mcp-vet]\nfail_on = "medium"\nmin_severity = "LOW"\nignore = ["x"]\n'
            'disable = ["MCP006"]\n\n[tool.mcp-vet.severity]\nMCP009 = "off"\n',
            source="pyproject.toml",
        )
        self.assertEqual((cfg.fail_on, cfg.min_severity), ("MEDIUM", "LOW"))
        self.assertEqual(cfg.severity, {"MCP009": "OFF"})
        self.assertEqual(cfg.source, "pyproject.toml")

    def test_pyproject_missing_tool_table_raises_error(self):
        with self.assertRaisesRegex(config.ConfigError, r"missing \[tool\.mcp-vet\] table"):
            config.parse('[project]\nname = "demo"\n', source="pyproject.toml")

    def test_pyproject_typo_in_setting_suggests_fix(self):
        with self.assertRaisesRegex(config.ConfigError, r"did you mean 'fail_on'"):
            config.parse('[tool.mcp-vet]\nfail-on = "HIGH"\n', source="pyproject.toml")

    def test_errors_name_the_problem(self):
        for text, needle in [('fail_on = "EXTREME"', "not valid"),
                             ('fail_on = "OFF"', "not valid"),
                             ('disable = ["MCP999"]', "unknown rule"),
                             ('[severity]\nMCP999 = "LOW"', "unknown rule"),
                             ('ignore = "not a list"', "list of strings"),
                             ('include_tests = "yes"', "true or false")]:
            with self.assertRaisesRegex(config.ConfigError, needle):
                config.parse(text)


class ConfigBehaviour(unittest.TestCase):
    def test_ignore_hides_a_folder(self):
        d, root = project({"legacy/a.py": VULN, "src/b.py": VULN}, 'ignore = ["legacy/**"]\n')
        with d:
            _, files, data = report_files(root)
            self.assertEqual(files, ["src/b.py"])

    def test_ignore_matches_a_folder_name_and_a_single_file(self):
        d, root = project({"vendor/a.py": VULN, "src/b.py": VULN, "src/c.py": VULN},
                          'ignore = ["vendor", "src/c.py"]\n')
        with d:
            self.assertEqual(report_files(root)[1], ["src/b.py"])

    def test_disable_turns_a_rule_off(self):
        d, root = project({"a.py": VULN}, 'disable = ["MCP001"]\n')
        with d:
            code, files, _ = report_files(root)
            self.assertEqual((code, files), (0, []))

    def test_severity_override_changes_the_gate(self):
        d, root = project({"a.py": VULN}, '[severity]\nMCP001 = "LOW"\n')
        with d:
            code, _, data = report_files(root)
            self.assertEqual(code, 0)
            self.assertEqual(data["findings"][0]["severity"], "LOW")

    def test_severity_off_removes_the_rule(self):
        d, root = project({"a.py": VULN}, '[severity]\nMCP001 = "OFF"\n')
        with d:
            self.assertEqual(report_files(root)[1], [])

    def test_fail_on_from_config_and_command_line_wins(self):
        d, root = project({"a.py": VULN}, 'fail_on = "CRITICAL"\n')
        with d:
            self.assertEqual(run(str(root), "--no-color")[0], 0)                       # config: CRITICAL, finding is HIGH
            self.assertEqual(run(str(root), "--no-color", "--fail-on", "HIGH")[0], 1)  # the flag wins

    def test_min_severity_from_config(self):
        d, root = project({"a.py": VULN}, 'min_severity = "CRITICAL"\n')
        with d:
            self.assertEqual(report_files(root)[1], [])

    def test_config_is_found_in_a_parent_folder(self):
        d, root = project({"sub/a.py": VULN}, 'disable = ["MCP001"]\n')
        with d:
            self.assertEqual(report_files(root / "sub")[1], [])

    def test_no_config_flag_ignores_it(self):
        d, root = project({"a.py": VULN}, 'disable = ["MCP001"]\n')
        with d:
            self.assertEqual(report_files(root, "--no-config")[1], ["a.py"])

    def test_explicit_config_path(self):
        d, root = project({"a.py": VULN})
        with d:
            other = root / "elsewhere.toml"
            other.write_text('disable = ["MCP001"]\n', encoding="utf-8")
            self.assertEqual(report_files(root, "--config", str(other))[1], [])

    def test_invalid_config_is_a_usage_error_with_a_helpful_message(self):
        d, root = project({"a.py": VULN}, 'fail-on = "HIGH"\n')
        with d:
            code, out, err = run(str(root))
            self.assertEqual(code, 2)
            self.assertIn("did you mean 'fail_on'", err)
            self.assertEqual(out, "")

    def test_report_names_the_config_in_use(self):
        d, root = project({"a.py": VULN}, 'min_severity = "LOW"\n')
        with d:
            self.assertIn(".mcp-vet.toml", run(str(root), "--no-color")[1])

    def test_pyproject_toml_configuration(self):
        pyproject = '[project]\nname = "demo"\n\n[tool.mcp-vet]\ndisable = ["MCP001"]\n'
        d, root = project({"a.py": VULN, "pyproject.toml": pyproject})
        with d:
            code, files, _ = report_files(root)
            self.assertEqual((code, files), (0, []))
            self.assertIn("pyproject.toml", run(str(root), "--no-color")[1])

    def test_mcp_vet_toml_wins_over_pyproject_in_same_folder(self):
        pyproject = '[tool.mcp-vet]\nfail_on = "LOW"\n'
        d, root = project({"a.py": VULN, "pyproject.toml": pyproject}, cfg='fail_on = "CRITICAL"\n')
        with d:
            self.assertEqual(run(str(root), "--no-color")[0], 0)
            self.assertIn(".mcp-vet.toml", run(str(root), "--no-color")[1])

    def test_pyproject_without_tool_table_is_ignored_and_parent_config_used(self):
        pyproject = '[project]\nname = "demo"\n'
        d, root = project({"sub/a.py": VULN, "sub/pyproject.toml": pyproject},
                          cfg='disable = ["MCP001"]\n')
        with d:
            self.assertEqual(report_files(root / "sub")[1], [])

    def test_pyproject_severity_subtable(self):
        pyproject = (
            '[tool.mcp-vet]\n'
            'fail_on = "CRITICAL"\n\n'
            '[tool.mcp-vet.severity]\n'
            'MCP001 = "LOW"\n'
        )
        d, root = project({"a.py": VULN, "pyproject.toml": pyproject})
        with d:
            code, _, data = report_files(root)
            self.assertEqual(code, 0)
            self.assertEqual(data["findings"][0]["severity"], "LOW")


class Baseline(unittest.TestCase):
    def test_accepted_findings_are_hidden_and_the_gate_passes(self):
        d, root = project({"a.py": VULN})
        with d:
            bl = str(root / "baseline.json")
            code, out, _ = run(str(root), "--write-baseline", bl)
            self.assertEqual(code, 0)
            self.assertIn("Wrote 1 finding", out)
            code, files, data = report_files(root, "--baseline", bl)
            self.assertEqual((code, files, data["baselined"]), (0, [], 1))

    def test_only_new_findings_are_reported(self):
        d, root = project({"a.py": VULN})
        with d:
            bl = str(root / "baseline.json")
            run(str(root), "--write-baseline", bl)
            (root / "b.py").write_text(VULN, encoding="utf-8")
            code, files, data = report_files(root, "--baseline", bl)
            self.assertEqual((code, files, data["baselined"]), (1, ["b.py"], 1))

    def test_moving_code_does_not_resurrect_an_accepted_finding(self):
        d, root = project({"a.py": VULN})
        with d:
            bl = str(root / "baseline.json")
            run(str(root), "--write-baseline", bl)
            (root / "a.py").write_text("# a new header\n# and another\n" + VULN, encoding="utf-8")
            code, files, _ = report_files(root, "--baseline", bl)
            self.assertEqual((code, files), (0, []))

    def test_fixing_the_code_retires_the_entry_and_a_new_copy_is_reported(self):
        d, root = project({"a.py": VULN})
        with d:
            bl = str(root / "baseline.json")
            run(str(root), "--write-baseline", bl)
            (root / "a.py").write_text(VULN + "    os.system(c)  # a second, new call\n", encoding="utf-8")
            code, files, data = report_files(root, "--baseline", bl)
            self.assertEqual((code, data["baselined"]), (1, 1))  # the old one hidden, the new one reported

    def test_identical_findings_are_matched_one_for_one(self):
        two = VULN + "    os.system(c)\n"
        d, root = project({"a.py": two})
        with d:
            bl = str(root / "baseline.json")
            run(str(root), "--write-baseline", bl)
            (root / "a.py").write_text(two + "    os.system(c)\n", encoding="utf-8")
            _, _, data = report_files(root, "--baseline", bl)
            self.assertEqual(data["baselined"], 2)
            self.assertEqual(len(data["findings"]), 1)

    def test_unreadable_baseline_is_a_usage_error(self):
        d, root = project({"a.py": VULN})
        with d:
            code, _, err = run(str(root), "--baseline", str(root / "missing.json"))
            self.assertEqual(code, 2)
            self.assertIn("cannot use baseline", err)

    def test_baseline_does_not_contain_secrets_in_full(self):
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        d, root = project({"a.py": f"KEY = '{key}'\n"})
        with d:
            bl = root / "baseline.json"
            run(str(root), "--write-baseline", str(bl))
            self.assertNotIn(key, bl.read_text(encoding="utf-8"))

    def test_report_shows_how_many_were_hidden(self):
        d, root = project({"a.py": VULN})
        with d:
            bl = str(root / "baseline.json")
            run(str(root), "--write-baseline", bl)
            self.assertIn("1 accepted finding hidden", run(str(root), "--baseline", bl, "--no-color")[1])


class ClientConfigs(unittest.TestCase):
    CONFIG = ('{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},'
              ' "git": {"command": "uvx", "args": ["mcp-server-git==0.6.2"]}}}\n')

    def test_finds_the_known_locations_that_exist(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / ".cursor").mkdir()
            (home / ".cursor" / "mcp.json").write_text(self.CONFIG, encoding="utf-8")
            appdata = home / "AppData"
            (appdata / "Claude").mkdir(parents=True)
            (appdata / "Claude" / "claude_desktop_config.json").write_text(self.CONFIG, encoding="utf-8")
            found = clients.existing_configs(home=home, env={"APPDATA": str(appdata)}, cwd=home / "work")
            names = sorted(p.name for p in found)
            self.assertEqual(names, ["claude_desktop_config.json", "mcp.json"])

    def test_nothing_found_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(clients.existing_configs(home=Path(d), env={}, cwd=Path(d)), [])

    def test_project_level_configs_are_found_in_the_working_folder(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = Path(d)
            (cwd / ".vscode").mkdir()
            (cwd / ".vscode" / "mcp.json").write_text(self.CONFIG, encoding="utf-8")
            (cwd / ".mcp.json").write_text(self.CONFIG, encoding="utf-8")
            found = clients.existing_configs(home=cwd / "nohome", env={}, cwd=cwd)
            self.assertEqual(sorted(p.name for p in found), [".mcp.json", "mcp.json"])

    def test_paths_under_home_are_shown_with_a_tilde(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            p = home / ".cursor" / "mcp.json"
            self.assertEqual(clients.display(p, home=home), "~/.cursor/mcp.json")
            self.assertNotIn(d.replace("\\", "/"), clients.display(p, home=home))

    def test_clients_flag_scans_and_reports_each_file(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "mcp.json"
            cfg.write_text(self.CONFIG, encoding="utf-8")
            with mock.patch("mcp_vet.cli.clients.existing_configs", return_value=[cfg]):
                code, out, _ = run("--clients", "--no-color", "-f", "json")
            data = json.loads(out)
            rules = {f["rule_id"] for f in data["findings"]}
            self.assertIn("MCP007", rules)   # "/" as the filesystem root
            self.assertIn("MCP014", rules)   # the unpinned npx package
            self.assertEqual(code, 1)

    def test_clients_flag_with_nothing_installed_exits_cleanly(self):
        with mock.patch("mcp_vet.cli.clients.existing_configs", return_value=[]):
            code, out, _ = run("--clients")
        self.assertEqual(code, 0)
        self.assertIn("No MCP client configuration was found", out)

    def test_a_path_or_clients_is_required(self):
        code, _, err = run()
        self.assertEqual(code, 2)
        self.assertIn("--clients", err)


if __name__ == "__main__":
    unittest.main()
