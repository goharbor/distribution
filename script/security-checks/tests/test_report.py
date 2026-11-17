import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))
import check
from security_report import group_findings, render_markdown


def setUpModule():
    global report_environment
    report_environment = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""})
    report_environment.start()


def tearDownModule():
    report_environment.stop()


class ReportTests(unittest.TestCase):
    def item(self, rule="go-secret-to-log", path="main.go", line=10):
        return {"tool": "semgrep", "rule": rule, "path": path, "line": line, "message": "redacted finding"}

    def scan(self, items, sha="a" * 40, **extra):
        return {"scope": "full-codebase", "commit": sha, "findings": items, **extra}

    def test_repeated_commits_are_counted_once_and_locations_are_distinct_from_rules(self):
        items = [self.item(), self.item("go-hardcoded-secret")]
        scans = [self.scan(items, digit * 40) for digit in "abc"]
        findings, stats = group_findings(scans)
        self.assertEqual((stats["occurrences"], stats["unique_findings"], stats["locations"], stats["files"]), (6, 2, 1, 1))
        self.assertTrue(all(item["occurrences"] == 3 and len(item["snapshots"]) == 3 for item in findings))
        self.assertEqual(stats["latest_findings"], 2)

    def test_earlier_defect_links_to_its_actual_revision_and_still_fails_gate(self):
        scans = [self.scan([self.item()]), self.scan([], "b" * 40)]
        findings, stats = group_findings(scans)
        markdown = render_markdown(scans, findings, stats, {"GITHUB_REPOSITORY": "example/project"})
        self.assertEqual(stats["latest_findings"], 0)
        self.assertIn("Earlier snapshot only", markdown)
        self.assertIn("/blob/" + "a" * 40 + "/main.go#L10", markdown)
        self.assertNotIn("/blob/" + "b" * 40, markdown)
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check.write_report(Path(temporary) / "code.json", scans), 1)

    def test_failure_reasons_and_full_guidance_are_in_job_summary_and_artifact(self):
        scans = [self.scan([self.item("error-missing-remediation", "errors.go", 18)])]
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "job.md"), "GITHUB_REPOSITORY": "example/project"}):
                self.assertEqual(check.write_report(root / "code.json", scans), 1)
            data = json.loads((root / "code.json").read_text())
            artifact = (root / "code.md").read_text()
            self.assertEqual((root / "job.md").read_text(), artifact)
            self.assertEqual(data["summary"]["unique_findings"], 1)
            self.assertIn("API/CLI", data["findings"][0]["remediation"])
            for expected in ("errors.go:18", "error-missing-remediation", "sentinel", "FAILED"):
                self.assertIn(expected, artifact)

    def test_untrusted_names_cannot_inject_markdown_or_actions_commands(self):
        item = self.item(path="<script>|[link](javascript:alert(1))\n::error::.go")
        item.update({"Secret": "DO-NOT-PUBLISH", "Match": "DO-NOT-PUBLISH", "message": "DO-NOT-PUBLISH"})
        scans = [self.scan([item])]
        findings, stats = group_findings(scans)
        markdown = render_markdown(scans, findings, stats, {"GITHUB_REPOSITORY": "example/project"})
        for text in ("DO-NOT-PUBLISH", "<script>", "[link](javascript:", "\n::error::"):
            self.assertNotIn(text, markdown)
        self.assertNotIn("DO-NOT-PUBLISH", json.dumps(findings))
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn("%0A%3A%3Aerror%3A%3A", markdown)

    def test_incomplete_scanner_and_failed_command_remain_visible_with_no_matches(self):
        scans = [self.scan([], error="analysis failed"), {"scope": "build-logs", "findings": [], "command_exit": 7}]
        findings, stats = group_findings(scans)
        markdown = render_markdown(scans, findings, stats, {})
        self.assertEqual((stats["scanner_errors"], stats["failed_commands"]), (1, 1))
        for text in ("FAILED", "Analysis is incomplete", "ERROR: incomplete", "7"):
            self.assertIn(text, markdown)

    def test_large_report_keeps_full_artifacts_and_bounds_job_summary(self):
        scans = [self.scan([self.item(line=line) for line in range(1, 4001)])]
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "job.md")}):
                self.assertEqual(check.write_report(root / "code.json", scans), 1)
            full = (root / "code.md").read_text()
            limited = (root / "job.md").read_text()
            self.assertIn("F4000", full)
            self.assertNotIn("F4000", limited)
            self.assertIn("Showing 100 of 4000", limited)
            self.assertLess(len(limited.encode()), 900_000)
            self.assertEqual(len(json.loads((root / "code.json").read_text())["findings"]), 4000)

    def test_clean_report_and_fallback_guidance(self):
        findings, stats = group_findings([self.scan([])])
        self.assertIn("PASSED", render_markdown([self.scan([])], findings, stats, {}))
        item = self.item("new-provider-rule")
        item["tool"] = "gitleaks"
        findings, _ = group_findings([self.scan([item])])
        self.assertIn("runtime secret injection", findings[0]["remediation"])


if __name__ == "__main__":
    unittest.main()
