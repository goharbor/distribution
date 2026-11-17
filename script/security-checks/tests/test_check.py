import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))
SPEC = importlib.util.spec_from_file_location("security", Path(__file__).parents[1] / "check.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class CommitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "scanner-test@example.invalid")
        self.git("config", "user.name", "Scanner Test")
        self.base = self.commit("base.txt", "base")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, name, content):
        (self.repo / name).write_text(content)
        self.git("add", name)
        self.git("commit", "-s", "-qm", "scanner fixture")
        return self.git("rev-parse", "HEAD")

    def select(self, kind, event, head):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": kind, "GITHUB_SHA": head}):
            return check.select_commits(self.repo, event)

    def test_every_commit_even_if_head_removes_defect(self):
        first = self.commit("secret.txt", "synthetic failing commit")
        head = self.commit("secret.txt", "fixed in later commit")
        event = {"pull_request": {"base": {"sha": self.base}, "head": {"sha": head}}}
        self.assertEqual(self.select("pull_request", event, head), [first, head])
        event = {"before": self.base, "after": head, "commits": []}
        self.assertEqual(self.select("push", event, head), [first, head])

    def test_merge_result_is_scanned(self):
        self.git("checkout", "-b", "feature")
        head = self.commit("feature.txt", "feature")
        self.git("checkout", "main")
        self.commit("main.txt", "new base change")
        self.git("merge", "--signoff", "--no-ff", "feature", "-m", "merge fixture")
        merged = self.git("rev-parse", "HEAD")
        event = {"pull_request": {"base": {"sha": self.base}, "head": {"sha": head}}}
        self.assertEqual(self.select("pull_request", event, merged), [head, merged])

    def test_new_branch_does_not_skip_commits(self):
        head = self.commit("new.txt", "new")
        event = {"before": "0" * 40, "after": head}
        self.assertEqual(self.select("push", event, head), [self.base, head])

    def test_new_feature_branch_only_excludes_shared_default_history(self):
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        first = self.commit("first.txt", "first")
        head = self.commit("last.txt", "last")
        event = {"before": "0" * 40, "after": head, "ref": "refs/heads/feature",
                 "repository": {"default_branch": "main"}}
        self.assertEqual(self.select("push", event, head), [first, head])

    def test_manual_and_merge_queue_scan_full_head(self):
        for kind in ("workflow_dispatch", "merge_group"):
            self.assertEqual(self.select(kind, {}, self.base), [self.base])

    def test_missing_history_and_invalid_sha_fail_closed(self):
        with self.assertRaises(check.ScanError):
            check.commit(self.repo, "--all")
        with self.assertRaises(check.ScanError):
            self.select("push", {"before": "f" * 40, "after": self.base}, self.base)

    def test_snapshot_ignores_export_ignore_and_never_follows_symlinks(self):
        self.commit(".gitattributes", "hidden.go export-ignore\n")
        self.commit("hidden.go", "package hidden")
        (self.repo / "outside-link").symlink_to("/etc/passwd")
        self.git("add", "outside-link")
        sha = self.commit("last.txt", "last")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            check.export_snapshot(self.repo, sha, root)
            self.assertEqual((root / "hidden.go").read_text(), "package hidden")
            self.assertFalse((root / "outside-link").exists())

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("semgrep", "codespell", "gitleaks")),
                         "requires all pinned scanners")
    def test_real_pr_gate_fails_for_intermediate_defect_after_head_fix(self):
        first = self.commit("main.go", '''package example
func same(hostname, other string) bool { return hostname == other }
''')
        head = self.commit("main.go", '''package example
import "strings"
func same(hostname, other string) bool { return strings.EqualFold(hostname, other) }
''')
        event = self.repo / "event.json"
        event.write_text(json.dumps({"pull_request": {"base": {"sha": self.base}, "head": {"sha": head}}}))
        report = self.repo / "report.json"
        environment = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_SHA": head,
                       "GITHUB_EVENT_PATH": str(event)}
        argv = ["check.py", "event", "--repo", str(self.repo), "--report", str(report)]
        with patch.dict(os.environ, environment), patch.object(sys, "argv", argv), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check.main(), 1)
        scans = json.loads(report.read_text())["scans"]
        self.assertFalse(any(scan.get("error") for scan in scans), scans)
        self.assertEqual([scan["commit"] for scan in scans], [first, head])
        self.assertTrue(scans[0]["findings"])
        self.assertEqual(scans[1]["findings"], [])


class PolicyTests(unittest.TestCase):
    def message_rules(self, text, spelling_exit=0):
        return {item["rule"] for item in check.message_findings(
            text, "errors.go", 3, misspelled=spelling_exit == 65)}

    def test_escalation_requires_self_service(self):
        self.assertIn("error-contact-only", self.message_rules("DNS failed. Contact technical support."))
        self.assertNotIn("error-contact-only", self.message_rules(
            "DNS lookup failed. Verify the configured DNS server and retry. If it persists, contact support."))
        self.assertIn("error-contact-only", self.message_rules("Contact your administrator"))
        self.assertIn("error-contact-only", self.message_rules("Contact support to configure the cluster"))
        self.assertNotIn("error-contact-only", self.message_rules("Contact support if needed. Check DNS and retry."))

    def test_messages_provide_clear_troubleshooting_guidance(self):
        self.assertIn("error-cryptic", self.message_rules("Unknown error"))
        self.assertIn("error-cryptic", self.message_rules("Server error"))
        self.assertIn("error-missing-remediation", self.message_rules("Registry connection failed"))
        self.assertIn("error-repeated-word", self.message_rules("Check the the DNS server"))
        self.assertIn("error-spelling", self.message_rules("Check the occured error", spelling_exit=65))
        self.assertEqual(self.message_rules("Invalid port: set a port from 1 to 65535 and retry"), set())

    def test_reports_never_include_secret_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def fake_gitleaks(command, **kwargs):
                report = Path(command[command.index("--report-path") + 1])
                report.write_text(json.dumps([{"RuleID": "synthetic-rule", "File": str(root / "config.yml"),
                                               "StartLine": 1, "Secret": "NEVER-PUBLISH-THIS", "Match": "NEVER-PUBLISH-THIS"}]))
                return subprocess.CompletedProcess([], 10)
            with patch.object(check, "run", side_effect=fake_gitleaks):
                findings = check.scan_secrets(root)
            self.assertNotIn("NEVER-PUBLISH-THIS", json.dumps(findings))
            self.assertEqual(findings[0]["path"], "config.yml")

    def test_scanner_errors_do_not_skip_other_scanners(self):
        with patch.object(check, "export_snapshot"), \
             patch.object(check, "scan_secrets", side_effect=check.ScanError("bad")), \
             patch.object(check, "scan_code", return_value=[{"rule": "test"}]) as code, \
             contextlib.redirect_stdout(io.StringIO()):
            entry = check.scan_revision(Path("."), "a" * 40)
        code.assert_called_once()
        self.assertIn("error", entry)
        self.assertEqual(len(entry["findings"]), 1)

    def test_build_failure_and_findings_fail_gate(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            report = Path(temporary) / "report.json"
            for scan in ({"command_exit": 1}, {"error": "failed"}, {"findings": [{}]}):
                self.assertEqual(check.write_report(report, [scan]), 1)
            self.assertEqual(check.write_report(report, [{"findings": [], "command_exit": 0}]), 0)
            self.assertEqual(set(json.loads(report.read_text())), {"schema_version", "checks", "summary", "findings", "scans"})


@unittest.skipUnless(shutil.which("gitleaks"), "requires pinned Gitleaks binary")
class GitleaksIntegrationTests(unittest.TestCase):
    def test_weak_defaults_and_target_ignore_files_cannot_hide_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config.yml").write_text('password: weak-default # gitleaks:allow\n')
            (root / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
            findings = check.scan_secrets(root)
            self.assertTrue(any(item["path"] == "config.yml" for item in findings))

    def test_runtime_credentials_are_blocked_without_exposing_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            secret = "synthetic-runtime-credential"
            result = subprocess.run(
                [sys.executable, str(Path(check.__file__)), "logs", "--report", str(report),
                 "--", sys.executable, "-c", f"print('password: {secret}')"], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(secret.encode(), result.stdout + result.stderr + report.read_bytes())
            self.assertTrue(json.loads(report.read_text())["scans"][0]["findings"])

    def test_clean_failed_build_keeps_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            result = subprocess.run(
                [sys.executable, str(Path(check.__file__)), "logs", "--report", str(report),
                 "--", sys.executable, "-c", "raise SystemExit(7)"], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(report.read_text())["scans"][0]["command_exit"], 7)

    def test_code_variable_references_are_not_default_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.go").write_text('package example\nfunc f() { secretKey = params.SecretKey }\n')
            (root / "build.log").write_text('password: [REDACTED]\n')
            self.assertEqual(check.scan_secrets(root), [])


@unittest.skipUnless(shutil.which("semgrep") and shutil.which("codespell"),
                     "requires pinned Semgrep and codespell")
class SemgrepIntegrationTests(unittest.TestCase):
    def scan(self, text, extra=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.go").write_text(text)
            for name, data in (extra or {}).items():
                (root / name).write_text(data)
            return check.scan_code(root)

    def test_security_findings_and_spelling_reach_redacted_report(self):
        findings = self.scan('''package example
import ("errors"; "log"; "strings")
func f(hostname, other, clusterName, password string) {
    log.Printf("value: %s", password)
    _ = errors.New("An error occured: contact support")
    _ = hostname == other
    _ = strings.ToLower(clusterName)
}
''')
        rules = {item["rule"] for item in findings}
        self.assertTrue({"go-secret-to-log", "error-contact-only", "error-spelling",
                         "go-case-sensitive-network-name", "go-cluster-name-case-fold"} <= rules)
        self.assertNotIn("occured", json.dumps(findings))

    def test_valid_identifier_comparison_and_actionable_error_are_clean(self):
        source = '''package example
import ("errors"; "strings")
func f(hostname, other string) error {
    if !strings.EqualFold(hostname, other) {
        return errors.New("DNS lookup failed: verify DNS configuration and retry")
    }
    return nil
}
'''
        self.assertEqual(self.scan(source, {"example_test.go": '''package example
const password = "synthetic-test-default"
'''}), [])

    def test_target_ignore_files_and_inline_suppression_cannot_hide_defect(self):
        findings = self.scan('''package example
func f(hostname, other string) bool {
    return hostname == other // nosemgrep: go-case-sensitive-network-name
}
''', {".semgrepignore": "main.go\n", ".gitignore": "main.go\n"})
        self.assertIn("go-case-sensitive-network-name", {item["rule"] for item in findings})


if __name__ == "__main__":
    unittest.main()
