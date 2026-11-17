import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.request import Request
import zipfile


sys.path.insert(0, str(Path(__file__).parents[1]))
import pr_comment as publisher


def report_archive(scans=None, extra=None):
    if scans is None:
        scans = [{"commit": "a" * 40, "scope": "binary-changes", "findings": [
            {"tool": "semgrep", "rule": "go-secret-to-log", "path": "cmd/registry/main.go", "line": 12,
             "message": "NEVER-PUBLISH-RAW-MESSAGE", "Secret": "NEVER-PUBLISH-RAW-SECRET"}]}]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("code.json", json.dumps({"schema_version": 1, "scans": scans, **(extra or {})}))
        archive.writestr("../../untrusted.py", "raise RuntimeError('never execute artifact code')")
    return stream.getvalue()


class FakeGitHub:
    def __init__(self):
        self.run = {"id": 100, "run_attempt": 1, "status": "completed", "conclusion": "failure",
                    "event": "pull_request", "path": ".github/workflows/security-checks.yml",
                    "head_sha": "a" * 40, "head_repository": {"full_name": "fork/project"},
                    "head_branch": "feature", "pull_requests": [{"number": 7}]}
        self.pull = {"number": 7, "state": "open", "merged": False,
                     "base": {"repo": {"full_name": "example/project"}},
                     "head": {"sha": "a" * 40, "repo": {"full_name": "fork/project"}}}
        self.comments = []
        self.archive = report_archive()
        self.missing = False
        self.writes = []
        self.calls = []

    def request(self, method, path, data=None, binary=False):
        self.calls.append((method, path))
        if method in {"POST", "PATCH"}:
            self.writes.append((method, path, data))
            if method == "POST":
                self.comments.append({"id": 55, "body": data["body"],
                                      "user": {"login": "github-actions[bot]", "type": "Bot"}})
            else:
                self.comments[-1]["body"] = data["body"]
            return {"id": 55}
        if path == "/actions/runs/100":
            return self.run
        if path == "/pulls/7":
            return self.pull
        if path == "/actions/artifacts/10/zip":
            return self.archive
        raise AssertionError((method, path))

    def pages(self, path, key=None):
        self.calls.append(("pages", path))
        if path.endswith("/artifacts"):
            return [] if self.missing else [{"id": 10, "name": f"security-checks-100-{self.run['run_attempt']}"}]
        if path.endswith("/comments"):
            return self.comments
        if path.startswith("/commits/"):
            return []
        if path.startswith("/pulls?"):
            return [{"number": 7}]
        raise AssertionError(path)


class PullRequestCommentTests(unittest.TestCase):
    def test_creates_collapsible_redacted_comment_then_updates_same_comment(self):
        api = FakeGitHub()
        self.assertEqual(publisher.publish(api, 100, "example/project"), [7])
        body = api.writes[0][2]["body"]
        for text in (publisher.MARKER, "<details>", "<summary>Security scan: FAILED", "main.go:12", "Remove credential values"):
            self.assertIn(text, body)
        self.assertNotIn("NEVER-PUBLISH", body)
        api.run.update({"run_attempt": 2, "conclusion": "success"})
        api.archive = report_archive([{"commit": "a" * 40, "scope": "binary-changes", "findings": []}])
        self.assertEqual(publisher.publish(api, 100, "example/project"), [7])
        self.assertEqual([item[0] for item in api.writes], ["POST", "PATCH"])
        self.assertEqual(len(api.comments), 1)
        self.assertIn("Security scan: PASSED", api.writes[-1][2]["body"])

    def test_summary_distinguishes_changed_coverage_and_earlier_commit_findings(self):
        scans = publisher.read_report(report_archive())
        scans.append({"commit": "b" * 40, "scope": "binary-changes", "findings": []})
        body = publisher.render_comment(FakeGitHub().run, scans, "example/project")
        self.assertIn("Coverage: changed product inputs only", body)
        self.assertIn("Reported by latest scan", body)
        self.assertIn("Earlier scan only", body)
        scans[-1]["scope"] = "binary-full"
        body = publisher.render_comment(FakeGitHub().run, scans, "example/project")
        self.assertIn("Coverage includes a full-product scan", body)

    def test_fork_association_uses_service_metadata_when_run_has_no_pr_array(self):
        api = FakeGitHub()
        api.run["pull_requests"] = []
        self.assertEqual(publisher.publish(api, 100, "example/project"), [7])
        self.assertTrue(any("head=fork%3Afeature" in path for _, path in api.calls))

    def test_outdated_head_does_not_post_or_download_artifacts(self):
        api = FakeGitHub()
        api.pull["head"]["sha"] = "b" * 40
        self.assertEqual(publisher.publish(api, 100, "example/project"), [])
        self.assertEqual(api.writes, [])
        self.assertFalse(any("artifacts" in path for _, path in api.calls))

    def test_old_completion_cannot_replace_newer_summary_on_same_head(self):
        api = FakeGitHub()
        api.comments = [{"id": 55, "body": publisher.MARKER + "\n<!-- source-run:101:1 -->",
                         "user": {"login": "github-actions[bot]", "type": "Bot"}}]
        self.assertEqual(publisher.publish(api, 100, "example/project"), [])
        self.assertEqual(api.writes, [])

    def test_human_comment_with_marker_is_never_overwritten(self):
        api = FakeGitHub()
        api.comments = [{"id": 12, "body": publisher.MARKER, "user": {"login": "reviewer", "type": "User"}}]
        publisher.publish(api, 100, "example/project")
        self.assertEqual(api.writes[0][0], "POST")
        self.assertEqual(api.comments[0]["body"], publisher.MARKER)

    def test_closed_without_merge_is_skipped_but_merge_result_can_be_published(self):
        api = FakeGitHub()
        api.pull["state"] = "closed"
        self.assertEqual(publisher.publish(api, 100, "example/project"), [])
        api.pull.update({"merged": True, "merge_commit_sha": "b" * 40})
        api.run["head_sha"] = "b" * 40
        self.assertEqual(publisher.publish(api, 100, "example/project"), [7])

    def test_missing_or_malformed_report_is_incomplete_even_when_run_is_green(self):
        for archive in (None, b"not a ZIP file", report_archive([{"scope": "binary-changes", "findings": [{"line": "invalid"}]}])):
            api = FakeGitHub()
            api.run["conclusion"] = "success"
            api.missing = archive is None
            api.archive = archive
            publisher.publish(api, 100, "example/project")
            self.assertIn("Security scan: INCOMPLETE", api.writes[0][2]["body"])
            self.assertNotIn("Security scan: PASSED", api.writes[0][2]["body"])

    def test_failed_self_tests_do_not_get_a_passed_comment_with_empty_findings(self):
        api = FakeGitHub()
        api.archive = report_archive([{"scope": "binary-changes", "findings": []}])
        publisher.publish(api, 100, "example/project")
        self.assertIn("Security scan: INCOMPLETE", api.writes[0][2]["body"])

    def test_filenames_cannot_inject_html_or_notify_named_users(self):
        archive = report_archive([{"commit": "a" * 40, "scope": "binary-changes", "findings": [
            {"tool": "semgrep", "rule": "go-secret-to-log", "path": "@reviewer<details>|[x].go", "line": 1}]}])
        run = FakeGitHub().run
        body = publisher.render_comment(run, publisher.read_report(archive), "example/project")
        self.assertNotIn("@reviewer", body)
        self.assertIn("&lt;details&gt;", body)
        self.assertNotIn("<details>|[x]", body)
        self.assertIn("%40reviewer%3Cdetails%3E", body)

    def test_size_limits_and_unsafe_report_fields(self):
        with patch.object(publisher, "MAX_REPORT_BYTES", 1), self.assertRaises(publisher.PublishError):
            publisher.read_report(report_archive())
        for path in ("../outside.go", "/absolute.go", "line\nbreak.go"):
            archive = report_archive([{"scope": "binary-changes", "findings": [
                {"tool": "semgrep", "rule": "go-secret-to-log", "path": path, "line": 1}]}])
            with self.assertRaises(publisher.PublishError):
                publisher.read_report(archive)

    def test_large_report_keeps_comment_bounded_with_full_report_link(self):
        scans = [{"commit": "a" * 40, "scope": "binary-changes", "findings": [
            {"tool": "semgrep", "rule": "go-secret-to-log", "path": "src/" + "字" * 500 + str(line) + ".go", "line": line}
            for line in range(1, 201)]}]
        body = publisher.render_comment(FakeGitHub().run, scans, "example/project")
        self.assertLess(len(body.encode()), publisher.MAX_COMMENT_BYTES)
        self.assertIn("200 candidate findings", body)
        self.assertIn("/actions/runs/100", body)
        self.assertIn("of 200 unique findings", body)

    def test_download_redirect_does_not_forward_token_to_blob_storage(self):
        handler = publisher.SafeRedirect()
        request = Request("https://api.github.com/report", headers={"Authorization": "Bearer unit-test-token"})
        redirected = handler.redirect_request(request, None, 302, "", {}, "https://storage.example/report.zip")
        self.assertFalse(redirected.has_header("Authorization"))
        same_host = handler.redirect_request(request, None, 302, "", {}, "https://api.github.com/renamed")
        self.assertTrue(same_host.has_header("Authorization"))
        with self.assertRaises(publisher.PublishError):
            handler.redirect_request(request, None, 302, "", {}, "http://storage.example/report.zip")

    def test_other_workflow_or_event_is_never_published(self):
        api = FakeGitHub()
        api.run["path"] = ".github/workflows/unrelated.yml"
        self.assertEqual(publisher.publish(api, 100, "example/project"), [])
        self.assertEqual(api.writes, [])


if __name__ == "__main__":
    unittest.main()
