"""Publish a bounded, collapsible PR comment from an unprivileged scan report."""

import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from security_report import group_findings, md_text, rule_help, source_location


MARKER = "<!-- product-security-summary -->"
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_COMMENT_BYTES = 55_000


class PublishError(Exception):
    pass


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        redirected = super().redirect_request(request, fp, code, message, headers, target)
        if redirected and urlsplit(request.full_url).netloc != urlsplit(target).netloc:
            # Artifact downloads redirect to blob storage. Never forward the
            # repository token to a different host.
            redirected.remove_header("Authorization")
        if redirected and urlsplit(target).scheme != "https":
            raise PublishError("Refusing an insecure download redirect")
        return redirected


class GitHub:
    def __init__(self, repository, token, api_url="https://api.github.com"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise PublishError("Invalid repository")
        if urlsplit(api_url).scheme != "https":
            raise PublishError("Invalid API URL")
        self.prefix = f"/repos/{repository}"
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.opener = build_opener(SafeRedirect())

    def request(self, method, path, data=None, binary=False):
        body = json.dumps(data).encode() if data is not None else None
        request = Request(self.api_url + self.prefix + path, data=body, method=method, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
            "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "product-security-summary"})
        try:
            with self.opener.open(request, timeout=60) as response:
                payload = response.read(32 * 1024 * 1024 + 1)
        except HTTPError as error:
            raise PublishError(f"GitHub API returned HTTP {error.code}") from None
        if len(payload) > 32 * 1024 * 1024:
            raise PublishError("GitHub response exceeds report size limit")
        return payload if binary else json.loads(payload)

    def pages(self, path, key=None):
        items = []
        for page in range(1, 101):
            separator = "&" if "?" in path else "?"
            data = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            batch = data[key] if key else data
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise PublishError("GitHub pagination limit reached")


def read_report(archive):
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        entry = bundle.getinfo("code.json")
        if entry.file_size > MAX_REPORT_BYTES:
            raise PublishError("Report exceeds size limit")
        report = json.loads(bundle.read(entry))
    if report.get("schema_version") != 1 or not isinstance(report.get("scans"), list):
        raise PublishError("Unsupported report schema")
    if not report["scans"] or len(report["scans"]) > 10_000:
        raise PublishError("Invalid scan count")
    scans = []
    count = 0
    for scan in report["scans"]:
        sha = scan.get("commit", "")
        if sha and not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
            raise PublishError("Invalid scan revision")
        scope = scan.get("scope", "unknown")
        if not isinstance(scope, str) or not re.fullmatch(r"[a-z-]{1,40}", scope):
            raise PublishError("Invalid scan scope")
        cleaned = {"commit": sha, "scope": scope, "findings": []}
        if scan.get("error"):
            cleaned["error"] = "Scan did not complete"
        for item in scan.get("findings", []):
            count += 1
            path = item.get("path", "")
            rule = item.get("rule", "")
            line = item.get("line")
            if (count > 100_000 or not isinstance(path, str) or not path or len(path) > 1024
                    or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                    or any(ord(character) < 32 for character in path)):
                raise PublishError("Invalid finding path or count")
            if not isinstance(rule, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,99}", rule):
                raise PublishError("Invalid finding rule")
            if item.get("tool") not in {"semgrep", "gitleaks", "message-policy"} or type(line) is not int or not 1 <= line <= 100_000_000:
                raise PublishError("Invalid finding metadata")
            # Never publish artifact-provided message, remediation, Markdown,
            # matched values or summary counts. Recompute from allowed metadata.
            cleaned["findings"].append({"tool": item["tool"], "rule": rule, "path": path, "line": line})
        scans.append(cleaned)
    return scans


def render_comment(run, scans, repository, server="https://github.com", detail_limit=40):
    run_id, attempt = int(run["id"]), int(run["run_attempt"])
    url = f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    if scans is None:
        findings, stats = [], None
        status = "INCOMPLETE"
    else:
        findings, stats = group_findings(scans)
        status = "FAILED" if stats["unique_findings"] else "PASSED"
        if stats["scanner_errors"] or run.get("conclusion") not in {"success", "failure"}:
            status = "INCOMPLETE"
        elif run.get("conclusion") == "failure" and status == "PASSED":
            status = "INCOMPLETE"
    title = f"Security scan: {status}"
    if stats:
        title += f" — {stats['unique_findings']} candidate findings in {stats['files']} files"
    lines = [MARKER, f"<!-- source-run:{run_id}:{attempt} -->", "<details>", f"<summary>{title}</summary>", "",
             f"[Full summary, scan logs and report artifacts]({url})", "",
             "Scope: product-binary compilation inputs. Results are candidates requiring review.", ""]
    if stats is None:
        lines += ["A valid report was not available. Inspect the source run's checkout, tool self-tests and artifact upload steps; the scan is not verified."]
    else:
        if all(scan.get("scope") == "binary-changes" for scan in scans):
            lines += ["Coverage: changed product inputs only. This does not establish that the complete product is clean.", ""]
        elif any(scan.get("scope") == "binary-full" for scan in scans):
            lines += ["Coverage includes a full-product scan of the selected compilation inputs.", ""]
        lines += ["| Measure | Count |", "| --- | ---: |",
                  f"| Unique candidate findings | {stats['unique_findings']} |",
                  f"| File/line locations | {stats['locations']} |",
                  f"| Files affected | {stats['files']} |",
                  f"| Findings reported by latest scan | {stats['latest_findings']} |",
                  f"| Total occurrences across {stats['snapshots']} scans | {stats['occurrences']} |",
                  f"| Scanner errors | {stats['scanner_errors']} |", ""]
        if status == "INCOMPLETE":
            lines += ["Analysis or tool self-tests did not complete successfully. Resolve the source-run failure before accepting this scan.", ""]
        from collections import Counter
        counts = Counter((item["tool"], item["rule"]) for item in findings)
        if counts:
            lines += ["<details>", "<summary>Findings by rule</summary>", "",
                      "| Rule | Unique findings |", "| --- | ---: |"]
            for (_, rule), count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:20]:
                lines.append(f"| {md_text(rule)} | {count} |")
            lines += ["", "</details>", "", "<details>", "<summary>Locations and suggested changes</summary>", "",
                      "| File and line | Rule | Reported by latest scan | Suggested change |", "| --- | --- | --- | --- |"]
            environment = {"GITHUB_SERVER_URL": server, "GITHUB_REPOSITORY": repository}
            for item in findings[:detail_limit]:
                latest = "Yes" if item["present_in_latest_snapshot"] else ("Unknown" if scans[-1].get("error") else "Earlier scan only")
                lines.append(f"| {source_location(item, environment)} | {md_text(item['rule'])} | {latest} | {md_text(rule_help(item['tool'], item['rule'])[1])} |")
            lines += ["", f"Showing {min(detail_limit, len(findings))} of {len(findings)} unique findings. The full report lists every location and correction.",
                      "", "</details>"]
    lines += ["", "This comment is updated after each completed scan; earlier-only PR findings remain subject to the commit check.", "", "</details>"]
    # File names can contain '@'. Keep them readable without notifying users
    # named by untrusted repository content.
    body = "\n".join(lines).replace("@", "@\u200b")
    if len(body.encode()) > MAX_COMMENT_BYTES:
        if detail_limit:
            return render_comment(run, scans, repository, server, detail_limit // 2)
        raise PublishError("Comment exceeds size limit")
    return body


def publish(api, run_id, repository, server="https://github.com"):
    run = api.request("GET", f"/actions/runs/{int(run_id)}")
    if (run.get("event") != "pull_request" or run.get("status") != "completed"
            or run.get("path", "").split("@", 1)[0] != ".github/workflows/security-checks.yml"):
        return []
    head_repository = (run.get("head_repository") or {}).get("full_name")
    if not head_repository or not re.fullmatch(r"[0-9a-fA-F]{40,64}", run.get("head_sha", "")):
        return []
    candidates = run.get("pull_requests", [])
    if not candidates:
        try:
            candidates = api.pages(f"/commits/{run['head_sha']}/pulls")
        except PublishError:
            candidates = []
    if not candidates:
        owner = head_repository.split("/")[0]
        candidates = api.pages("/pulls?" + urlencode({"state": "all", "head": owner + ":" + run["head_branch"]}))
    pulls = []
    for number in sorted({int(item["number"]) for item in candidates}):
        pull = api.request("GET", f"/pulls/{number}")
        same_head = (pull["head"]["sha"] == run["head_sha"]
                     and (pull["head"].get("repo") or {}).get("full_name") == head_repository)
        merged_result = pull.get("merged") and pull.get("merge_commit_sha") == run["head_sha"]
        if (pull["base"]["repo"]["full_name"] == repository and (same_head or merged_result)
                and (pull.get("state") == "open" or pull.get("merged"))):
            pulls.append(number)
    if not pulls:
        return []
    scans = None
    artifacts = api.pages(f"/actions/runs/{int(run_id)}/artifacts", "artifacts")
    name = f"security-checks-{run_id}-{run['run_attempt']}"
    matches = [item for item in artifacts if item["name"] == name and not item.get("expired")]
    if len(matches) == 1:
        try:
            archive = api.request("GET", f"/actions/artifacts/{int(matches[0]['id'])}/zip", binary=True)
            scans = read_report(archive)
        except (PublishError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile):
            # An unavailable or malformed report gets an explicit incomplete
            # comment; its contents are never evaluated or echoed.
            pass
    body = render_comment(run, scans, repository, server)
    changed = []
    for number in pulls:
        comments = api.pages(f"/issues/{number}/comments")
        owned = [item for item in comments if item.get("user", {}).get("login") == "github-actions[bot]"
                 and item.get("user", {}).get("type") == "Bot" and MARKER in (item.get("body") or "")]
        existing = max(owned, key=lambda item: item["id"]) if owned else None
        if existing:
            previous = re.search(r"<!-- source-run:(\d+):(\d+) -->", existing["body"])
            if previous and tuple(map(int, previous.groups())) > (int(run_id), int(run["run_attempt"])):
                continue
            api.request("PATCH", f"/issues/comments/{existing['id']}", {"body": body})
        else:
            api.request("POST", f"/issues/{number}/comments", {"body": body})
        changed.append(number)
    return changed


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        api = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"],
                     os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        changed = publish(api, event["workflow_run"]["id"], os.environ["GITHUB_REPOSITORY"],
                          os.environ.get("GITHUB_SERVER_URL", "https://github.com"))
        print(f"Updated security summary on {len(changed)} matching pull request(s).")
        return 0
    except (PublishError, ValueError, KeyError, OSError):
        print("Unable to publish the security summary; check repository permissions and source-run metadata.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
