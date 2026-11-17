#!/usr/bin/env python3
"""Scan changed or complete product-binary compilation inputs.

Only trusted policy and tool binaries are executed. Source snapshots are data;
their scripts, Git hooks, .gitleaksignore and Semgrep configuration are not used.
Reports intentionally omit source, matches, metavariables and credential values.
"""

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

from security_report import group_findings, render_markdown
from binary_scope import ScopeError, discover_files, load_targets


POLICY = Path(__file__).resolve().parents[2] / ".github/security-checks"
ACTION = re.compile(
    r"\b(?:check|verify|retry|restart|configure|set|provide|specify|remove|"
    r"replace|install|enable|disable|ensure|use|inspect|review|run|update|"
    r"correct|enter|select|restore|renew|increase|reduce|see https?://)\b", re.I)
ESCALATION = re.compile(
    r"\b(?:contact\s+(?:(?:your|the|technical)\s+)*"
    r"(?:support|administrator|admin)|open\s+(?:a\s+)?(?:support\s+)?case)\b", re.I)
VAGUE = re.compile(r"^(?:an? )?(?:unknown|unexpected|server|generic) "
                   r"(?:error|failure)(?: occurred)?[.!\s]*$", re.I)


class ScanError(ScopeError):
    """A scanner/configuration error must fail closed, never count as clean."""


def run(command, *, cwd=None, accepted=(0,), input=None, env=None):
    result = subprocess.run(command, cwd=cwd, input=input, env=env, capture_output=True)
    if result.returncode not in accepted:
        # Tool stderr can contain the offending source/secret. Never echo it.
        raise ScanError(f"{Path(command[0]).name} failed with exit {result.returncode}")
    return result


def git(repo, *args):
    return run(["git", "--literal-pathspecs", "-C", str(repo), *args]).stdout


def commit(repo, value):
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise ScanError("Expected a complete commit SHA")
    return git(repo, "rev-parse", "--verify", value + "^{commit}").decode().strip()


def select_commits(repo, event):
    """Use Git graph traversal, never the truncated webhook commits array."""
    kind = os.environ["GITHUB_EVENT_NAME"]
    if kind == "pull_request":
        base = commit(repo, event["pull_request"]["base"]["sha"])
        head = commit(repo, event["pull_request"]["head"]["sha"])
        revisions = git(repo, "rev-list", "--reverse", "--topo-order", f"{base}..{head}")
    elif kind == "push":
        head = commit(repo, event["after"])
        before = event["before"]
        if set(before) == {"0"}:
            # A feature branch's shared default-branch history was already
            # checked there. Scan every commit unique to the new branch.
            default = event.get("repository", {}).get("default_branch")
            default_ref = "refs/remotes/origin/" + default if default else None
            if default_ref and event.get("ref") != "refs/heads/" + default:
                base = git(repo, "rev-parse", "--verify", default_ref).decode().strip()
                args = (f"{commit(repo, base)}..{head}",)
            else:
                args = (head,)
        else:
            args = (f"{commit(repo, before)}..{head}",)
        revisions = git(repo, "rev-list", "--reverse", "--topo-order", *args)
    else:
        head = commit(repo, os.environ["GITHUB_SHA"])
        revisions = b""
    # Also scan the synthetic PR/merge-queue result, since integration with the
    # base branch can introduce a defect absent from either branch alone.
    resulting = commit(repo, os.environ.get("GITHUB_SHA", head))
    return list(dict.fromkeys([*revisions.decode().splitlines(), head, resulting]))


def first_parent(repo, sha):
    parents = git(repo, "rev-list", "--parents", "-n", "1", sha).decode().split()
    return parents[1] if len(parents) > 1 else None


def select_scans(repo, event):
    kind = os.environ["GITHUB_EVENT_NAME"]
    if kind == "pull_request" and event.get("action") == "closed":
        if not event["pull_request"].get("merged"):
            return []
        return [(commit(repo, event["pull_request"]["merge_commit_sha"]), None, "full")]
    revisions = select_commits(repo, event)
    if kind not in {"pull_request", "push", "merge_group"}:
        return [(revisions[-1], None, "full")]
    plan = []
    for sha in revisions:
        base = first_parent(repo, sha)
        if kind == "pull_request" and sha != event["pull_request"]["head"]["sha"] and sha == os.environ["GITHUB_SHA"]:
            base = commit(repo, event["pull_request"]["base"]["sha"])
        elif kind == "merge_group" and event.get("merge_group", {}).get("base_sha"):
            base = commit(repo, event["merge_group"]["base_sha"])
        plan.append((sha, base, "changes"))
    if kind == "push":
        reference = event.get("ref", "")
        default = event.get("repository", {}).get("default_branch", "main")
        if reference == "refs/heads/" + default or reference.startswith("refs/heads/release/"):
            plan.append((commit(repo, event["after"]), None, "full"))
    return plan


def changed_ranges(repo, sha, base, paths):
    ranges = {}
    if base:
        names = git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, sha)
    else:
        names = git(repo, "diff-tree", "--root", "--no-commit-id", "--no-renames", "--name-only", "-r", "-z", sha)
    changed = set(filter(None, names.decode().split("\0")))
    for path in sorted(set(paths) & changed):
        if base:
            command = ("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0", base, sha, "--", path)
        else:
            command = ("show", "--format=", "--root", "--no-ext-diff", "--no-textconv", "--unified=0", sha, "--", path)
        hunks = []
        for line in git(repo, *command).decode(errors="replace").splitlines():
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                start, count = int(match[1]), int(match[2] or 1)
                if count:
                    hunks.append((start, start + count - 1))
        if hunks:
            ranges[path] = hunks
    return ranges


def touches_change(item, changes):
    spans = [(item["line"], item.get("end_line", item["line"]))]
    spans.extend(tuple(span) for span in item.get("related_ranges", []))
    return any(start <= changed_end and changed_start <= end
               for start, end in spans for changed_start, changed_end in changes.get(item["path"], []))


def export_snapshot(repo, sha, destination):
    # git archive respects export-ignore attributes. Explicit ls-tree/cat-file
    # enumeration instead guarantees a PR cannot hide files using attributes.
    entries = git(repo, "ls-tree", "-rz", "--full-tree", sha).split(b"\0")
    blobs = []
    for entry in filter(None, entries):
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        path = PurePosixPath(os.fsdecode(raw_path))
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
            raise ScanError("Unsafe source path")
        if mode == b"160000":
            # Unrelated submodules are outside the selected product. A product
            # import that needs this unmaterialized source fails Go discovery.
            continue
        if mode == b"120000":
            # Do not dereference attacker-controlled symlinks outside the tree.
            continue
        if kind != b"blob":
            raise ScanError("Unsupported source tree entry")
        blobs.append((path, oid))
    # Batch objects in one Git process; starting Git once per file is costly
    # when a multi-commit PR scans many complete trees.
    stream = io.BytesIO(run(["git", "-C", str(repo), "cat-file", "--batch"],
                          input=b"".join(oid + b"\n" for _, oid in blobs)).stdout)
    for path, oid in blobs:
        header = stream.readline().split()
        if len(header) != 3 or header[:2] != [oid, b"blob"]:
            raise ScanError("Invalid Git object response")
        size = int(header[2])
        data = stream.read(size)
        if len(data) != size or stream.read(1) != b"\n":
            raise ScanError("Incomplete Git object")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def finding(tool, rule, path, line, message, end_line=None):
    return {"tool": tool, "rule": rule, "path": str(path),
            "line": int(line), "end_line": int(end_line or line), "message": message}


def scan_secrets(root):
    with tempfile.TemporaryDirectory(prefix="gitleaks-report-") as temporary:
        report = Path(temporary) / "report.json"
        # Run from a trusted, empty working directory. No target-supplied ignore
        # file/configuration can silently allowlist a credential.
        result = run(["gitleaks", "dir", str(root), "--config", str(POLICY / "gitleaks.toml"),
                      "--redact=100", "--no-banner", "--ignore-gitleaks-allow",
                      "--gitleaks-ignore-path", str(Path(temporary) / "no-ignore-file"),
                      "--max-target-megabytes", "0", "--report-format", "json",
                      "--report-path", str(report), "--exit-code", "10"],
                     cwd=temporary, accepted=(0, 10))
        if not report.exists():
            raise ScanError("Gitleaks did not produce a report")
        raw = json.loads(report.read_text())
        if bool(raw) != (result.returncode == 10):
            raise ScanError("Gitleaks exit code/report mismatch")
        return [finding("gitleaks", item["RuleID"],
                        relative_path(item["File"], root), item["StartLine"],
                        "Possible plaintext credential; remove or redact it.", item.get("EndLine"))
                for item in raw]


def relative_path(path, root):
    source = Path(path)
    return source.relative_to(root).as_posix() if source.is_absolute() else source.as_posix()


def message_findings(text, path, line, *, misspelled=False):
    issues = []
    self_service = False
    for clause in re.split(r"[.!?;\n]", text):
        escalation = ESCALATION.search(clause)
        if ACTION.search(clause[:escalation.start()] if escalation else clause):
            self_service = True
    if ESCALATION.search(text) and not self_service:
        issues.append(("error-contact-only", "Explain the cause and provide a self-service step before escalation."))
    if not text.strip() or VAGUE.fullmatch(text.strip()):
        issues.append(("error-cryptic", "Explain the failing task, specific cause and remediation."))
    elif not ACTION.search(text) and not ESCALATION.search(text):
        issues.append(("error-missing-remediation", "Add a concrete remediation step or troubleshooting reference."))
    if re.search(r"\b(\w+)\s+\1\b", text, re.I):
        issues.append(("error-repeated-word", "Correct a repeated word in the error message."))
    if misspelled:
        issues.append(("error-spelling", "Correct spelling in the error message (codespell)."))
    return [finding("message-policy", rule, path, line, message)
            for rule, message in issues]


def misspelled_messages(messages, temporary):
    """One dictionary process per tree, scoped only to extracted messages."""
    if not messages:
        return set()
    textfile = Path(temporary) / "messages.txt"
    textfile.write_text("\n".join(" ".join(text.splitlines()) for text in messages) + "\n")
    spelling = run(["codespell", "--quiet-level", "7", "--", str(textfile)], accepted=(0, 65))
    indices = {int(match) - 1 for match in re.findall(
        re.escape(str(textfile)) + r":(\d+):", spelling.stdout.decode())}
    if (spelling.returncode == 65) != bool(indices):
        raise ScanError("Unexpected codespell report format")
    return indices


def scan_code(root):
    with tempfile.TemporaryDirectory(prefix="semgrep-report-") as temporary:
        report = Path(temporary) / "report.json"
        # Disable ignore files, inline nosemgrep and automatic registry rules.
        command = ["semgrep", "scan", "--config", str(POLICY / "rules"),
                   "--json-output", str(report), "--quiet", "--strict", "--metrics=off",
                   "--disable-version-check", "--disable-nosem", "--no-git-ignore",
                   "--max-target-bytes", "0", "--timeout", "0",
                   "--exclude", ".semgrepignore"]
        # Semgrep also honors .semgrepignore outside Git ignore handling.
        # Source is already a disposable data-only snapshot; remove this input.
        for ignore in root.rglob(".semgrepignore"):
            ignore.unlink()
        (root / ".semgrepignore").write_text("")
        environment = {**os.environ,
                       "SEMGREP_LOG_FILE": str(Path(temporary) / "semgrep.log"),
                       "SEMGREP_SETTINGS_FILE": str(Path(temporary) / "settings.yml")}
        run([*command, "."], cwd=root, env=environment)
        raw = json.loads(report.read_text())
        if raw.get("errors"):
            raise ScanError("Semgrep reported incomplete analysis")
        findings = []
        messages = []
        for item in raw["results"]:
            rule = item["check_id"].split(".")[-1]
            path = relative_path(item["path"], root)
            line = item["start"]["line"]
            if rule == "go-error-message-text":
                # The public CLI JSON formatter omits metavars. Use Semgrep's
                # supported message interpolation to obtain the focused text.
                prefix = "Error message candidate: "
                message = item["extra"]["message"]
                if not message.startswith(prefix):
                    raise ScanError("Missing extracted error message")
                text = message[len(prefix):]
                messages.append((text, path, line))
            else:
                entry = finding("semgrep", rule, path, line, item["extra"]["message"], item["end"]["line"])
                findings.append(entry)
        misspelled = misspelled_messages([text for text, _, _ in messages], temporary)
        for index, (text, path, line) in enumerate(messages):
            findings.extend(message_findings(text, path, line, misspelled=index in misspelled))
        return findings


def match_key(item, root):
    # Compare matching code in changed files, not line numbers, so unrelated
    # line insertions do not make an old finding look newly introduced. The
    # digest stays in memory; source text and credential hashes are not reported.
    lines = (root / item["path"]).read_bytes().splitlines()
    source = b" ".join(b" ".join(lines[item["line"] - 1:item.get("end_line", item["line"])]).split())
    return item["tool"], item["rule"], item["path"], hashlib.sha256(source).digest()


def write_report(path, scans):
    findings, stats = group_findings(scans)
    report = {"schema_version": 1, "checks": ["secrets", "error-messages", "identifier-handling"],
              "summary": stats, "findings": findings, "scans": scans}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    markdown = render_markdown(scans, findings, stats, os.environ)
    markdown_path = path.with_suffix(".md")
    if markdown_path == path:
        markdown_path = path.with_name(path.stem + ".summary.md")
    markdown_path.write_text(markdown)
    summary = (f"Security checks: {stats['snapshots']} snapshot(s), {stats['unique_findings']} unique candidate finding(s) "
               f"at {stats['locations']} location(s) in {stats['files']} file(s), "
               f"{stats['occurrences']} total occurrence(s), {stats['scanner_errors']} scanner error(s), "
               f"{stats['failed_commands']} failed build/test command(s).")
    print(summary)
    print(f"Locations, reasons and suggested changes: {markdown_path.name} (report artifact / Actions job summary).")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        # Keep the job summary below the platform's per-step size limit; the
        # downloadable artifact always retains the complete location list.
        job_summary = markdown if len(markdown.encode("utf-8")) < 900_000 else render_markdown(
            scans, findings, stats, os.environ, detail_limit=100)
        if len(job_summary.encode("utf-8")) >= 900_000:
            job_summary = summary + "\nDownload the Markdown/JSON artifact for the complete report.\n"
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(job_summary)
    return 1 if stats["occurrences"] or stats["scanner_errors"] or stats["failed_commands"] else 0


def scan_revision(repo, sha, base=None, mode="full", scope_cache=None):
    entry = {"commit": sha, "base": base, "scope": "binary-" + mode, "findings": []}
    scope_cache = scope_cache if scope_cache is not None else {}
    with tempfile.TemporaryDirectory(prefix="security-source-") as temporary:
        root = Path(temporary) / "source"
        root.mkdir()
        try:
            export_snapshot(repo, sha, root)
            targets = load_targets(POLICY / "targets.json")
            if sha not in scope_cache:
                scope_cache[sha] = discover_files(root, targets)
            compiled = scope_cache[sha]
            selected = set(compiled)
            changes = {}
            newly_compiled = set()
            if mode == "changes":
                changes = changed_ranges(repo, sha, base, compiled)
                if base and base not in scope_cache:
                    before = Path(temporary) / "before"
                    before.mkdir()
                    export_snapshot(repo, base, before)
                    scope_cache[base] = discover_files(before, targets, allow_missing=True)
                newly_compiled = compiled - scope_cache.get(base, set())
                selected = set(changes) | newly_compiled
            entry["product"] = {"entrypoints": targets["entrypoints"], "tags": targets["tags"],
                                "platforms": targets["platforms"], "compiled_files": len(compiled),
                                "scanned_files": len(selected), "files": sorted(selected)}
            inputs = Path(temporary) / "inputs"
            inputs.mkdir()
            for name in selected:
                destination = inputs / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / name, destination)
        except (ScopeError, ValueError, KeyError, OSError) as error:
            entry["error"] = str(error) if isinstance(error, ScopeError) else "Product build-input discovery failed."
            return entry
        if not selected:
            print(f"Scanned {sha} ({mode}): no product compilation inputs changed")
            return entry
        for name, scanner in (("gitleaks", scan_secrets), ("semgrep", scan_code)):
            try:
                results = scanner(inputs)
                if mode == "changes":
                    direct = [item for item in results if item["path"] in newly_compiled or touches_change(item, changes)]
                    indirect = [item for item in results if item not in direct]
                    if indirect:
                        before = Path(temporary) / "before"
                        if not before.exists():
                            before.mkdir()
                            export_snapshot(repo, base, before)
                        prior_inputs = Path(temporary) / (name + "-before")
                        prior_inputs.mkdir()
                        for path in selected & scope_cache.get(base, set()):
                            target = prior_inputs / path
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(before / path, target)
                        prior = scanner(prior_inputs)
                        counts = Counter(match_key(item, prior_inputs) for item in prior)
                        for item in indirect:
                            key = match_key(item, inputs)
                            if counts[key]:
                                counts[key] -= 1
                            else:
                                item["change_reason"] = "New finding in a changed product file"
                                direct.append(item)
                    results = direct
                entry["findings"].extend(results)
            except (ScopeError, ValueError, KeyError, OSError) as error:
                entry["error"] = "Scanner failed or analysis was incomplete; rerun locally to diagnose."
                entry.setdefault("scanner_errors", []).append({
                    "tool": name,
                    "reason": str(error) if isinstance(error, ScanError) else type(error).__name__})
    print(f"Scanned {sha} ({mode}, {len(selected)} product files): {len(entry['findings'])} finding(s)")
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["event", "full"])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    scans = []
    try:
        repo = args.repo.resolve()
        if args.mode == "event":
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
            plan = select_scans(repo, event)
        else:
            sha = args.sha or git(repo, "rev-parse", "HEAD").decode().strip()
            plan = [(commit(repo, sha), None, "full")]
        scope_cache = {}
        for sha, base, mode in plan:
            scans.append(scan_revision(repo, sha, base, mode, scope_cache))
    except (ScopeError, ValueError, KeyError, OSError):
        scans.append({"scope": args.mode, "error": "Scan could not complete; missing history, tools or invalid input.", "findings": []})
    return write_report(args.report, scans)


if __name__ == "__main__":
    sys.exit(main())
