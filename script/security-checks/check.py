#!/usr/bin/env python3
"""Strict commit-snapshot checks and private build-log scanning.

Only trusted policy and tool binaries are executed. Source snapshots are data;
their scripts, Git hooks, .gitleaksignore and Semgrep configuration are not used.
Reports intentionally omit source, matches, metavariables and credential values.
"""

import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile


POLICY = Path(__file__).resolve().parents[2] / ".github/security-checks"
EXCLUDES = ["vendor", "node_modules", ".git", "bin", "dist", "build",
            "*_test.go", "*.pb.go", "*.generated.*", "go.sum",
            "script/security-checks/tests"]
ACTION = re.compile(
    r"\b(?:check|verify|retry|restart|configure|set|provide|specify|remove|"
    r"replace|install|enable|disable|ensure|use|inspect|review|run|update|"
    r"correct|enter|select|restore|renew|increase|reduce|see https?://)\b", re.I)
ESCALATION = re.compile(
    r"\b(?:contact\s+(?:(?:your|the|technical)\s+)*"
    r"(?:support|administrator|admin)|open\s+(?:a\s+)?(?:support\s+)?case)\b", re.I)
VAGUE = re.compile(r"^(?:an? )?(?:unknown|unexpected|server|generic) "
                   r"(?:error|failure)(?: occurred)?[.!\s]*$", re.I)


class ScanError(Exception):
    """A scanner/configuration error must fail closed, never count as clean."""


def run(command, *, cwd=None, accepted=(0,), input=None, env=None):
    result = subprocess.run(command, cwd=cwd, input=input, env=env, capture_output=True)
    if result.returncode not in accepted:
        # Tool stderr can contain the offending source/secret. Never echo it.
        raise ScanError(f"{Path(command[0]).name} failed with exit {result.returncode}")
    return result


def git(repo, *args):
    return run(["git", "-C", str(repo), *args]).stdout


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
            raise ScanError("Submodule source must be scanned explicitly")
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


def finding(tool, rule, path, line, message):
    return {"tool": tool, "rule": rule, "path": str(path),
            "line": int(line), "message": message}


def scan_secrets(root, *, logs=False):
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
                        "build.log" if logs else relative_path(item["File"], root),
                        item["StartLine"], "Possible plaintext credential; remove or redact it.")
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
                   "--max-target-bytes", "0", "--timeout", "0"]
        for exclusion in [*EXCLUDES, ".semgrepignore"]:
            command.extend(["--exclude", exclusion])
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
                findings.append(finding("semgrep", rule, path, line, item["extra"]["message"]))
        misspelled = misspelled_messages([text for text, _, _ in messages], temporary)
        for index, (text, path, line) in enumerate(messages):
            findings.extend(message_findings(text, path, line, misspelled=index in misspelled))
        return findings


def write_report(path, scans):
    report = {"schema_version": 1, "checks": ["secrets", "error-messages", "identifier-handling"],
              "scans": scans}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    count = sum(len(scan.get("findings", [])) for scan in scans)
    errors = sum(bool(scan.get("error")) for scan in scans)
    summary = f"Security checks: {len(scans)} scan(s), {count} finding(s), {errors} scanner error(s)."
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(summary + " See the redacted report artifact for locations and rules.\n")
    return 1 if count or errors or any(scan.get("command_exit", 0) for scan in scans) else 0


def scan_revision(repo, sha):
    entry = {"commit": sha, "scope": "full-codebase", "findings": []}
    with tempfile.TemporaryDirectory(prefix="security-source-") as temporary:
        root = Path(temporary)
        try:
            export_snapshot(repo, sha, root)
        except (ScanError, ValueError, OSError):
            entry["error"] = "The complete source snapshot could not be exported."
            return entry
        for name, scanner in (("gitleaks", scan_secrets), ("semgrep", scan_code)):
            try:
                entry["findings"].extend(scanner(root))
            except (ScanError, ValueError, KeyError, OSError) as error:
                entry["error"] = "Scanner failed or analysis was incomplete; rerun locally to diagnose."
                entry.setdefault("scanner_errors", []).append({
                    "tool": name,
                    "reason": str(error) if isinstance(error, ScanError) else type(error).__name__})
    print(f"Scanned {sha}: {len(entry['findings'])} finding(s)")
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["event", "full", "logs"])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--report", type=Path, required=True)
    args, command = parser.parse_known_args()
    if command and command[0] == "--":
        command.pop(0)
    scans = []
    try:
        if args.mode == "logs":
            if not command:
                raise ScanError("A build/test command is required after --")
            with tempfile.TemporaryDirectory(prefix="security-logs-") as temporary:
                log = Path(temporary) / "build.log"
                with log.open("wb") as stream:
                    result = subprocess.run(command, cwd=args.repo, stdout=stream, stderr=subprocess.STDOUT)
                scan = {"scope": "build-logs", "command_exit": result.returncode,
                        "findings": scan_secrets(Path(temporary), logs=True)}
                scans.append(scan)
                print(f"Build/test command exited {result.returncode}; raw logs are not published.")
        else:
            if command:
                raise ScanError("Unexpected command arguments")
            repo = args.repo.resolve()
            if args.mode == "event":
                event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
                revisions = select_commits(repo, event)
            else:
                sha = args.sha or git(repo, "rev-parse", "HEAD").decode().strip()
                revisions = [commit(repo, sha)]
            # Do not short-circuit: a failing early commit must not prevent
            # later commits/full head from being scanned and reported.
            for sha in revisions:
                scans.append(scan_revision(repo, sha))
    except (ScanError, ValueError, KeyError, OSError):
        scans.append({"scope": args.mode, "error": "Scan could not complete; missing history, tools or invalid input.", "findings": []})
    return write_report(args.report, scans)


if __name__ == "__main__":
    sys.exit(main())
