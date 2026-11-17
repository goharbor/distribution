"""Build redacted, actionable reports from scanner metadata."""

from collections import Counter
from html import escape
import re
from urllib.parse import quote, urlsplit


RULE_HELP = {
    "go-secret-to-log": (
        "Possible credential flow to a log or console",
        "Trace the logged argument. Remove credential values or replace them with a fixed redaction before logging; "
        "add a test that a synthetic credential is absent from captured output. Confirm whether an existing formatter already redacts the value."),
    "go-hardcoded-secret": (
        "Literal production credential",
        "Load the credential from runtime input or a secret store. Remove the literal and rotate it if it was used as a real credential."),
    "labelled-plaintext-secret": (
        "Possible plaintext credential in configuration or logs",
        "Replace configuration defaults with runtime secret injection; remove credential values from log output. "
        "Confirm sample values are test-only before proposing a narrowly scoped, reviewed rule exception."),
    "private-key": (
        "Private-key material in a tracked file",
        "For production keys, remove the tracked key, load it securely at runtime, and rotate/revoke exposed credentials. "
        "For synthetic fixtures, verify test-only use and prefer generating an ephemeral key in test setup."),
    "jwt": (
        "Possible JSON Web Token",
        "Remove live tokens and rotate/revoke them if exposed. Generate synthetic tokens during tests instead of embedding reusable credentials; "
        "verify test fixtures cannot authenticate against a deployed service."),
    "generic-api-key": (
        "Possible API credential",
        "Confirm the value is a credential. Replace live values with runtime secret injection and rotate exposed keys. "
        "For synthetic fixtures or protocol samples, document evidence before changing the detector's scope."),
    "shell-secret-to-console": (
        "Credential variable printed by a shell command",
        "Remove the echo/printf of the credential variable. Print a fixed redacted marker or non-sensitive status instead."),
    "workflow-secret-to-console": (
        "Workflow secret printed to output",
        "Remove the echo/printf of the workflow secret; pass it through the command's supported secret input without printing it."),
    "shell-xtrace": (
        "Shell tracing can expose expanded credentials",
        "Remove set -x, set -o xtrace, or shell -x. Use targeted non-sensitive diagnostics and disable tracing before credential-bearing commands."),
    "go-swallowed-error": (
        "Error branch may silently report success",
        "Handle expected EOF/cancellation explicitly and propagate unexpected errors with operation context. "
        "Check the caller contract before changing an intentional recovery path; add a failure-path test."),
    "go-raw-error-http-response": (
        "Raw downstream error exposed in an HTTP response",
        "Map the error to an appropriate HTTP status and a safe, contextual response with a recovery step and correlation/log reference. "
        "Keep sensitive diagnostics out of the response."),
    "go-raw-stack-output": (
        "Raw stack output may reach users",
        "Return a safe contextual error and a correlation identifier. Send necessary diagnostics to a reviewed, access-controlled destination with secret redaction."),
    "error-contact-only": (
        "Error message provides only escalation",
        "Explain the failing operation and cause, then provide a concrete self-service step before suggesting escalation."),
    "error-cryptic": (
        "Empty or generic error message",
        "Trace the error to its user-facing response and add operation context, a specific cause and a recovery step. "
        "Preserve protocol-defined text and low-level sentinel errors when callers add the necessary context."),
    "error-missing-remediation": (
        "No recovery guidance detected in an error string",
        "Verify this text reaches an API/CLI user without added context. Add a concrete check, retry instruction or troubleshooting reference at that boundary. "
        "Preserve low-level sentinel and protocol-defined strings; review caller wrapping before classifying this heuristic match as a defect."),
    "error-repeated-word": (
        "Repeated word in an error message",
        "Correct the repeated word in the displayed message while preserving format placeholders and protocol-defined identifiers."),
    "error-spelling": (
        "Possible spelling error in an error message",
        "Correct the displayed text and preserve placeholders. Check technical terms and protocol names against the specification before changing them."),
    "go-case-sensitive-network-name": (
        "Case-sensitive DNS/FQDN/hostname comparison",
        "Use case-insensitive identity comparison, such as Go strings.EqualFold, while retaining the original spelling for storage and display."),
    "go-network-name-case-discard": (
        "DNS input spelling discarded during assignment",
        "Keep the original input for storage/output and use a separate normalized key for case-insensitive lookup or comparison."),
    "go-case-sensitive-certificate-alias": (
        "Certificate alias comparison needs contract review",
        "Check the backing certificate store's alias contract; use case-insensitive comparison only where required and preserve the stored spelling."),
    "go-case-sensitive-uuid-string": (
        "Case-sensitive comparison of UUID string output",
        "Parse both UUID strings into UUID values before comparing, or use strings.EqualFold for text. Typed UUID byte-array equality is valid."),
    "go-case-sensitive-uuid-text": (
        "Case-sensitive comparison of UUID text",
        "Accept mixed-case UUID input and compare parsed UUID values or use strings.EqualFold for text; a uniform output case is not required."),
    "go-cluster-name-case-fold": (
        "Case-sensitive resource names may be conflated",
        "Confirm the resource naming contract. For case-sensitive cluster names, preserve the input and compare exactly so differently cased names remain distinct."),
}


def rule_help(tool, rule):
    if rule in RULE_HELP:
        return RULE_HELP[rule]
    if tool == "gitleaks":
        return ("Possible provider credential", "Confirm whether the detected value is a live credential. Remove it from tracked files/logs, "
                "rotate it if exposed, and use runtime secret injection. Review synthetic fixtures individually.")
    return ("Scanner rule requires review", "Inspect the referenced location and rule definition, confirm the data flow or identifier contract, "
            "and add a regression test for the correction. Do not automatically suppress the finding.")


def group_findings(scans):
    """Deduplicate identical tool/rule/file/line entries across snapshots."""
    grouped = {}
    for index, scan in enumerate(scans):
        for item in scan.get("findings", []):
            key = (str(item.get("tool", "unknown")), str(item.get("rule", "unknown")),
                   str(item.get("path", "unknown")), int(item.get("line", 0)))
            if key not in grouped:
                tool, rule, path, line = key
                description, remediation = rule_help(tool, rule)
                grouped[key] = {"tool": tool, "rule": rule, "path": path, "line": line,
                                "description": description, "remediation": remediation,
                                "occurrences": 0, "snapshots": [], "present_in_latest_snapshot": False}
            group = grouped[key]
            group["occurrences"] += 1
            snapshot = {"scan": index + 1, "commit": scan.get("commit"), "scope": scan.get("scope", "unknown")}
            if snapshot not in group["snapshots"]:
                group["snapshots"].append(snapshot)
            group["present_in_latest_snapshot"] |= index == len(scans) - 1
    findings = sorted(grouped.values(), key=lambda item: (item["path"], item["line"], item["tool"], item["rule"]))
    for number, item in enumerate(findings, 1):
        item["id"] = f"F{number:04d}"
    latest = [item for item in findings if item["present_in_latest_snapshot"]]
    stats = {"snapshots": len(scans), "occurrences": sum(item["occurrences"] for item in findings),
             "unique_findings": len(findings), "locations": len({(item["path"], item["line"]) for item in findings}),
             "files": len({item["path"] for item in findings}), "latest_findings": len(latest),
             "scanner_errors": sum(bool(scan.get("error")) for scan in scans),
             "failed_commands": sum(bool(scan.get("command_exit", 0)) for scan in scans)}
    return findings, stats


def md_text(value):
    """Render untrusted file/rule names as text, never Markdown or HTML."""
    text = escape(" ".join(str(value).split()), quote=False)
    return re.sub(r"([\\`*_\[\]()|])", r"\\\1", text)


def source_location(item, environment):
    label = md_text(f"{item['path']}:{item['line']}")
    snapshot = item["snapshots"][-1]
    sha = snapshot.get("commit") or ""
    server = environment.get("GITHUB_SERVER_URL", "https://github.com")
    repository = environment.get("GITHUB_REPOSITORY", "")
    parsed = urlsplit(server)
    if (snapshot["scope"] != "build-logs" and re.fullmatch(r"[0-9a-fA-F]{40,64}", sha)
            and re.fullmatch(r"[\w.-]+/[\w.-]+", repository) and parsed.scheme == "https"
            and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment):
        url = f"{server.rstrip('/')}/{repository}/blob/{sha}/{quote(item['path'], safe='/')}#L{item['line']}"
        return f"[{label}]({url})"
    return label


def render_markdown(scans, findings, stats, environment, detail_limit=None):
    failed = stats["occurrences"] or stats["scanner_errors"] or stats["failed_commands"]
    lines = ["# Security scan summary", "", f"**Result: {'FAILED' if failed else 'PASSED'}.**", "",
             "| Measure | Count |", "| --- | ---: |",
             f"| Snapshots scanned | {stats['snapshots']} |",
             f"| Total occurrences across snapshots | {stats['occurrences']} |",
             f"| Unique candidate findings requiring review | {stats['unique_findings']} |",
             f"| Distinct file/line locations | {stats['locations']} |",
             f"| Files affected | {stats['files']} |",
             f"| Findings present in latest snapshot | {stats['latest_findings']} |",
             f"| Scanner errors | {stats['scanner_errors']} |",
             f"| Failed build/test commands | {stats['failed_commands']} |", "",
             "Repeated matches across commits are counted once by tool, rule, file and line. These are candidates, not confirmed vulnerabilities; "
             "one correction may resolve several findings, and line movement may create separate entries.", ""]
    if any(scan.get("error") for scan in scans):
        lines += ["**Analysis is incomplete.** Resolve scanner errors before treating these counts or a missing match as complete coverage.", ""]
    lines += ["## Scan results", "", "| Snapshot | Scope | Matches | Scanner | Build/test exit |",
              "| --- | --- | ---: | --- | ---: |"]
    for index, scan in enumerate(scans, 1):
        sha = scan.get("commit", "")
        label = sha[:12] if re.fullmatch(r"[0-9a-fA-F]{40,64}", sha) else f"Scan {index}"
        lines.append(f"| {md_text(label)} | {md_text(scan.get('scope', 'unknown'))} | {len(scan.get('findings', []))} | "
                     f"{'ERROR: incomplete' if scan.get('error') else 'Complete'} | {int(scan.get('command_exit', 0))} |")
    if stats["scanner_errors"] or stats["failed_commands"]:
        lines += ["", "Resolve failed scanner/tool installation, rule validation or missing-history checks using the preceding self-test output. "
                  "Reproduce a failed build/test command locally; raw build logs are intentionally not published."]
    lines += ["", "## Findings by rule", "", "| Rule | Unique findings | Why it was flagged | How to review or fix |",
              "| --- | ---: | --- | --- |"]
    counts = Counter((item["tool"], item["rule"]) for item in findings)
    for (tool, rule), count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])):
        description, remediation = rule_help(tool, rule)
        lines.append(f"| {md_text(rule)} | {count} | {md_text(description)} | {md_text(remediation)} |")
    lines += ["", "## Locations and suggested changes", "",
              "Links point to the most recent scanned commit containing each finding. No source snippets or credential values are included.", "",
              "| ID | File and line | Rule | Present in latest snapshot | Suggested change |",
              "| --- | --- | --- | --- | --- |"]
    latest_incomplete = bool(scans and scans[-1].get("error"))
    details = findings if detail_limit is None else findings[:detail_limit]
    for item in details:
        status = "Yes" if item["present_in_latest_snapshot"] else ("Unknown: latest analysis incomplete" if latest_incomplete else "Earlier snapshot only")
        lines.append(f"| {item['id']} | {source_location(item, environment)} | {md_text(item['rule'])} | {status} | {md_text(item['remediation'])} |")
    if not findings:
        lines.append("| - | No candidate findings reported | - | - | Resolve any scanner or build errors listed above before accepting the scan. |")
    if len(details) < len(findings):
        lines += ["", f"Showing {len(details)} of {len(findings)} unique findings. Download the Markdown/JSON artifact for every location and suggested change."]
    lines += ["", "## Review order", "",
              "1. Review potential credentials and log exposures first. Rotate/revoke live credentials when exposure is confirmed; verify synthetic fixtures are test-only.",
              "2. Review swallowed errors and identifier handling against caller and protocol contracts; add targeted failure/mixed-case tests for confirmed defects.",
              "3. For missing remediation, trace the text to the API/CLI response. Add guidance at that boundary; preserve sentinel and protocol-defined strings when callers already add context.",
              "4. Document confirmed false positives and adjust the precise detector with regression fixtures through code review. Do not blanket-ignore a directory or automatically baseline matches.",
              "5. Re-run the checks after corrections. Earlier PR commits remain blocking even when the final tree is fixed; amend/rebase the affected PR commits as appropriate, without rewriting shared branch history.", ""]
    return "\n".join(lines)
