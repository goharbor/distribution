# Security checks

These checks reduce credential exposure in source code and build logs, improve
failure handling, and catch identifier comparisons that can weaken validation
or conflate distinct resources.

## When checks run

The `Security checks` job runs on every PR update, every branch
push, merge-queue event and manual dispatch. There are no branch or path
filters that skip source changes, and newer runs do not cancel older runs.

For PRs, Git history enumerates **every commit in `base..head`**, including
intermediate commits that introduce a defect later removed from the PR head.
Each commit's complete tracked tree is scanned. The synthetic merge result is
also scanned to catch integration defects. A push scans every commit in
`before..after` and the complete final tree, covering merge, squash, rebase and
direct pushes. A new feature branch with an all-zero `before` scans every
commit unique to that branch relative to the default branch, plus its full
head. An initial default-branch push scans all reachable history. Merge queues
and manual dispatch scan the complete resulting tree.
Missing Git history fails the job rather than silently narrowing the range.

Checks are strict: existing findings also fail. There is no generated baseline,
automatic allowlist, or initial report-only period. Remediate existing findings
and verify the first full scan before requiring the check for all PRs. Large
historical ranges can require a larger job timeout; a timeout never counts as
success.

The existing `CI / build` job scans the combined output of its setup, builds,
validation, tests and coverage commands. The build's original exit status is
preserved, and detected log credentials or scanner errors also fail the job.
Raw build output is captured privately in an ephemeral runner directory and
deleted after scanning; it is never printed or uploaded. To diagnose a build
failure, reproduce the build locally. Only redacted scanner reports are retained
as Actions artifacts for 14 days.

Repository administrators must configure branch protection/rulesets to require
both `Security checks` and `build`, including the merge queue if
used. A failing workflow alone does not prevent a merge without required status
checks. Protect review of `.github/security-checks/`, this workflow,
`ci.yml`, and `script/security-checks/` using the repository's code owners
and review rules: changes to CI policy are security-sensitive.

## Coverage

| Area | Automated checks |
| --- | --- |
| Credential security | Pinned Gitleaks credential/private-key detectors; low-entropy labelled secret assignments in configuration/logs; Go literal production credentials; intraprocedural Go credential-to-log/console taint flow (including debug and structured log fields); shell credential-variable echo/printf and shell tracing. |
| Safe failure handling | Go error constructors, HTTP error text, error `Message` fields and `WithMessage` literals; codespell dictionary checks and repeated words; support-only escalation, empty/generic messages and missing remediation; simple swallowed error branches, raw HTTP downstream errors and raw stack output. Findings block the check. |
| Identifier handling | Case-sensitive comparison of recognizable DNS/FQDN/hostname and certificate-alias identifiers; discarding DNS spelling in storage assignments; case-folding recognizable cluster names; case-sensitive comparisons of recognizable UUID string names or UUID `.String()` values. Byte-array UUID equality remains valid. |

Code patterns use Semgrep Community Edition and local, versioned rules; no
registry rules, Semgrep account, model API, repository secret or license is
needed. Tool versions are pinned in `requirements.txt` and `install-tools.sh`.
The installer verifies the upstream Gitleaks archive checksum before executing
the binary. See [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
and [Gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration).

Static analysis does not prove the security or correctness of every runtime
path. These checks cannot establish all grammar, a message's factual root
cause, correct cross-component translation, arbitrary alias names/types,
transitive credential-bearing DTOs or interprocedural sanitization. Certificate
aliases must follow their backing store's published contract. OS/non-OS user
names require the specific OS or identity-provider contract; they are not
globally case-folded. Protocol-defined error strings must be reviewed against
their specification before changing their text. Extend rules and add regression
fixtures for confirmed gaps and contract-specific exceptions; do not apply
blanket case normalization or guess that a helper named `mask` is safe.

Production Semgrep scans exclude Go test files, generated protobuf/files,
third-party/build directories, `go.sum` and scanner regression fixtures.
Gitleaks scans all regular tracked files, including ignored-by-Git and
export-ignored files. Only the low-entropy default-secret detector exempts
`*_test.go`; built-in real-key/token detectors still
scan Go tests. Synthetic scanner fixtures are exempt from secret detection.
Symlinks are not followed. Submodules fail closed until explicitly integrated.
Target `.semgrepignore`, `.gitleaksignore`, `.gitleaks.toml`, `nosemgrep` and
`gitleaks:allow` comments cannot suppress a source finding.

The log check covers output from the existing CI build/test process. It does
not exercise deployed services or scan Docker image build logs and diagnostic
archives. Supplement these checks with runtime tests of authentication, input
validation and public error responses. Do not expose service credentials to
fork PR jobs.

## Run locally

Install Python 3.12+, Git, curl and the pinned scanners in an isolated environment:

```sh
python3 -m venv /tmp/security-venv
. /tmp/security-venv/bin/activate
python -m pip install -r .github/security-checks/requirements.txt
bash script/security-checks/install-tools.sh /tmp/security-bin
export PATH="/tmp/security-bin:$PATH"

python -m unittest discover -s script/security-checks/tests -v
semgrep --test --config .github/security-checks/rules script/security-checks/tests/fixtures
python script/security-checks/check.py full --report /tmp/security.json
python script/security-checks/check.py logs --report /tmp/log-security.json -- go test ./...
```

`full` scans committed `HEAD` by default. Use `--sha` with a full commit SHA
to select another revision; uncommitted work is not included. `event` reads
`GITHUB_EVENT_NAME`, `GITHUB_EVENT_PATH` and `GITHUB_SHA` from the Actions runner
and follows the event's complete Git range, not the truncated webhook commit
list. All selected snapshots are processed even after earlier findings.

The JSON reports list each commit, scope, tool, rule, path and line. They omit
source snippets, matched secrets, taint traces and message metavariables. A
scanner failure is reported separately and always blocks the check. Never
upload a raw scanner report or unreviewed build log: either can contain secrets.
