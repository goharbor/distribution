# Product binary security checks

These checks audit repository-owned content used to build the released product
binary. They detect potential credentials, unsafe error handling and identifier
comparison defects without reporting unrelated tests, examples or build tools.

## Product scope

`.github/security-checks/targets.json` defines the product entrypoint, build tags
and release platforms. Its defaults follow the registry image and release
artifacts: `./cmd/registry`, tags `include_oss,include_gcs`, CGO disabled, and Linux
amd64, arm/v6, arm/v7, arm64, ppc64le and s390x.

For each revision and release platform, `go list -deps -json` resolves the
non-test package graph using read-only module resolution or the project's
default vendor mode. The union of repository-local compiler
inputs is scanned, including Go sources, selected generated code, applicable
native/assembly inputs, blank-imported packages, and resources included through
`go:embed`. Build tags, OS and architecture constraints determine membership.
The JSON report records the selected files and build profiles for each scan.

This excludes test files and test-only dependencies, fixtures that are not
embedded, unreferenced packages, helper commands, build scripts, CI workflows,
documentation and configuration files not embedded in the product. Even a
fixture-named resource is included if the product explicitly embeds it. The
standalone digest and API-descriptor helper commands are outside the default
released-product target. Add entrypoints or profiles when the shipped product
changes. External modules outside the repository are not scanned by this
repository-source check; tracked vendored inputs are included when selected.

File selection follows compiler inputs, not linker symbol liveness. A selected
Go file may contain functions later discarded by the linker. Scope discovery
never runs tests, generators, package initialization or the product binary.
Unresolved imports, missing modules, invalid entrypoints and incomplete package
graphs fail the check rather than silently reducing coverage.

## Before and after merge

- PR updates scan each introduced commit against its first parent. Only
  added/modified lines in product inputs are reported. The synthetic PR merge
  result is checked against the target base with the same change-only policy.
- A feature-branch push scans each introduced commit's product changes. A new
  branch excludes history already shared with the default branch.
- A merged PR triggers a full-product scan of its merge result, including when
  the destination is a non-default branch. Closing without merging is skipped.
- Pushes to the default branch and `release/*` scan introduced commits and then
  the complete product inputs at the resulting head. This also covers direct,
  squash and rebase pushes. Merge queues scan the queued changes.
- Manual workflow dispatch and local `full` mode scan the complete product
  compilation inputs.

A change-only scan uses full changed files for syntax/data-flow context, then
filters findings to changed line ranges. Findings elsewhere in a changed file
are compared with the parent version's matches; a newly introduced data flow
can therefore flag an unchanged logging sink. Existing matches are compared
using their matching code rather than line numbers, so inserting unrelated
lines does not re-report old findings.
When an import or build constraint adds a file to the product dependency graph,
that newly compiled content is scanned in full even if its Git contents did not
change. Removing a file does not produce a finding for the removed content.

An unchanged historical finding does not block an unrelated PR edit. A new
finding in an earlier PR commit remains blocking when a later commit fixes it;
amend/rebase the affected PR commits when appropriate. Full-product scans after
merge still report all existing product findings. No baseline is generated.

The ordinary build/test workflow runs independently with normal build output.
Build logs and test/build artifacts are not scanned or included in security
reports. Ordinary build or test failures retain their normal workflow status.

## Coverage and limitations

Gitleaks checks the selected compilation inputs for provider credentials,
private keys and labelled plaintext defaults in embedded resources. Semgrep
checks Go credential literals and possible credential-to-log flows, swallowed
errors, raw public error responses, error-message quality and recognizable
identifier comparisons. Codespell checks extracted error strings only.
Dictionary findings and missing-remediation patterns require review at the
API/CLI boundary: preserve low-level sentinel and protocol-defined text when
callers already add context. Follow the certificate store's alias contract,
compare UUID text without case sensitivity, preserve DNS input spelling, and
retain case-sensitive resource naming contracts.

Static rules do not prove security across every runtime path. Review actual
secret flows and user-visible failure handling and add targeted regression tests
for confirmed defects. Review false positives individually rather than
excluding whole directories or automatically allowing findings. Test code can
be ignored because it is absent from the product graph, not because a filename
is globally exempt when its content actually enters the binary.

Pinned tools and local rules require no hosted scanner account, model API,
repository secret or license. Pydantic is pinned because Semgrep's MCP dependency
uses a typing helper removed in newer versions. Tool self-tests run before scan
execution. Gitleaks downloads are checked against the upstream archive checksum.
Target ignore files and inline suppression comments cannot bypass the scanners.

Rule samples live in `script/security-checks/tests/testdata`. This directory is
excluded from Go's recursive package discovery, so deliberately invalid or
unsafe examples do not enter normal builds, linting or coverage. The rule
self-tests explicitly scan this directory.

## Reports and required checks

The workflow run Summary contains scope and file counts, deduplicated findings,
source links, rule explanations and suggested corrections. Links point to the
scanned commit containing the finding. Counts describe candidates requiring
review, not confirmed vulnerabilities or a guaranteed number of code edits.
Change-only counts are limited to those changes; full-product counts cover all
selected repository inputs. Identical tool/rule/file/line entries are grouped
across scans, and matches still reported by the latest scan are identified.

Download `code.md` and `code.json` from the security-checks artifact for the full
report. JSON includes `summary`, deduplicated `findings`, and individual `scans`
with product scope metadata. Large job summaries show the first 100 locations;
downloadable reports retain every finding. Reports omit source snippets, matched
credentials and raw taint traces. Scanner/discovery errors always fail the check.

PR conversations also receive one automatically updated bot comment. Its
summary is collapsed by default and shows the result and finding count in the
heading. Expand it for deduplicated counts, findings by rule, file/line links
and suggested corrections. Location details are bounded to keep comments
readable; the linked run contains the complete reports. Clean runs update the
same comment, and missing or invalid reports are marked incomplete. Results
for an outdated PR head cannot replace the current summary.

The separate `Security PR summary` workflow publishes this comment after
`Security checks` completes. It has permission to read scan artifacts and write
PR comments, while the scanning workflow remains read-only for fork PRs. The
publisher checks out only the target repository's default branch, validates
report metadata, and never executes code or extracts files from the downloaded
report archive. Artifact-provided messages and Markdown are not published.

**Initial setup:** merge `security-pr-summary.yml`, `pr_comment.py` and its
`security_report.py` dependency into the target repository's default branch
first. GitHub only triggers `workflow_run` listeners that exist on the default
branch. Then complete or rerun `Security checks` on the PR. Adding the publisher
only to a PR branch does not activate PR comments. Repository Actions policies
must permit the publisher's `pull-requests: write` permission.

Configure branch protection/rulesets to require `Security checks` and the normal
`build` check. Review changes to target manifests, rules and workflow scripts
through code-owner/review rules, since they control security coverage. Reports
are retained as Actions artifacts for 14 days.

## Run locally

Install Go matching `go.mod`, Python 3.12+, Git, curl and the pinned scanners:

```sh
python3 -m venv /tmp/security-venv
. /tmp/security-venv/bin/activate
python -m pip install -r .github/security-checks/requirements.txt
python -m pip check
bash script/security-checks/install-tools.sh /tmp/security-bin
export PATH="/tmp/security-bin:$PATH"

python -m unittest discover -s script/security-checks/tests -v
semgrep --test --config .github/security-checks/rules script/security-checks/tests/testdata
python script/security-checks/check.py full --report /tmp/security.json
```

`full` scans committed `HEAD`; use `--sha` with a full commit SHA to select
another revision. Uncommitted changes are not included. `event` reads the GitHub
event payload and traverses complete Git history rather than the webhook's
bounded commit list. All selected revisions are processed after earlier
findings. Resolving the product graph may download modules into Go's cache;
module files are read-only and no package code is executed by discovery.
