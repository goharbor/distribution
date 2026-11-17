#!/usr/bin/env bash
set -euo pipefail

# Install a pinned upstream binary and verify its published SHA-256 checksum.
# No curl-to-shell, repository token, or Gitleaks Action license is required.
version=8.24.3
destination=${1:?usage: install-tools.sh DESTINATION}
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux_x64 ;;
  Linux/aarch64|Linux/arm64) platform=linux_arm64 ;;
  Darwin/arm64) platform=darwin_arm64 ;;
  Darwin/x86_64) platform=darwin_x64 ;;
  *) echo "Unsupported scanner platform" >&2; exit 2 ;;
esac
mkdir -p "$destination"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
archive="gitleaks_${version}_${platform}.tar.gz"
url="https://github.com/gitleaks/gitleaks/releases/download/v${version}"
curl --fail --silent --show-error --location --retry 3 "$url/$archive" -o "$temporary/$archive"
curl --fail --silent --show-error --location --retry 3 "$url/gitleaks_${version}_checksums.txt" -o "$temporary/checksums.txt"
python3 - "$temporary" "$archive" "$destination" <<'PY'
import hashlib
from pathlib import Path
import sys
import tarfile

temporary, archive, destination = map(Path, sys.argv[1:])
expected = dict(line.split()[::-1] for line in (temporary / "checksums.txt").read_text().splitlines())
data = (temporary / archive).read_bytes()
if hashlib.sha256(data).hexdigest() != expected[archive.name]:
    raise SystemExit("Gitleaks checksum mismatch")
with tarfile.open(temporary / archive) as bundle:
    member = bundle.getmember("gitleaks")
    if not member.isfile():
        raise SystemExit("Gitleaks archive has no regular binary")
    (destination / "gitleaks").write_bytes(bundle.extractfile(member).read())
(destination / "gitleaks").chmod(0o755)
PY
