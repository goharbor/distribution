#!/bin/sh
# ruleid: shell-secret-to-console
echo "$PASSWORD"
# ruleid: shell-secret-to-console
printf '%s\n' "$API_KEY"
# ok: shell-secret-to-console
echo 'Credentials have been redacted'
# ruleid: shell-xtrace
set -x
# ruleid: shell-xtrace
set -o xtrace
# ok: shell-xtrace
set +x
