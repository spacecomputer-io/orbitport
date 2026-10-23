#!/usr/bin/env bash
# Lists the demos by role and runs one by name.
#
#   ./booth.sh                    list every demo
#   ./booth.sh <demo>             run a demo, e.g. ./booth.sh signed-webhooks
#   BOOTH_PAUSE=1 ./booth.sh <d>  wait for Enter between steps

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLES=(dev devops sre cloud-security)

# first line of the README, without the "# "
summary() { sed -n '1s/^# //p' "$1/README.md"; }

list() {
  local role demo
  for role in "${ROLES[@]}"; do
    echo
    echo "$role"
    for demo in "$DIR/$role"/*/; do
      demo="${demo%/}"
      printf '  %-28s %s\n' "$(basename "$demo")" "$(summary "$demo")"
    done
  done
  echo
  echo "Run one with: ./booth.sh <demo>"
}

if [[ $# -eq 0 ]]; then
  list
  exit 0
fi

for role in "${ROLES[@]}"; do
  if [[ -x "$DIR/$role/$1/run.sh" ]]; then
    exec "$DIR/$role/$1/run.sh"
  fi
done

echo "unknown demo: $1" >&2
list >&2
exit 1
