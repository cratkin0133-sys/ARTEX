#!/usr/bin/env bash
# Ratchet on oversized source files: nothing new above BUDGET, and grandfathered
# files may not grow. Non-test production sources only.
#
# Usage:
#   scripts/check-file-budget.sh
#   scripts/check-file-budget.sh --help
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET=1000
ALLOWLIST="scripts/file-budget-allowlist.tsv"

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \?//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ ! -f "$ALLOWLIST" ]; then
  echo "missing allowlist: $ALLOWLIST" >&2
  exit 1
fi

fail=0

is_test_path() {
  case "$1" in
    *_test.go) return 0 ;;
    */*.test.ts|*/*.test.tsx|*/*.test.mjs) return 0 ;;
    *) return 1 ;;
  esac
}

allowlist_cap() {
  local rel="$1"
  local path max_lines
  while IFS=$'\t' read -r path max_lines _comment; do
    case "$path" in
      ''|'#'*) continue ;;
    esac
    if [ "$path" = "$rel" ]; then
      echo "$max_lines"
      return 0
    fi
  done < "$ALLOWLIST"
  return 1
}

grandfathered=0
while IFS=$'\t' read -r path max_lines _comment; do
  case "$path" in
    ''|'#'*) continue ;;
  esac
  if ! [[ "$max_lines" =~ ^[0-9]+$ ]]; then
    echo "invalid cap for $path: $max_lines" >&2
    exit 1
  fi
  grandfathered=$((grandfathered + 1))
done < "$ALLOWLIST"

while IFS= read -r -d '' f; do
  rel="${f#./}"
  is_test_path "$rel" && continue
  lines=$(wc -l < "$f" | tr -d ' ')
  cap_max=""
  if cap_max=$(allowlist_cap "$rel"); then
    if [ "$lines" -gt "$cap_max" ]; then
      echo "RATchet: $rel is $lines lines (cap $cap_max)" >&2
      fail=1
    fi
    continue
  fi
  if [ "$lines" -gt "$BUDGET" ]; then
    echo "OVER budget ($BUDGET): $rel has $lines lines (add to $ALLOWLIST to grandfather, or split the file)" >&2
    fail=1
  fi
done < <(find . -type f \( -name '*.go' -o -name '*.ts' -o -name '*.tsx' \) \
  ! -path './web/node_modules/*' ! -path './.git/*' -print0)

if [ "$fail" -ne 0 ]; then
  echo "file budget check FAILED" >&2
  exit 1
fi
echo "file budget check passed ($BUDGET lines; $grandfathered grandfathered)"