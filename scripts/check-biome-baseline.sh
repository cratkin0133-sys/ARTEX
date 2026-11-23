#!/usr/bin/env bash
# Ratchet on Biome: CI and verify run the full web tree, but only fail when
# error/warning counts rise above the recorded baseline. Replace with `npm run check`
# once the baseline reaches zero errors.
#
# Usage:
#   scripts/check-biome-baseline.sh
#   scripts/check-biome-baseline.sh --help
set -euo pipefail
cd "$(dirname "$0")/.."

BASELINE="scripts/biome-baseline.json"

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \?//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ ! -f "$BASELINE" ]; then
  echo "missing baseline: $BASELINE" >&2
  exit 1
fi
if [ ! -d web/node_modules ]; then
  echo "run npm ci in web first" >&2
  exit 1
fi

summary=$(
  cd web
  # biome exits non-zero when diagnostics fail; JSON still lands on stdout.
  set +o pipefail
  npx biome check --reporter=json 2>/dev/null | node -e '
    let raw = "";
    process.stdin.on("data", (c) => { raw += c; });
    process.stdin.on("end", () => {
      const parsed = JSON.parse(raw);
      if (!parsed.summary) {
        console.error("biome JSON missing summary");
        process.exit(1);
      }
      process.stdout.write(JSON.stringify(parsed.summary));
    });
  '
)

errors=$(node -pe "JSON.parse(process.argv[1]).errors" "$summary")
warnings=$(node -pe "JSON.parse(process.argv[1]).warnings" "$summary")
max_errors=$(node -pe "JSON.parse(require('fs').readFileSync('$BASELINE','utf8')).maxErrors")
max_warnings=$(node -pe "JSON.parse(require('fs').readFileSync('$BASELINE','utf8')).maxWarnings")

fail=0
if [ "$errors" -gt "$max_errors" ]; then
  echo "Biome errors $errors exceed baseline cap $max_errors" >&2
  fail=1
fi
if [ "$warnings" -gt "$max_warnings" ]; then
  echo "Biome warnings $warnings exceed baseline cap $max_warnings" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "biome baseline check FAILED (run: cd web && npm run check)" >&2
  exit 1
fi

printf 'biome baseline ok (errors %s/%s, warnings %s/%s)\n' \
  "$errors" "$max_errors" "$warnings" "$max_warnings"