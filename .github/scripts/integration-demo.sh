#!/usr/bin/env bash
# Integration smoke: package demo-app under the agent and assert REACHABLE hits.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

REPORT="${REPORT:-$ROOT/demo-report.html}"
METHODS="${METHODS:-$ROOT/examples/methods.json}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

shopt -s nullglob
agents=(agent/target/radio-tracer-agent-*.jar)
apps=(demo-app/target/demo-app-*.jar)
# Drop shade "original-*" if present
filtered=()
for j in "${agents[@]}"; do
  [[ "$(basename "$j")" == original-* ]] && continue
  filtered+=("$j")
done
agents=("${filtered[@]}")

if [[ ${#agents[@]} -ne 1 ]]; then
  echo "error: expected exactly one agent JAR, found: ${agents[*]:-none}" >&2
  exit 1
fi
if [[ ${#apps[@]} -ne 1 ]]; then
  echo "error: expected exactly one demo-app JAR, found: ${apps[*]:-none}" >&2
  exit 1
fi
if [[ ! -d demo-app/target/deps ]]; then
  echo "error: demo-app/target/deps missing (run mvn package first)" >&2
  exit 1
fi
if [[ ! -f "$METHODS" ]]; then
  echo "error: methods watchlist not found: $METHODS" >&2
  exit 1
fi

AGENT="${agents[0]}"
APP="${apps[0]}"
echo "agent=$AGENT"
echo "app=$APP"
echo "report=$REPORT"

set +e
java \
  -javaagent:"${AGENT}=methods=${METHODS},report=${REPORT}" \
  -cp "${APP}:demo-app/target/deps/*" \
  com.example.app.DemoApp --cli \
  >"$LOG" 2>&1
rc=$?
set -e
cat "$LOG"
if [[ $rc -ne 0 ]]; then
  echo "error: DemoApp exited with $rc" >&2
  exit "$rc"
fi

fail() { echo "error: $*" >&2; exit 1; }

grep -q 'DemoApp done' "$LOG" || fail "DemoApp did not finish cleanly"
grep -q '\[REACHABLE\]' "$LOG" || fail "no [REACHABLE] lines on agent stderr/stdout"
for cve in CVE-2023-DEMO-0001 CVE-2023-DEMO-0002 CVE-2023-DEMO-0003; do
  grep -q "$cve" "$LOG" || fail "expected reachable $cve in log"
done
grep -q 'reachable=3' "$LOG" || fail "expected reachable=3 in summary"

[[ -f "$REPORT" ]] || fail "HTML report not written: $REPORT"
grep -q 'REACHABLE' "$REPORT" || fail "HTML report missing REACHABLE"
grep -q 'CVE-2023-DEMO-0001' "$REPORT" || fail "HTML report missing CVE-2023-DEMO-0001"
grep -q 'critical' "$REPORT" || fail "HTML report missing severity"

echo "Integration demo OK (3 REACHABLE methods, report=$REPORT)"
