#!/usr/bin/env bash
# End-to-end RadioTracer against smaller Java apps.
#
# Targets (in order):
#   1) snyk/java-goof          — Maven multi-module SCA demo
#   2) SasanLabs/VulnerableApp — Gradle Spring Boot + tests
#
# Usage:
#   ./scripts/e2e-java-apps.sh
#   ./scripts/e2e-java-apps.sh --only goof
#   ./scripts/e2e-java-apps.sh --only vulnerableapp
#   ./scripts/e2e-java-apps.sh --skip-snyk
#   JAVA_HOME_BUILD=/path/to/jdk21 ./scripts/e2e-java-apps.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RT_JAVA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CODE_ROOT="$(cd "${RT_JAVA_ROOT}/.." && pwd)"

RT_IMPORT_ROOT="${RT_IMPORT_ROOT:-${CODE_ROOT}/radio-tracer-cve-import}"
WORK_ROOT="${WORK_ROOT:-${RT_JAVA_ROOT}/.e2e-java-apps}"
MAX_METHODS="${MAX_METHODS:-500}"
PREFER_CONFIDENCE="${PREFER_CONFIDENCE:-1}"

SKIP_SNYK=0
SKIP_AGENT_BUILD=0
ONLY=""

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --skip-snyk) SKIP_SNYK=1; shift ;;
    --skip-agent-build) SKIP_AGENT_BUILD=1; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    --max-methods) MAX_METHODS="$2"; shift 2 ;;
    *) die "Unknown option: $1" ;;
  esac
done

mkdir -p "${WORK_ROOT}"

# Prefer Java 21 for Gradle 8.x / older Maven apps (Java 25 = class major 69 breaks Gradle 8.5)
pick_java_home() {
  if [[ -n "${JAVA_HOME_BUILD:-}" && -d "${JAVA_HOME_BUILD}" ]]; then
    echo "${JAVA_HOME_BUILD}"
    return
  fi
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    /usr/libexec/java_home -v 21 2>/dev/null \
      || /usr/libexec/java_home -v 17 2>/dev/null \
      || /usr/libexec/java_home 2>/dev/null \
      || true
    return
  fi
  echo "${JAVA_HOME:-}"
}

JAVA_HOME_APP="$(pick_java_home)"
if [[ -n "${JAVA_HOME_APP}" ]]; then
  export JAVA_HOME="${JAVA_HOME_APP}"
  export PATH="${JAVA_HOME}/bin:${PATH}"
fi
log "Java for targets: $(java -version 2>&1 | head -1)"
log "JAVA_HOME=${JAVA_HOME:-}"

command -v java >/dev/null || die "java not found"
command -v git >/dev/null || die "git not found"

# ---------------------------------------------------------------------------
# Agent (built with whatever default JDK built the agent before — usually 25)
# ---------------------------------------------------------------------------
if [[ "${SKIP_AGENT_BUILD}" -eq 0 ]]; then
  log "Building RadioTracer agent"
  # Build agent with Java 25 if available (project requires it), else current
  AGENT_JAVA_HOME=""
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    AGENT_JAVA_HOME="$(/usr/libexec/java_home -v 25 2>/dev/null || true)"
  fi
  if [[ -n "${AGENT_JAVA_HOME}" ]]; then
    (cd "${RT_JAVA_ROOT}" && JAVA_HOME="${AGENT_JAVA_HOME}" PATH="${AGENT_JAVA_HOME}/bin:$PATH" mvn -q -pl agent package -DskipTests)
  else
    (cd "${RT_JAVA_ROOT}" && mvn -q -pl agent package -DskipTests)
  fi
fi

RT_AGENT="$(ls -1 "${RT_JAVA_ROOT}"/agent/target/radio-tracer-agent-*.jar 2>/dev/null | head -1 || true)"
[[ -f "${RT_AGENT}" ]] || die "Agent JAR missing under agent/target/"
log "Agent: ${RT_AGENT}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
ensure_clone() {
  local dir="$1" repo="$2"
  if [[ ! -d "${dir}/.git" ]]; then
    log "Cloning ${repo} → ${dir}"
    git clone --depth 1 "${repo}" "${dir}"
  else
    log "Using existing ${dir}"
  fi
}

resolve_import_bin() {
  if [[ -x "${RT_IMPORT_ROOT}/.venv/bin/radio-tracer-cve-import" ]]; then
    echo "${RT_IMPORT_ROOT}/.venv/bin/radio-tracer-cve-import"
    return
  fi
  if command -v radio-tracer-cve-import >/dev/null 2>&1; then
    command -v radio-tracer-cve-import
    return
  fi
  if [[ -d "${RT_IMPORT_ROOT}" ]]; then
    log "Creating venv + installing radio-tracer-cve-import"
    python3 -m venv "${RT_IMPORT_ROOT}/.venv"
    # shellcheck disable=SC1091
    source "${RT_IMPORT_ROOT}/.venv/bin/activate"
    pip install -q -e "${RT_IMPORT_ROOT}"
    echo "${RT_IMPORT_ROOT}/.venv/bin/radio-tracer-cve-import"
    return
  fi
  echo ""
}

write_empty_methods() {
  cat > "$1" <<'EOF'
{
  "version": 1,
  "methods": []
}
EOF
}

filter_watchlist() {
  local path="$1"
  local max="$2"
  python3 - "$path" "$max" "${PREFER_CONFIDENCE}" <<'PY'
import json, sys
path, max_n, prefer = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
methods = doc.get("methods") or []
if prefer:
    ranked = [m for m in methods if (m.get("confidence") or "").lower() in ("high", "medium")]
    if ranked:
        methods = ranked
sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
conf = {"high": 0, "medium": 1, "low": 2}
def key(m):
    return (
        sev.get((m.get("severity") or "").lower(), 9),
        conf.get((m.get("confidence") or "").lower(), 9),
        -(m.get("cvssScore") or 0),
    )
methods = sorted(methods, key=key)[:max_n]
doc["methods"] = methods
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
print(len(methods))
PY
}

# Snyk on multi-module Maven / Gradle: always --all-projects when possible
run_snyk() {
  local app_dir="$1"
  local snyk_json="$2"
  shift 2
  # remaining: extra snyk args
  log "Snyk test --json --all-projects in ${app_dir}"
  set +e
  (
    cd "${app_dir}"
    # Ensure Gradle/Snyk use the selected (non-25) JDK when set
    if [[ -n "${JAVA_HOME:-}" ]]; then
      export JAVA_HOME PATH="${JAVA_HOME}/bin:${PATH}"
    fi
    snyk test --all-projects --json "$@" > "${snyk_json}"
  )
  local ec=$?
  set -e
  log "Snyk exit=${ec} → ${snyk_json}"
  return 0
}

build_watchlist() {
  local app_dir="$1"
  local snyk_json="$2"
  local methods_json="$3"
  local workdir="$4"

  if [[ "${SKIP_SNYK}" -eq 1 ]]; then
    warn "Skipping Snyk for $(basename "${app_dir}")"
    write_empty_methods "${methods_json}"
    return
  fi
  if ! command -v snyk >/dev/null 2>&1; then
    warn "snyk not found — empty watchlist"
    write_empty_methods "${methods_json}"
    return
  fi

  run_snyk "${app_dir}" "${snyk_json}"

  if [[ ! -s "${snyk_json}" ]]; then
    warn "Empty Snyk JSON — empty watchlist"
    write_empty_methods "${methods_json}"
    return
  fi

  # Snyk error payloads (e.g. Gradle failed) are not importable
  if python3 -c "import json;d=json.load(open('${snyk_json}')); import sys; sys.exit(0 if (isinstance(d,dict) and d.get('error')) else 1)"; then
    warn "Snyk JSON is an error payload (tooling failed) — empty watchlist"
    write_empty_methods "${methods_json}"
    return
  fi

  local import_bin
  import_bin="$(resolve_import_bin)"
  if [[ -z "${import_bin}" ]]; then
    warn "Importer unavailable — empty watchlist"
    write_empty_methods "${methods_json}"
    return
  fi

  log "Import → ${methods_json}"
  set +e
  "${import_bin}" \
    --input "${snyk_json}" \
    --output "${methods_json}" \
    --workdir "${workdir}" \
    --format agent \
    -v
  local imp_ec=$?
  set -e
  if [[ "${imp_ec}" -ne 0 || ! -s "${methods_json}" ]]; then
    warn "Import failed (${imp_ec}) — empty watchlist"
    write_empty_methods "${methods_json}"
    return
  fi

  local n
  n="$(filter_watchlist "${methods_json}" "${MAX_METHODS}")"
  log "Watchlist methods after filter (max ${MAX_METHODS}): ${n}"
  if [[ "${n}" == "0" ]]; then
    warn "Zero methods resolved — agent will start idle (no instrumentation)"
  fi
}

# Extra JVM flags for ancient apps on modern JDKs (Hibernate/javassist etc.)
LEGACY_OPENS=(
  --add-opens=java.base/java.lang=ALL-UNNAMED
  --add-opens=java.base/java.lang.reflect=ALL-UNNAMED
  --add-opens=java.base/java.util=ALL-UNNAMED
  --add-opens=java.base/java.io=ALL-UNNAMED
  --enable-native-access=ALL-UNNAMED
)

# Build -javaagent=… string (no leading/trailing junk)
agent_jvm_flags() {
  local methods_json="$1"
  local report_html="$2"
  local agent_args="methods=${methods_json},report=${report_html},verbose=true"
  printf '%s' "-javaagent:${RT_AGENT}=${agent_args} ${LEGACY_OPENS[*]}"
}

run_with_agent() {
  local label="$1"
  local methods_json="$2"
  local report_html="$3"
  local mode="$4"   # tool_options | surefire_argline
  shift 4

  # Remove any stale report so this run starts clean (agent still won't empty-clobber)
  rm -f "${report_html}"

  local flags
  flags="$(agent_jvm_flags "${methods_json}" "${report_html}")"
  log "[${label}] JAVA_HOME=${JAVA_HOME:-}"
  log "[${label}] agent flags: ${flags}"

  local ec=0
  set +e
  case "${mode}" in
    surefire_argline)
      # Only Surefire test JVMs get the agent — not the Maven parent (avoids empty report clobber).
      log "[${label}] Running (Surefire argLine): $*"
      "$@" -DargLine="${flags}"
      ec=$?
      ;;
    *)
      # Gradle / other: JAVA_TOOL_OPTIONS still needed for worker JVMs
      export JAVA_TOOL_OPTIONS="${flags}"
      log "[${label}] JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS}"
      log "[${label}] Running: $*"
      "$@"
      ec=$?
      unset JAVA_TOOL_OPTIONS || true
      ;;
  esac
  set -e

  if [[ -f "${report_html}" ]]; then
    log "[${label}] Report: ${report_html} ($(wc -c < "${report_html}" | tr -d ' ') bytes)"
    if command -v rg >/dev/null 2>&1; then
      rg -n "reachable=|REACHABLE \(listed\)|total_hits" "${report_html}" 2>/dev/null | head -5 || true
    fi
  else
    warn "[${label}] No HTML report (check agent on test JVM / empty watchlist)"
  fi
  return "${ec}"
}

# ---------------------------------------------------------------------------
# java-goof
# ---------------------------------------------------------------------------
run_java_goof() {
  local dir="${CODE_ROOT}/java-goof"
  local work="${WORK_ROOT}/java-goof"
  mkdir -p "${work}"
  local snyk_json="${work}/snyk.json"
  local methods_json="${work}/methods.json"
  local report_html="${work}/radio-tracer-report.html"

  log "========== Target: snyk/java-goof =========="
  ensure_clone "${dir}" "https://github.com/snyk/java-goof.git"
  # Parent pom has no deps; --all-projects hits log4shell + todolist modules
  build_watchlist "${dir}" "${snyk_json}" "${methods_json}" "${work}"

  command -v mvn >/dev/null || die "mvn required for java-goof"

  # Hardcoded <source>1.7</source> in todolist-goof/pom.xml fails on modern JDKs.
  # Patch in-tree for this clone only (demo repo is intentionally ancient).
  local todo_pom="${dir}/todolist-goof/pom.xml"
  if [[ -f "${todo_pom}" ]] && grep -q '<source>1.7</source>' "${todo_pom}"; then
    log "Patching todolist-goof compiler source/target 1.7 → 1.8 for JDK 21+"
    sed -i.bak 's|<source>1.7</source>|<source>1.8</source>|; s|<target>1.7</target>|<target>1.8</target>|' "${todo_pom}"
  fi

  # Modules with tests / interesting deps: todolist-core, log4shell-server
  # surefire_argline: agent only on test forks (not Maven parent)
  run_with_agent "java-goof" "${methods_json}" "${report_html}" surefire_argline \
    mvn -f "${dir}/pom.xml" -pl todolist-goof/todolist-core,log4shell-goof/log4shell-server -am test \
      -DfailIfNoTests=false
}

# ---------------------------------------------------------------------------
# VulnerableApp (Gradle 8.5 → needs JDK ≤ 21)
# ---------------------------------------------------------------------------
run_vulnerableapp() {
  local dir="${CODE_ROOT}/VulnerableApp"
  local work="${WORK_ROOT}/vulnerableapp"
  mkdir -p "${work}"
  local snyk_json="${work}/snyk.json"
  local methods_json="${work}/methods.json"
  local report_html="${work}/radio-tracer-report.html"

  log "========== Target: SasanLabs/VulnerableApp =========="
  ensure_clone "${dir}" "https://github.com/SasanLabs/VulnerableApp.git"

  # Force Java 21 for this target
  local j21=""
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    j21="$(/usr/libexec/java_home -v 21 2>/dev/null || /usr/libexec/java_home -v 17 2>/dev/null || true)"
  fi
  if [[ -n "${j21}" ]]; then
    export JAVA_HOME="${j21}"
    export PATH="${JAVA_HOME}/bin:${PATH}"
    log "VulnerableApp JAVA_HOME=${JAVA_HOME} ($(java -version 2>&1 | head -1))"
  else
    warn "No JDK 17/21 found — Gradle 8.5 may fail on Java 25"
  fi

  build_watchlist "${dir}" "${snyk_json}" "${methods_json}" "${work}"

  local gradle_cmd=()
  if [[ -x "${dir}/gradlew" ]]; then
    gradle_cmd=("${dir}/gradlew" -p "${dir}")
  elif command -v gradle >/dev/null 2>&1; then
    gradle_cmd=(gradle -p "${dir}")
  else
    die "gradlew/gradle not found for VulnerableApp"
  fi

  run_with_agent "VulnerableApp" "${methods_json}" "${report_html}" tool_options \
    env JAVA_HOME="${JAVA_HOME}" PATH="${PATH}" \
    "${gradle_cmd[@]}" test --no-daemon
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
FAILED=0

should_run() {
  local name="$1"
  [[ -z "${ONLY}" || "${ONLY}" == "${name}" ]]
}

if should_run goof; then
  if ! run_java_goof; then
    warn "java-goof finished with errors"
    FAILED=1
  fi
fi

if should_run vulnerableapp; then
  if ! run_vulnerableapp; then
    warn "VulnerableApp finished with errors"
    FAILED=1
  fi
fi

echo
log "========== E2E summary =========="
log "Work root: ${WORK_ROOT}"
log "Agent:     ${RT_AGENT}"
[[ -f "${WORK_ROOT}/java-goof/methods.json" ]] && \
  log "goof methods: $(python3 -c "import json;print(len(json.load(open('${WORK_ROOT}/java-goof/methods.json')).get('methods',[])))" 2>/dev/null || echo '?')"
[[ -f "${WORK_ROOT}/vulnerableapp/methods.json" ]] && \
  log "vulnapp methods: $(python3 -c "import json;print(len(json.load(open('${WORK_ROOT}/vulnerableapp/methods.json')).get('methods',[])))" 2>/dev/null || echo '?')"
log "Reports under ${WORK_ROOT}/*/radio-tracer-report.html"

if [[ "${FAILED}" -ne 0 ]]; then
  warn "One or more targets failed"
  exit 1
fi
log "Done."
exit 0
