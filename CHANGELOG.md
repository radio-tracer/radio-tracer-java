# Changelog

All notable changes to **radio-tracer-java** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-08-03

### Highlights

Multi-module / multi-JVM flat report merge, Slack on first REACHABLE, and an interactive demo UI — all on top of the 0.1.0 agent.

### Added

- **Multi-module / multi-JVM reports:** each process writes `report.html.d/<label>-<pid>.json` and merges a **flat** HTML report (same CVE+method → hit counts summed across JVMs; locked merge)
- **Slack Incoming Webhook** (`slack=` / `webhook=` or env `RADIO_TRACER_SLACK_WEBHOOK`): notify on first `[REACHABLE]` and end-of-run summary
- **Demo-app browser UI** (Acme Finance console on `:8080`): click **Generate report** to exercise a watched path; `--cli` remains for headless/CI

### Changed

- Slack notifier cleanup: drop dead imports and tighten tests (#18)

### Requirements

- **App JVM:** JDK **21+**
- **Build:** JDK 21+ (CI may use a newer JDK with `--release 21`)
- **Build tool:** Maven 3.9+

### Artifact

```text
agent/target/radio-tracer-agent-0.2.0.jar
```

```bash
java -javaagent:radio-tracer-agent-0.2.0.jar=\
methods=methods.json,report=report.html \
  -jar your-app.jar
```

GitHub Release asset: `radio-tracer-agent-0.2.0.jar`  
Download: https://github.com/radio-tracer/radio-tracer-java/releases/latest

### Notes

- Early preview: watchlist fields and report layout may evolve before 1.0.
- Multi-module merge is **flat** (sum hits by CVE+method), not a hierarchical multi-page tree.
- No hit under a run ≠ “safe” — only not observed for that workload.

## [0.1.0] — 2026-08-03

### First public preview

Initial open-source release of the RadioTracer JVM agent: attach with `-javaagent`, watch vulnerable methods from a `methods.json` watchlist, and report **REACHABLE** hits at runtime.

### Added

- Java agent (`radio-tracer-agent`) built as a shaded fat JAR with `Premain-Class` / `Agent-Class`
- ByteBuddy instrumentation of watched methods (and constructors via `<init>`) as classes load
- Watchlist loader for agent-oriented `methods.json` (`className`, `methodName`, optional `descriptor`)
- Optional SCA metadata on watchlist rows: `severity`, `cvssScore`, `cvssVector` (e.g. from [radio-tracer-cve-import](https://github.com/radio-tracer/radio-tracer-cve-import))
- First-hit `[REACHABLE]` lines on stderr (CVE, severity, CVSS, package, method, thread + short stack)
- HTML report and console summary table on JVM exit (REACHABLE rows listed; NOT_OBSERVED summary-only)
- Empty watchlist allowed (agent starts idle — useful for wiring checks)
- Skip empty HTML overwrite when another JVM already wrote a report to the same path
- Demo modules (`demo-lib`, `demo-app`) and sample watchlist / report under `examples/`
- CI with 100% line + branch coverage gate on the agent module
- Tag-driven **Release** workflow: unit tests → demo-app integration → GitHub Release + agent JAR
- CODEOWNERS and branch-protection docs

### Requirements

- **App JVM:** JDK **21+** (agent bytecode target 21)
- **Build:** JDK 21+ (CI may use a newer JDK with `--release 21`)
- **Build tool:** Maven 3.9+

### Artifact

```text
agent/target/radio-tracer-agent-0.1.0.jar
```

```bash
java -javaagent:radio-tracer-agent-0.1.0.jar=methods=methods.json,report=report.html -jar your-app.jar
```

### Notes

- Early preview: watchlist fields and report layout may evolve before 1.0.
- Severity / CVSS are advisory risk from the scanner, not proof of exploitability.
- Confidence on watchlist rows is mapping quality (CVE→method), not CVSS.

[Unreleased]: https://github.com/radio-tracer/radio-tracer-java/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/radio-tracer/radio-tracer-java/releases/tag/v0.2.0
[0.1.0]: https://github.com/radio-tracer/radio-tracer-java/releases/tag/v0.1.0
