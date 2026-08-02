<p align="center">
  <img src="docs/radio-tracer-logo.png" alt="RadioTracer" width="280"/>
</p>

<h1 align="center">RadioTracer</h1>
<p align="center"><strong>Dynamic reachability for known dependency vulnerabilities</strong></p>
<p align="center">This repo is <code>radio-tracer-java</code> — the JVM agent. Prep tooling and other languages will live under the RadioTracer umbrella later.</p>

---

## The problem

SCA tools (Dependabot, Snyk, Trivy, OWASP Dependency-Check, …) answer:

> *Do I depend on a package version with a CVE?*

They do **not** answer:

> *Did my app actually execute the vulnerable code?*

Most findings are noise: the library is on the classpath, but the bad code never matters for *your* run. Teams either upgrade everything in a panic or ignore alerts until something burns.

### How bad is the noise?

Independent numbers (definitions of “false positive” differ — wrong package match vs “CVE real but unused”):

| Finding | Approx. figure | Source |
|--------|----------------|--------|
| Sample of OWASP Dependency-Check–only findings that were **false positives** (enterprise Java, code-level vulns) | **~88.8%** | Ponta, Plate & Sabetta, *Empir. Softw. Eng.* 2020 [1] |
| Open-source libraries **never used** at runtime | **~62%** | Contrast Security OSS materials, 2021 [2] |
| SCA noise tied to **unreachable** code; call-graph analysis can prune a large share | **~92%** FP-style noise; **~61.9%** pruned | KAUST empirical study (2,414 repos, 2025) [4] |

**Package SCA is noisy.** Static reachability is the usual next step: one public Semgrep sample found only **~2%** of Dependabot alerts on a static path (31 of 1,614 across ~1,100 projects) [3] — meaning most alerts are *candidates to deprioritize*, not “proven safe.” That analysis is still **static** (call graphs), so it can miss runtime-only paths (reflection, DI, frameworks) and can mark paths that never actually run under your tests.

RadioTracer is the layer after triage: **runtime proof** that a watched method executed under *your* workload — not another package match, not another best-effort graph.

---

## What people do today

| Approach | Idea | Gap |
|----------|------|-----|
| **Package SCA** | Match versions to CVE DBs | No idea if the vuln is used; high noise (see above) |
| **Static reachability** | Call graphs / “is this API referenced?” | Misses reflection, DI, frameworks; can over- or under-claim |
| **Commercial “reachable” scores** | Proprietary function DBs + static analysis | Closed data, still mostly static |
| **“Just upgrade”** | Bump everything | Breaks builds; still no proof of risk |

---

## What RadioTracer does

**Prove that a watched vulnerable method ran under a real workload** (integration tests, staging, the app itself).

```text
SCA output  →  watchlist (CVE → class#method)   [prep — coming]
                    ↓
         java -javaagent:radio-tracer.jar=methods=...
                    ↓
         your tests / app run as usual
                    ↓
         HTML report: what was REACHABLE
```

On the JVM this is a **Java agent**: it does not rewrite dependency JARs on disk. When the JVM loads a class on the watchlist, it injects a tiny probe. When that method executes, you get a hit (CVE, library, upgrade target, stack).

Java first. Same idea later for other runtimes (`radio-tracer-python`, …) under the RadioTracer project.

---

## What it is not

RadioTracer does **not** replace SCA. You still need a scanner to know *which* CVEs exist.

It also does **not**:

- Prove exploitability (attacker control, configs, …)
- Prove safety if a method was **not** hit (your tests simply may not cover that path)
- Invent vulnerable-method mappings for every CVE (that’s the prep stage + public data limits)

Treat **REACHABLE** as evidence to prioritize. Treat **no hit** as “not observed under this run.”

---

## Quick start (this repo)

**Needs:** JDK 25+, Maven 3.9+

```bash
mvn -q test package

java -javaagent:agent/target/radio-tracer-agent-0.1.0-SNAPSHOT.jar=\
methods=examples/methods.json,report=/tmp/radio-tracer-report.html \
  -cp "demo-app/target/demo-app-0.1.0-SNAPSHOT.jar:demo-app/target/deps/*" \
  com.example.app.DemoApp
```

Open the HTML report. Demo watchlist: `examples/methods.json`. Sample report: `examples/sample-report.html`.

Agent args: `methods=<watchlist.json>`, optional `report=<file.html>`, optional `verbose=true`.

---

## Watchlist (today)

Hand-written JSON until prep lands:

```json
{
  "cve": "CVE-…",
  "package": "group:artifact",
  "installedVersion": "1.0.0",
  "upgradeTo": "1.2.0",
  "className": "com.example.Lib",
  "methodName": "vulnerableApi",
  "descriptor": "(Ljava/lang/String;)V",
  "confidence": "high",
  "source": "fix-commit"
}
```

`confidence` = quality of the CVE→method mapping, not severity.

---

## Layout

```text
agent/       Java agent + unit tests (JaCoCo 100% line/branch gate)
demo-lib/    Fake vulnerable dependency
demo-app/    App that calls into the dep
examples/    Sample watchlist + sample HTML report
docs/        Logo and docs assets
```

---

## Status

- [x] JVM agent, watchlist-driven instrumentation  
- [x] Console + HTML report  
- [ ] Prep: SCA → OSV / fix commits → methods.json  
- [ ] Other languages under RadioTracer  

---

## References

1. S. E. Ponta, H. Plate, A. Sabetta, “Detection, assessment and mitigation of vulnerabilities in open source dependencies,” *Empirical Software Engineering*, vol. 25, pp. 3175–3215, 2020. https://doi.org/10.1007/s10664-020-09830-x  
2. Contrast Security, *State of Open Source Security* / OSS observability materials (2021) — often cited for unused-library rates (~62% of libraries never used at runtime).  
3. Semgrep, SCA reachability analysis notes (Dependabot alerts vs reachable): https://semgrep.dev/blog/2024/sca-reachability-analysis-methods  
4. KAUST empirical work on downstream scanners / unreachable vulns (2025; ~92% FP-style noise, ~61.9% pruned by call-graph analysis) — summarized e.g. in industry write-ups of the study.  
5. H. Plate, S. E. Ponta, A. Sabetta, “Impact assessment for vulnerabilities in open-source software libraries,” IEEE QRS, 2015 (code-centric / usage-based lineage behind Eclipse Steady).

---

## License

**[Apache License 2.0](LICENSE)** — OSI-approved open source.

Use, modify, and distribute freely, including commercially. Contributions are under the same terms. A patent grant is included; see the license text for details.
