# <img src="docs/radio-tracer-logo.png" alt="" width="40" height="40" align="left"> &nbsp;RadioTracer

**Dynamic reachability for known dependency vulnerabilities** · JVM agent (`radio-tracer-java`)

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
![Java](https://img.shields.io/badge/Java-25+-orange.svg)
![Maven](https://img.shields.io/badge/build-Maven-C71A36.svg)
![Coverage](https://img.shields.io/badge/coverage-100%25%20line%2Fbranch-brightgreen.svg)
![Status](https://img.shields.io/badge/status-early%20preview-yellow.svg)

![SCA](https://img.shields.io/badge/SCA-agnostic-0A66C2?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-method%20probes-6f42c1?style=flat-square)
![Report](https://img.shields.io/badge/report-HTML-2088FF?style=flat-square)
![Platform](https://img.shields.io/badge/platform-JVM%20first-red?style=flat-square)

---

<details open>
<summary><b>Why this exists</b></summary>
<br/>

SCA tools (Dependabot, Snyk, Trivy, OWASP DC, …) answer *“is a vulnerable package on my tree?”*  
They do **not** answer *“did my app actually run the vulnerable code?”*

That gap is huge. Teams drown in alerts that never matter for their workload.

| Finding | ~Figure | Source |
|--------|---------|--------|
| OWASP DC–only sample that were **false positives** (enterprise Java) | **~88.8%** | Ponta et al., ESE 2020 [1] |
| Libraries **never used** at runtime | **~62%** | Contrast OSS materials, 2021 [2] |
| SCA noise tied to unreachable code (call graphs prune a large share) | **~92%** noise; **~61.9%** pruned | KAUST study, 2025 [4] |

Static reachability helps triage, but it’s still a graph guess (reflection, DI, frameworks hurt). RadioTracer answers with **runtime evidence**.

</details>

<details>
<summary><b>What people do today</b></summary>
<br/>

| Approach | Gap |
|----------|-----|
| Package SCA | No usage signal; lots of noise |
| Static reachability | Misses dynamic paths; can over-claim “reachable” |
| Commercial reachability | Closed function DBs; still mostly static |
| “Just upgrade” | Breakage without proof of real risk |

</details>

<details open>
<summary><b>What RadioTracer does</b></summary>
<br/>

**Prove a watched vulnerable method ran** under your tests / app.

```text
SCA → watchlist (CVE → class#method)   [prep coming]
         ↓
java -javaagent:…=methods=watchlist.json,report=out.html
         ↓
your app / integration tests
         ↓
stderr: [REACHABLE] on first hit  ·  HTML on JVM exit
```

- Java agent (no rewrite of dependency JARs on disk)
- Probe when watchlist classes **load**; report when methods **run**
- Hits show instantly on first call; HTML summary when the process exits

> **REACHABLE** = prioritize.  
> **No hit** = not observed under this run — not “safe.”

Does **not** replace SCA, prove exploitability, or invent CVE→method maps by itself.

</details>

<details open>
<summary><b>Quick start</b></summary>
<br/>

**Needs:** JDK 25+, Maven 3.9+

```bash
mvn -q test package

java -javaagent:agent/target/radio-tracer-agent-0.1.0-SNAPSHOT.jar=\
methods=examples/methods.json,report=/tmp/radio-tracer-report.html \
  -cp "demo-app/target/demo-app-0.1.0-SNAPSHOT.jar:demo-app/target/deps/*" \
  com.example.app.DemoApp
```

| Arg | Meaning |
|-----|---------|
| `methods=` | Watchlist JSON (**required**) |
| `report=` | HTML path (optional; written on JVM exit) |
| `verbose=true` | Log which classes get instrumented |

Samples: [`examples/methods.json`](examples/methods.json) · [`examples/sample-report.html`](examples/sample-report.html)

</details>

<details>
<summary><b>Watchlist format</b></summary>
<br/>

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

`confidence` = quality of the CVE→method mapping, not CVSS.

</details>

<details>
<summary><b>Repo layout</b></summary>
<br/>

```text
agent/      Java agent + tests (JaCoCo 100% line/branch)
demo-lib/   Fake vulnerable dependency
demo-app/   App that calls the dep
examples/   Watchlist + sample HTML report
docs/       Logo
```

</details>

<details>
<summary><b>Roadmap</b></summary>
<br/>

- [x] JVM agent + HTML report  
- [ ] Prep: SCA → OSV / fix commits → methods.json  
- [ ] `radio-tracer-python` and other runtimes under the RadioTracer umbrella  

</details>

<details>
<summary><b>References</b></summary>
<br/>

1. Ponta, Plate, Sabetta — *Empir. Softw. Eng.* 2020 — https://doi.org/10.1007/s10664-020-09830-x  
2. Contrast Security OSS materials (2021) — unused library rates  
3. Semgrep SCA reachability notes — https://semgrep.dev/blog/2024/sca-reachability-analysis-methods  
4. KAUST empirical study (2025) on unreachable SCA noise  
5. Plate, Ponta, Sabetta — IEEE QRS 2015 — usage-based OSS vulnerability assessment  

</details>

---

**License:** [Apache-2.0](LICENSE) · use and commercialize under the usual Apache terms.
