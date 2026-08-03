package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;

import java.io.PrintStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Collects runtime hits for watched methods and writes the final HTML report
 * (plus a console summary table) on shutdown.
 * <p>
 * Multi-module / multi-JVM: each process writes a JSON fragment under
 * {@code report.html.d/}, then merges all fragments into one flat HTML table
 * (hit counts summed for the same CVE+method) under a file lock.
 */
public final class HitReporter {

    private static final AtomicLong TOTAL_HITS = new AtomicLong();
    private static final ConcurrentHashMap<String, AtomicLong> COUNTS = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> FIRST_SEEN = new ConcurrentHashMap<>();

    private static volatile PrintStream out = System.err;
    private static volatile Path reportPath;
    private static volatile List<Watchlist.VulnerableMethod> watchlist = List.of();
    private static volatile String runLabel = "";
    private static volatile SlackNotifier slack = new SlackNotifier(null);

    private HitReporter() {}

    public static void configure(Path report, List<Watchlist.VulnerableMethod> methods) {
        configure(report, methods, null, null);
    }

    public static void configure(Path report, List<Watchlist.VulnerableMethod> methods, String label) {
        configure(report, methods, label, null);
    }

    public static void configure(
            Path report,
            List<Watchlist.VulnerableMethod> methods,
            String label,
            String slackWebhook
    ) {
        out = System.err;
        reportPath = report;
        watchlist = methods == null ? List.of() : List.copyOf(methods);
        runLabel = RunLabel.resolve(label);
        slack = new SlackNotifier(slackWebhook);
    }

    public static void onMethodEnter(
            String className,
            String methodName,
            String descriptor,
            String cve,
            String packageCoord
    ) {
        onMethodEnter(className, methodName, descriptor, cve, packageCoord, "", null);
    }

    public static void onMethodEnter(
            String className,
            String methodName,
            String descriptor,
            String cve,
            String packageCoord,
            String severity,
            Double cvssScore
    ) {
        try {
            String key = className + "#" + methodName + (descriptor == null ? "" : descriptor);
            TOTAL_HITS.incrementAndGet();
            COUNTS.computeIfAbsent(key, ignored -> new AtomicLong()).incrementAndGet();

            // First hit only: print stack; further calls only increment counts.
            if (FIRST_SEEN.putIfAbsent(key, System.currentTimeMillis()) != null) {
                return;
            }

            String thread = Thread.currentThread().getName();
            StringBuilder line = new StringBuilder();
            line.append("[REACHABLE] ")
                    .append(Instant.now())
                    .append(" cve=").append(empty(cve, "?"))
                    .append(" severity=").append(empty(severity, "?"))
                    .append(" cvss=").append(formatCvss(cvssScore))
                    .append(" package=").append(empty(packageCoord, "?"))
                    .append(" method=").append(key)
                    .append(" label=").append(RunLabel.display(runLabel))
                    .append(" thread=").append(thread);
            out.println(line);
            out.flush();

            printCallerStack(out, Thread.currentThread().getStackTrace());
            out.flush();

            // Instant Slack alert on first hit (does not block app correctness if Slack fails).
            slack.notifyFirstReachable(
                    cve,
                    severity,
                    formatCvss(cvssScore),
                    packageCoord,
                    key,
                    RunLabel.display(runLabel),
                    thread);
        } catch (Throwable t) {
            System.err.println("[radio-tracer] reporter error: " + t);
        }
    }

    private static String formatCvss(Double score) {
        if (score == null) {
            return "?";
        }
        double v = score;
        if (Double.isNaN(v) || Double.isInfinite(v)) {
            return "?";
        }
        if (v == Math.rint(v)) {
            return Long.toString((long) v);
        }
        return Double.toString(v);
    }

    public static List<MethodResult> buildResults() {
        Map<String, Long> counts = snapshotCounts();
        return watchlist.stream()
                .map(m -> {
                    long hits = resolveHits(m, counts);
                    ReachabilityStatus status =
                            hits > 0 ? ReachabilityStatus.REACHABLE : ReachabilityStatus.NOT_OBSERVED;
                    return new MethodResult(m, status, hits);
                })
                .toList();
    }

    private static Map<String, Long> snapshotCounts() {
        ConcurrentHashMap<String, Long> snap = new ConcurrentHashMap<>();
        COUNTS.forEach((k, v) -> snap.put(k, v.get()));
        return snap;
    }

    private static long resolveHits(Watchlist.VulnerableMethod m, Map<String, Long> counts) {
        String descriptor = m.descriptor();
        if (descriptor != null) {
            Long exact = counts.get(m.className() + "#" + m.methodName() + descriptor);
            if (exact != null) {
                return exact;
            }
        }
        String prefix = m.className() + "#" + m.methodName();
        long sum = 0;
        boolean any = false;
        for (Map.Entry<String, Long> e : counts.entrySet()) {
            String key = e.getKey();
            // Runtime keys are class#method or class#method + JVM descriptor (starts with '(').
            if (key.equals(prefix) || key.startsWith(prefix + "(")) {
                sum += e.getValue();
                any = true;
            }
        }
        return any ? sum : 0;
    }

    public static void writeFinalReport() {
        try {
            List<MethodResult> results = buildResults();
            List<MethodResult> reached = results.stream()
                    .filter(r -> r.status().isReached())
                    .toList();
            long total = TOTAL_HITS.get();
            long reachable = reached.size();
            long notObserved = results.size() - reachable;
            String label = RunLabel.display(runLabel);
            long pid = RunLabel.currentPid();

            out.println();
            out.println("[radio-tracer] ===== Reachability summary =====");
            out.println("[radio-tracer] label=" + label
                    + " pid=" + pid
                    + " watched=" + results.size()
                    + " reachable=" + reachable
                    + " not_observed=" + notObserved
                    + " total_hits=" + total
                    + " (table lists REACHABLE only)");
            out.println();
            if (reached.isEmpty()) {
                out.println("[radio-tracer] (no reachable vulnerable methods observed)");
            } else {
                out.println(HtmlReportWriter.consoleTable(reached));
            }
            out.flush();

            Path path = reportPath;
            if (path != null) {
                Path htmlPath = ensureHtmlPath(path);
                Path fragmentsDir = fragmentsDirFor(htmlPath);
                Path lockPath = fragmentsDir.resolve(".merge.lock");
                Instant now = Instant.now();
                JvmRunSnapshot mine = JvmRunSnapshot.fromResults(label, pid, results, total, now);

                Files.createDirectories(fragmentsDir);
                try (FileChannel channel = FileChannel.open(
                        lockPath,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE);
                     FileLock lock = channel.lock()) {

                    Path fragmentPath = fragmentsDir.resolve(
                            RunLabel.sanitize(label) + "-" + pid + ".json");
                    mine.write(fragmentPath);
                    out.println("[radio-tracer] fragment written " + fragmentPath.toAbsolutePath()
                            + " (label=" + label + ", hits=" + total + ")");

                    List<JvmRunSnapshot> all = JvmRunSnapshot.loadAll(fragmentsDir);
                    String html = HtmlReportWriter.renderMerged(all, now);
                    Path parent = htmlPath.getParent();
                    if (parent != null) {
                        Files.createDirectories(parent);
                    }
                    Files.writeString(
                            htmlPath,
                            html,
                            StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING,
                            StandardOpenOption.WRITE);
                    var mergedRows = JvmRunSnapshot.mergeReached(all);
                    long mergedHits = mergedRows.stream().mapToLong(JvmRunSnapshot.ReachedRow::hitCount).sum();
                    out.println("[radio-tracer] HTML report written to " + htmlPath.toAbsolutePath()
                            + " (jvms=" + all.size()
                            + ", reachable_rows=" + mergedRows.size()
                            + ", total_hits=" + mergedHits + ")");
                    out.flush();
                }
            }

            slack.notifySummary(label, reached, total);
        } catch (Throwable t) {
            System.err.println("[radio-tracer] failed to write report: " + t);
            t.printStackTrace(System.err);
        }
    }

    static Path fragmentsDirFor(Path htmlPath) {
        return htmlPath.resolveSibling(htmlPath.getFileName().toString() + ".d");
    }

    private static Path ensureHtmlPath(Path path) {
        String name = path.getFileName().toString();
        String lower = name.toLowerCase();
        if (lower.endsWith(".html") || lower.endsWith(".htm")) {
            return path;
        }
        if (name.contains(".")) {
            String base = name.substring(0, name.lastIndexOf('.'));
            return path.resolveSibling(base + ".html");
        }
        return path.resolveSibling(name + ".html");
    }

    private static void printCallerStack(PrintStream out, StackTraceElement[] stack) {
        int printed = 0;
        for (int i = 0; i < stack.length && printed < 8; i++) {
            StackTraceElement el = stack[i];
            String cn = el.getClassName();
            if (cn.startsWith("io.radiotracer.agent")
                    || cn.startsWith("java.lang.Thread")
                    || cn.startsWith("jdk.internal")) {
                continue;
            }
            out.println("    at " + el);
            printed++;
        }
    }

    private static String empty(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }
}
