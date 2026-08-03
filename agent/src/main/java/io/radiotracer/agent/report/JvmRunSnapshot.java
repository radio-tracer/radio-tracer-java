package io.radiotracer.agent.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.radiotracer.agent.Watchlist;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * One JVM's reachability result, persisted so multi-module runs can merge into one HTML report.
 * Gson-friendly field layout (package-private fields + default ctor).
 */
public final class JvmRunSnapshot {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    public static final int VERSION = 1;

    int version = VERSION;
    String label = "unknown";
    long pid;
    String generatedAt = "";
    long totalHits;
    int watchedTotal;
    int reachableCount;
    List<ReachedRow> reached = List.of();

    public JvmRunSnapshot() {
        // Gson
    }

    public static JvmRunSnapshot fromResults(
            String label,
            long pid,
            List<MethodResult> allResults,
            long totalHits,
            Instant generatedAt
    ) {
        JvmRunSnapshot s = new JvmRunSnapshot();
        s.version = VERSION;
        s.label = RunLabel.display(label);
        s.pid = pid;
        s.generatedAt = generatedAt.toString();
        s.totalHits = totalHits;
        s.watchedTotal = allResults.size();
        List<ReachedRow> rows = new ArrayList<>();
        for (MethodResult r : allResults) {
            if (!r.status().isReached()) {
                continue;
            }
            Watchlist.VulnerableMethod m = r.method();
            rows.add(ReachedRow.from(r, m));
        }
        s.reachableCount = rows.size();
        s.reached = List.copyOf(rows);
        return s;
    }

    public void write(Path path) throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(path, GSON.toJson(this), StandardCharsets.UTF_8);
    }

    public static JvmRunSnapshot read(Path path) throws IOException {
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            JvmRunSnapshot s = GSON.fromJson(reader, JvmRunSnapshot.class);
            if (s == null) {
                s = new JvmRunSnapshot();
            }
            if (s.label == null) {
                s.label = "unknown";
            } else if (s.label.isBlank()) {
                s.label = "unknown";
            }
            if (s.reached == null) {
                s.reached = List.of();
            }
            return s;
        }
    }

    public static List<JvmRunSnapshot> loadAll(Path fragmentsDir) throws IOException {
        if (fragmentsDir == null || !Files.isDirectory(fragmentsDir)) {
            return List.of();
        }
        List<JvmRunSnapshot> out = new ArrayList<>();
        try (var stream = Files.list(fragmentsDir)) {
            stream.filter(p -> p.getFileName().toString().endsWith(".json"))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .forEach(p -> {
                        try {
                            out.add(read(p));
                        } catch (Exception e) {
                            System.err.println("[radio-tracer] skip bad fragment " + p + ": " + e);
                        }
                    });
        }
        out.sort(Comparator
                .comparing((JvmRunSnapshot s) -> RunLabel.normalizeKey(s.label()))
                .thenComparingLong(JvmRunSnapshot::pid));
        return out;
    }

    public String label() {
        return label;
    }

    public long pid() {
        return pid;
    }

    public String generatedAt() {
        return generatedAt;
    }

    public long totalHits() {
        return totalHits;
    }

    public int watchedTotal() {
        return watchedTotal;
    }

    public int reachableCount() {
        return reachableCount;
    }

    public List<ReachedRow> reached() {
        return reached == null ? List.of() : reached;
    }

    public boolean hasHits() {
        return totalHits > 0 && reachableCount > 0;
    }

    /** One REACHABLE row for HTML/JSON. */
    public static final class ReachedRow {
        String cve = "";
        String severity = "";
        String cvssScore = "";
        String library = "?";
        String upgradeTo = "—";
        String method = "";
        String status = "REACHABLE";
        long hitCount;
        String confidence = "";
        String source = "";

        public ReachedRow() {
            // Gson
        }

        static ReachedRow from(MethodResult r, Watchlist.VulnerableMethod m) {
            ReachedRow row = new ReachedRow();
            row.cve = r.cve();
            row.severity = r.severity();
            row.cvssScore = r.cvssScore();
            row.library = r.library();
            row.upgradeTo = r.upgradeTo();
            row.method = m.displayMethod();
            row.status = r.status().name();
            row.hitCount = r.hitCount();
            row.confidence = m.confidence() == null ? "" : m.confidence();
            row.source = m.source() == null ? "" : m.source();
            return row;
        }

        public String cve() {
            return cve == null ? "" : cve;
        }

        public String severity() {
            return severity == null ? "" : severity;
        }

        public String cvssScore() {
            return cvssScore == null ? "" : cvssScore;
        }

        public String library() {
            return library == null || library.isEmpty() ? "?" : library;
        }

        public String upgradeTo() {
            return upgradeTo == null || upgradeTo.isEmpty() ? "—" : upgradeTo;
        }

        public String method() {
            return method == null ? "" : method;
        }

        public String status() {
            return status == null ? "REACHABLE" : status;
        }

        public long hitCount() {
            return hitCount;
        }

        public String confidence() {
            return confidence == null ? "" : confidence;
        }

        public String source() {
            return source == null ? "" : source;
        }
    }
}
