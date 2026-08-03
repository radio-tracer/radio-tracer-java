package io.radiotracer.agent.report;

import java.util.Locale;

/**
 * Identifies one JVM run in a multi-module / multi-process report.
 * <p>
 * Resolution order:
 * <ol>
 *   <li>Explicit agent arg {@code label=} / {@code runId=} / {@code module=}</li>
 *   <li>System property {@code radio.tracer.label} (or {@code .runId} / {@code .module})</li>
 *   <li>Maven {@code basedir} last path segment</li>
 *   <li>{@code user.dir} last path segment</li>
 *   <li>{@code pid-&lt;pid&gt;}</li>
 * </ol>
 */
public final class RunLabel {

    private RunLabel() {}

    public static String resolve(String configured) {
        if (notBlank(configured)) {
            return configured.trim();
        }
        String fromProp = firstProp(
                "radio.tracer.label",
                "radio.tracer.runId",
                "radio.tracer.module");
        if (notBlank(fromProp)) {
            return fromProp.trim();
        }
        String fromBasedir = lastSegment(System.getProperty("basedir"));
        if (notBlank(fromBasedir)) {
            return fromBasedir;
        }
        // user.dir is almost always set; still useful when basedir is absent (non-Maven)
        String fromUserDir = lastSegment(System.getProperty("user.dir", ""));
        if (notBlank(fromUserDir)) {
            return fromUserDir;
        }
        return "pid-" + ProcessHandle.current().pid();
    }

    /** Safe single path segment for fragment filenames. */
    public static String sanitize(String label) {
        if (label == null || label.isBlank()) {
            return "unknown";
        }
        String s = stripTrailingSlashes(label.trim().replace('\\', '/'));
        int slash = s.lastIndexOf('/');
        if (slash >= 0) {
            s = s.substring(slash + 1);
        }
        s = s.replaceAll("[^A-Za-z0-9._-]+", "_");
        if (s.isEmpty()) {
            return "unknown";
        }
        // Reject labels that are only separators (e.g. "..." or "___")
        if (s.replace("_", "").replace(".", "").replace("-", "").isEmpty()) {
            return "unknown";
        }
        if (s.length() > 80) {
            s = s.substring(0, 80);
        }
        return s;
    }

    public static long currentPid() {
        return ProcessHandle.current().pid();
    }

    private static String firstProp(String... keys) {
        for (String k : keys) {
            String v = System.getProperty(k);
            if (notBlank(v)) {
                return v;
            }
        }
        return null;
    }

    private static String lastSegment(String path) {
        if (!notBlank(path)) {
            return null;
        }
        String p = stripTrailingSlashes(path.trim().replace('\\', '/'));
        int slash = p.lastIndexOf('/');
        String leaf = slash >= 0 ? p.substring(slash + 1) : p;
        return leaf.isEmpty() ? null : leaf;
    }

    private static String stripTrailingSlashes(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return end == s.length() ? s : s.substring(0, end);
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    /** Display-friendly: strip noisy absolute prefixes for logs. */
    public static String display(String label) {
        if (label == null) {
            return "unknown";
        }
        return label.trim().isEmpty() ? "unknown" : label.trim();
    }

    public static String normalizeKey(String label) {
        return display(label).toLowerCase(Locale.ROOT);
    }
}
