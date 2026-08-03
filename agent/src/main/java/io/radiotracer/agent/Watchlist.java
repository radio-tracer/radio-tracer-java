package io.radiotracer.agent;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Output of the (future) "find vulnerable methods" stage.
 * Methods almost always live in dependency JARs, not the application JAR.
 */
public final class Watchlist {

    /** JVM internal name for constructors (Snyk {@code functionName}, etc.). */
    public static final String CONSTRUCTOR_NAME = "<init>";

    private final List<VulnerableMethod> methods;
    private final Map<String, List<VulnerableMethod>> byClass;

    private Watchlist(List<VulnerableMethod> methods) {
        this.methods = List.copyOf(methods);
        this.byClass = methods.stream()
                .collect(Collectors.groupingBy(
                        VulnerableMethod::className,
                        HashMap::new,
                        Collectors.collectingAndThen(Collectors.toList(), List::copyOf)
                ));
    }

    public static Watchlist load(Path path) throws IOException {
        try (Reader reader = Files.newBufferedReader(path)) {
            return parse(reader);
        }
    }

    public static Watchlist parse(Reader reader) {
        Document doc = new Gson().fromJson(reader, Document.class);
        if (doc == null || doc.methods == null) {
            throw new IllegalArgumentException("Watchlist JSON must contain a non-null 'methods' array");
        }
        List<VulnerableMethod> parsed = doc.methods.stream()
                .map(VulnerableMethod::from)
                .toList();
        // Empty is allowed: agent starts, reports nothing to watch (useful for e2e wiring).
        return new Watchlist(parsed);
    }

    public List<VulnerableMethod> methods() {
        return methods;
    }

    public Set<String> watchedClassNames() {
        return byClass.keySet();
    }

    public List<VulnerableMethod> methodsForClass(String className) {
        return byClass.getOrDefault(className, List.of());
    }

    public int size() {
        return methods.size();
    }

    /** Gson DTO — field names match methods.json (extras in JSON are ignored). */
    static final class Document {
        List<MethodEntry> methods;

        static final class MethodEntry {
            String cve;
            @SerializedName("package")
            String packageCoord;
            String installedVersion;
            String upgradeTo;
            String severity;
            Double cvssScore;
            String cvssVector;
            String className;
            String methodName;
            String descriptor;
            String source;
            String confidence;
        }
    }

    /**
     * One watched callable. {@code severity} / {@code cvssScore} / {@code cvssVector}
     * come from the SCA importer when present; they are optional for hand-written watchlists.
     */
    public record VulnerableMethod(
            String cve,
            String packageCoord,
            String installedVersion,
            String upgradeTo,
            String className,
            String methodName,
            String descriptor,
            String source,
            String confidence,
            String severity,
            Double cvssScore,
            String cvssVector
    ) {
        static VulnerableMethod from(Document.MethodEntry e) {
            if (e.className == null || e.className.isBlank()) {
                throw new IllegalArgumentException("method entry missing className");
            }
            if (e.methodName == null || e.methodName.isBlank()) {
                throw new IllegalArgumentException("method entry missing methodName for " + e.className);
            }
            String desc = e.descriptor == null || e.descriptor.isBlank() ? null : e.descriptor.trim();
            return new VulnerableMethod(
                    nullToEmpty(e.cve),
                    nullToEmpty(e.packageCoord),
                    nullToEmpty(e.installedVersion),
                    nullToEmpty(e.upgradeTo),
                    e.className.trim(),
                    e.methodName.trim(),
                    desc,
                    nullToEmpty(e.source),
                    nullToEmpty(e.confidence),
                    nullToEmpty(e.severity),
                    e.cvssScore,
                    nullToEmpty(e.cvssVector)
            );
        }

        private static String nullToEmpty(String s) {
            return s == null ? "" : s;
        }

        public String displayMethod() {
            return className + "#" + methodName + (descriptor != null ? descriptor : "");
        }

        /** Human-readable CVSS base score, or empty when unknown. */
        public String cvssScoreDisplay() {
            if (cvssScore == null) {
                return "";
            }
            double v = cvssScore;
            if (Double.isNaN(v) || Double.isInfinite(v)) {
                return "";
            }
            // Prefer compact form: 9.0 → "9", 9.8 → "9.8"
            if (v == Math.rint(v)) {
                return Long.toString((long) v);
            }
            return Double.toString(v);
        }

        @Override
        public String toString() {
            return displayMethod() + (cve.isEmpty() ? "" : " [" + cve + "]");
        }
    }
}
