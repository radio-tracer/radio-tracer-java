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
        if (parsed.isEmpty()) {
            throw new IllegalArgumentException("Watchlist has zero methods; nothing to instrument");
        }
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
            String className;
            String methodName;
            String descriptor;
            String source;
            String confidence;
        }
    }

    public record VulnerableMethod(
            String cve,
            String packageCoord,
            String installedVersion,
            String upgradeTo,
            String className,
            String methodName,
            String descriptor,
            String source,
            String confidence
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
                    nullToEmpty(e.confidence)
            );
        }

        private static String nullToEmpty(String s) {
            return s == null ? "" : s;
        }

        public String displayMethod() {
            return className + "#" + methodName + (descriptor != null ? descriptor : "");
        }

        @Override
        public String toString() {
            return displayMethod() + (cve.isEmpty() ? "" : " [" + cve + "]");
        }
    }
}
