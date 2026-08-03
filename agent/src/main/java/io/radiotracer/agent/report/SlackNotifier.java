package io.radiotracer.agent.report;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * Posts RadioTracer reachability events to a Slack Incoming Webhook.
 * Failures are logged and never fail the app under test.
 */
public final class SlackNotifier {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final String webhookUrl;
    private final BiFunction<String, String, Integer> poster;

    public SlackNotifier(String webhookUrl) {
        this(webhookUrl, SlackNotifier::httpPost);
    }

    /** Test seam: (url, jsonBody) → HTTP status. */
    SlackNotifier(String webhookUrl, BiFunction<String, String, Integer> poster) {
        this.webhookUrl = webhookUrl == null ? "" : webhookUrl.trim();
        this.poster = Objects.requireNonNull(poster);
    }

    public boolean enabled() {
        return !webhookUrl.isEmpty();
    }

    public String redactedUrl() {
        if (!enabled()) {
            return "(disabled)";
        }
        // Never log the full secret; show a short stable prefix only.
        int keep = Math.min(32, webhookUrl.length());
        return webhookUrl.substring(0, keep) + "…";
    }

    /** Instant alert when a watched method is first reached. */
    public void notifyFirstReachable(
            String cve,
            String severity,
            String cvss,
            String packageCoord,
            String method,
            String label,
            String thread
    ) {
        if (!enabled()) {
            return;
        }
        String sev = empty(severity, "unknown");
        String emoji = switch (sev.toLowerCase()) {
            case "critical" -> ":rotating_light:";
            case "high" -> ":warning:";
            case "medium" -> ":large_orange_diamond:";
            default -> ":information_source:";
        };
        String text = emoji + " *RadioTracer REACHABLE*\n"
                + "• *CVE:* " + empty(cve, "?") + "\n"
                + "• *Severity:* " + sev + "  *CVSS:* " + empty(cvss, "?") + "\n"
                + "• *Package:* `" + empty(packageCoord, "?") + "`\n"
                + "• *Method:* `" + empty(method, "?") + "`\n"
                + "• *Run:* " + empty(label, "?") + " · thread `" + empty(thread, "?") + "`";
        post(text);
    }

    /** End-of-run summary for REACHABLE rows (this JVM). */
    public void notifySummary(String label, List<MethodResult> reached, long totalHits) {
        if (!enabled() || reached == null || reached.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(":mag: *RadioTracer summary* · run `").append(empty(label, "?"))
                .append("` · reachable *").append(reached.size())
                .append("* · hits *").append(totalHits).append("*\n");
        int n = 0;
        for (MethodResult r : reached) {
            if (n >= 10) {
                sb.append("• …and ").append(reached.size() - 10).append(" more\n");
                break;
            }
            sb.append("• `").append(empty(r.cve(), "?"))
                    .append("` ").append(empty(r.severity(), "?"))
                    .append(" · `").append(r.method().displayMethod()).append("`")
                    .append(" (hits ").append(r.hitCount()).append(")\n");
            n++;
        }
        post(sb.toString().trim());
    }

    private void post(String text) {
        try {
            String json = "{\"text\":" + jsonString(text) + "}";
            Integer status = poster.apply(webhookUrl, json);
            if (status == null || status < 200 || status >= 300) {
                System.err.println("[radio-tracer] Slack webhook HTTP " + status
                        + " (" + redactedUrl() + ")");
            } else {
                System.err.println("[radio-tracer] Slack notified (" + redactedUrl() + ")");
            }
        } catch (Throwable t) {
            System.err.println("[radio-tracer] Slack notify failed: " + t.getMessage());
        }
    }

    private static int httpPost(String url, String jsonBody) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(TIMEOUT)
                    .build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            return res.statusCode();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    static String jsonString(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String empty(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }
}
