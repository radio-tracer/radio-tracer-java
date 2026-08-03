package io.radiotracer.agent.report;

import com.sun.net.httpserver.HttpServer;
import io.radiotracer.agent.Watchlist;
import io.radiotracer.agent.support.TestAccess;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SlackNotifierTest {

    @Test
    void disabledWhenWebhookBlank() {
        assertFalse(new SlackNotifier(null).enabled());
        assertFalse(new SlackNotifier("  ").enabled());
        assertTrue(new SlackNotifier("https://hooks.slack.com/services/T/B/XXX").enabled());
        assertEquals("(disabled)", new SlackNotifier(null).redactedUrl());
    }

    @Test
    void redactsWebhookUrl() {
        String redacted = new SlackNotifier("https://hooks.slack.com/services/T00/B00/ABCD1234")
                .redactedUrl();
        assertTrue(redacted.startsWith("https://hooks.slack.com/"));
        assertTrue(redacted.endsWith("…"));
        assertTrue(redacted.length() < "https://hooks.slack.com/services/T00/B00/ABCD1234".length());
        assertEquals("(disabled)", new SlackNotifier("").redactedUrl());
    }

    @Test
    void notifyFirstReachablePostsJson() {
        AtomicReference<String> body = new AtomicReference<>();
        SlackNotifier n = new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    body.set(json);
                    return 200;
                });
        n.notifyFirstReachable(
                "CVE-1", "critical", "9.8", "g:a", "c.A#m()V", "demo", "main");
        assertTrue(body.get().contains("REACHABLE"));
        assertTrue(body.get().contains("CVE-1"));
        assertTrue(body.get().contains("critical"));
        assertTrue(body.get().startsWith("{\"text\":"));

        n.notifyFirstReachable("C", "high", "7", "p", "m", "l", "t");
        n.notifyFirstReachable("C", "medium", "5", "p", "m", "l", "t");
        n.notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
        n.notifyFirstReachable(null, null, null, null, null, null, null);
        n.notifyFirstReachable("", "", "", "", "", "", "");
    }

    @Test
    void notifySummaryPostsWhenReachable() {
        AtomicReference<String> body = new AtomicReference<>();
        SlackNotifier n = new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    body.set(json);
                    return 200;
                });
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-9", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", 7.5, "");
        n.notifySummary("run", List.of(new MethodResult(m, ReachabilityStatus.REACHABLE, 3)), 3);
        assertTrue(body.get().contains("summary"));
        assertTrue(body.get().contains("CVE-9"));
    }

    @Test
    void notifySummarySkipsWhenEmptyOrDisabled() {
        AtomicReference<String> body = new AtomicReference<>();
        SlackNotifier n = new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    body.set(json);
                    return 200;
                });
        n.notifySummary("run", List.of(), 0);
        n.notifySummary("run", null, 0);
        assertEquals(null, body.get());
        new SlackNotifier(null).notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
    }

    @Test
    void notifySummaryTruncatesLongLists() {
        AtomicReference<String> body = new AtomicReference<>();
        SlackNotifier n = new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    body.set(json);
                    return 200;
                });
        List<MethodResult> many = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                    "CVE-" + i, "g:a", "1", "2", "c.A", "m" + i, null, "s", "high",
                    "high", 7.0, "");
            many.add(new MethodResult(m, ReachabilityStatus.REACHABLE, 1));
        }
        n.notifySummary("run", many, 12);
        assertTrue(body.get().contains("and 2 more"));
    }

    @Test
    void notifySwallowsHttpErrorsAndPosterExceptions() {
        new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> 500)
                .notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
        new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> 100)
                .notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
        new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> null)
                .notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
        new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    throw new RuntimeException("boom");
                })
                .notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
    }

    @Test
    void jsonStringEscapes() {
        assertEquals("\"\"", SlackNotifier.jsonString(null));
        assertEquals("\"a\\\"b\"", SlackNotifier.jsonString("a\"b"));
        assertTrue(SlackNotifier.jsonString("a\\b").contains("\\\\"));
        assertTrue(SlackNotifier.jsonString("a\nb").contains("\\n"));
        assertTrue(SlackNotifier.jsonString("a\tb\r").contains("\\t"));
        assertTrue(SlackNotifier.jsonString("\u0001").contains("\\u"));
    }

    @Test
    void realHttpPostConnectionFailureIsSwallowed() {
        // Nothing listening — exercise HttpClient error path inside default poster.
        new SlackNotifier("http://127.0.0.1:1/nope")
                .notifyFirstReachable("C", "low", "1", "p", "m", "l", "t");
    }

    @Test
    void realHttpPostAgainstLocalServer() throws Exception {
        AtomicReference<String> received = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", ex -> {
            received.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] ok = "ok".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, ok.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(ok);
            }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/hook";
            SlackNotifier n = new SlackNotifier(url);
            n.notifyFirstReachable("CVE-HTTP", "critical", "9.8", "g:a", "c.A#m", "lab", "main");
            assertTrue(received.get() != null && received.get().contains("CVE-HTTP"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void hitReporterSendsSlackOnFirstReachable() {
        List<String> posts = new ArrayList<>();
        SlackNotifier n = new SlackNotifier(
                "https://hooks.slack.com/services/T/B/XXX",
                (url, json) -> {
                    posts.add(json);
                    return 200;
                });
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-S", "g:lib", "1", "2", "c.S", "hit", "()V", "s", "high",
                "critical", 9.8, "");
        HitReporter.configure(null, List.of(m), "ui-demo", "https://hooks.slack.com/services/T/B/XXX");
        TestAccess.setStaticField(HitReporter.class, "slack", n);
        HitReporter.onMethodEnter("c.S", "hit", "()V", "CVE-S", "g:lib", "critical", 9.8);
        assertEquals(1, posts.size());
        assertTrue(posts.get(0).contains("CVE-S"));
        HitReporter.writeFinalReport();
        assertEquals(2, posts.size());
        assertTrue(posts.get(1).contains("summary"));
    }
}
