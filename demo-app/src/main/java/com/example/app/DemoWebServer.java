package com.example.app;

import com.example.vulnlib.CryptoHelper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.Executors;

/**
 * Tiny embedded HTTP UI for product demos (no external web framework).
 */
final class DemoWebServer {

    private final int port;
    private HttpServer server;

    DemoWebServer(int port) {
        this.port = port;
    }

    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", this::serveIndex);
        server.createContext("/api/health", this::health);
        server.createContext("/api/generate-report", this::generateReport);
        server.createContext("/api/process-payment", this::processPayment);
        server.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "demo-http");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    private void serveIndex(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=utf-8", "Method not allowed");
            return;
        }
        byte[] body = loadResource("/static/index.html");
        if (body == null) {
            send(ex, 500, "text/plain; charset=utf-8", "UI asset missing: /static/index.html");
            return;
        }
        send(ex, 200, "text/html; charset=utf-8", body);
    }

    private void health(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=utf-8", "Method not allowed");
            return;
        }
        String json = "{\"ok\":true,\"service\":\"radio-tracer-demo\",\"depVersion\":\""
                + escapeJson(CryptoHelper.version()) + "\",\"time\":\"" + Instant.now() + "\"}";
        send(ex, 200, "application/json; charset=utf-8", json);
    }

    /**
     * "Generate report" — app path that reaches watched {@code DeserUtil.deserialize}.
     * With the agent attached, this emits {@code [REACHABLE]} for CVE-2023-DEMO-0001.
     */
    private void generateReport(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=utf-8", "Method not allowed");
            return;
        }
        String payload = "{\"reportId\":\"demo-" + Instant.now().getEpochSecond()
                + "\",\"user\":\"demo\",\"format\":\"pdf\"}";
        System.out.println("[demo-ui] Generate report clicked → OrderService.importOrder(...)");
        Object result = OrderService.importOrder(payload);
        System.out.println("[demo-ui] importOrder returned: " + result);

        String json = "{\"ok\":true,"
                + "\"action\":\"generate-report\","
                + "\"watchedMethod\":\"com.example.vulnlib.DeserUtil#deserialize\","
                + "\"cve\":\"CVE-2023-DEMO-0001\","
                + "\"severity\":\"critical\","
                + "\"result\":\"" + escapeJson(String.valueOf(result)) + "\","
                + "\"hint\":\"Check the terminal for [REACHABLE] from the RadioTracer agent.\"}";
        send(ex, 200, "application/json; charset=utf-8", json);
    }

    /**
     * Secondary action → watched {@code CryptoHelper.weakDecrypt}.
     */
    private void processPayment(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "text/plain; charset=utf-8", "Method not allowed");
            return;
        }
        System.out.println("[demo-ui] Process payment clicked → PaymentClient.decryptToken(...)");
        byte[] plain = PaymentClient.decryptToken(new byte[]{9, 8, 7, 6}, "demo-secret");
        System.out.println("[demo-ui] decryptToken -> " + plain.length + " bytes");

        String json = "{\"ok\":true,"
                + "\"action\":\"process-payment\","
                + "\"watchedMethod\":\"com.example.vulnlib.CryptoHelper#weakDecrypt\","
                + "\"cve\":\"CVE-2023-DEMO-0002\","
                + "\"severity\":\"high\","
                + "\"bytes\":" + plain.length + ","
                + "\"hint\":\"Check the terminal for [REACHABLE] from the RadioTracer agent.\"}";
        send(ex, 200, "application/json; charset=utf-8", json);
    }

    private static byte[] loadResource(String path) throws IOException {
        try (InputStream in = DemoWebServer.class.getResourceAsStream(path)) {
            if (in == null) {
                return null;
            }
            return in.readAllBytes();
        }
    }

    private static void send(HttpExchange ex, int status, String contentType, String body)
            throws IOException {
        send(ex, status, contentType, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int status, String contentType, byte[] body)
            throws IOException {
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", contentType);
        h.set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
