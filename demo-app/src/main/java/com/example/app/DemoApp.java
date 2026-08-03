package com.example.app;

import com.example.vulnlib.CryptoHelper;
import com.example.vulnlib.DeserUtil;

/**
 * Demo application.
 * <ul>
 *   <li>Default: browser UI on {@code http://localhost:8080} (video / manual demos)</li>
 *   <li>{@code --cli}: headless path that hits watched methods and exits (CI)</li>
 * </ul>
 * Vulnerable methods live in {@code demo-lib}, not this JAR.
 */
public final class DemoApp {

    private DemoApp() {}

    public static void main(String[] args) throws Exception {
        if (args != null) {
            for (String a : args) {
                if ("--cli".equals(a) || "-c".equals(a)) {
                    runCli();
                    return;
                }
                if ("--help".equals(a) || "-h".equals(a)) {
                    printHelp();
                    return;
                }
            }
        }
        int port = resolvePort();
        DemoWebServer server = new DemoWebServer(port);
        server.start();
        System.out.println("DemoApp UI: http://localhost:" + port + "/");
        System.out.println("With agent attached, click \"Generate report\" to fire a watched method.");
        System.out.println("Press Ctrl+C to stop.");
        // Keep process alive until killed (agent report writes on JVM exit).
        Thread.currentThread().join();
    }

    /** Headless demo used by CI / integration-demo.sh. */
    static void runCli() {
        System.out.println("DemoApp starting (dep version=" + CryptoHelper.version() + ")");

        Object o = OrderService.importOrder("{\"id\":1}");
        System.out.println("importOrder -> " + o);

        byte[] plain = PaymentClient.decryptToken(new byte[]{1, 2, 3, 4}, "secret");
        System.out.println("decryptToken -> " + plain.length + " bytes");

        System.out.println("fingerprint -> " + DeserUtil.fingerprint("noise"));

        System.out.println("DemoApp done");
    }

    private static int resolvePort() {
        String env = System.getenv("DEMO_PORT");
        if (env != null && !env.isBlank()) {
            return Integer.parseInt(env.trim());
        }
        String prop = System.getProperty("demo.port");
        if (prop != null && !prop.isBlank()) {
            return Integer.parseInt(prop.trim());
        }
        return 8080;
    }

    private static void printHelp() {
        System.out.println("""
                RadioTracer demo-app

                  (default)   Start browser UI on http://localhost:8080
                  --cli, -c   Headless: call vulnerable paths once and exit
                  --help, -h  This help

                Env / properties:
                  DEMO_PORT / -Ddemo.port   UI listen port (default 8080)

                Example with agent:
                  java -javaagent:agent.jar=methods=examples/methods.json,report=/tmp/rt.html \\
                    -cp demo-app.jar:deps/* com.example.app.DemoApp
                """);
    }
}
