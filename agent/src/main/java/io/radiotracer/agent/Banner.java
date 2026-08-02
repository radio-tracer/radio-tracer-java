package io.radiotracer.agent;

/**
 * Terminal banner (ASCII — logs cannot render the PNG logo).
 */
final class Banner {

    private Banner() {}

    static void print(java.io.PrintStream out) {
        out.println();
        out.println("  ╔══════════════════════════════════════════╗");
        out.println("  ║                                          ║");
        out.println("  ║            ☢  RadioTracer                ║");
        out.println("  ║     Dynamic Reachability Analyzer        ║");
        out.println("  ║                                          ║");
        out.println("  ╚══════════════════════════════════════════╝");
        out.println();
    }
}
