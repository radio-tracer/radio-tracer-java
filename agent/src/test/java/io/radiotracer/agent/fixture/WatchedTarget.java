package io.radiotracer.agent.fixture;

/**
 * Loaded only via {@link Class#forName} after the agent is installed so instrumentation
 * applies on first class load.
 */
public final class WatchedTarget {

    private WatchedTarget() {}

    public static String touch() {
        return "touched";
    }

    public static int overload(String s) {
        return s == null ? 0 : s.length();
    }

    public static int overload(int n) {
        return n;
    }
}
