package com.example.vulnlib;

/**
 * Stand-in for a vulnerable dependency helper (e.g. unsafe deserialization).
 * Lives in demo-lib.jar — NOT in the application JAR.
 */
public final class DeserUtil {

    private DeserUtil() {}

    /** Simulated vulnerable entry point (called by demo app). */
    public static Object deserialize(String payload) {
        return "deserialized:" + payload;
    }

    /**
     * Simulated vulnerable entry point that the demo app never calls —
     * stays NOT_OBSERVED in the report.
     */
    public static Object legacyParse(byte[] raw) {
        return "legacy:" + (raw == null ? 0 : raw.length);
    }

    /** Safe-looking method that is NOT on the watchlist. */
    public static String fingerprint(String payload) {
        return Integer.toHexString(payload.hashCode());
    }
}
