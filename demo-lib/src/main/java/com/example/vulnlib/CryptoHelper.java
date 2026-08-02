package com.example.vulnlib;

/**
 * Another "vulnerable" API in the dependency JAR.
 */
public final class CryptoHelper {

    private CryptoHelper() {}

    public static byte[] weakDecrypt(byte[] ciphertext, String password) {
        byte[] out = new byte[ciphertext.length];
        byte key = (byte) password.hashCode();
        for (int i = 0; i < ciphertext.length; i++) {
            out[i] = (byte) (ciphertext[i] ^ key);
        }
        return out;
    }

    /**
     * Vulnerable method never invoked by the demo app (NOT_OBSERVED).
     */
    public static String legacyHash(String input) {
        return Integer.toHexString(input == null ? 0 : input.hashCode());
    }

    public static String version() {
        return "1.0.0-vulnerable";
    }
}
