package com.example.app;

import com.example.vulnlib.CryptoHelper;

public final class PaymentClient {

    private PaymentClient() {}

    public static byte[] decryptToken(byte[] token, String password) {
        return CryptoHelper.weakDecrypt(token, password);
    }
}
