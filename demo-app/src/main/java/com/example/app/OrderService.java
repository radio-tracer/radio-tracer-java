package com.example.app;

import com.example.vulnlib.DeserUtil;

/** App-layer code that eventually calls into the vulnerable dependency. */
public final class OrderService {

    private OrderService() {}

    public static Object importOrder(String json) {
        // Business logic wrapper — the CVE method is one call deeper.
        return DeserUtil.deserialize(json);
    }
}
