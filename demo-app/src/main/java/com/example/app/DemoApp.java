package com.example.app;

import com.example.vulnlib.CryptoHelper;
import com.example.vulnlib.DeserUtil;

/**
 * Application code. This JAR does not contain the vulnerable methods;
 * it only <em>calls</em> them in the dependency {@code demo-lib}.
 * <p>
 * That mirrors real SCA: the CVE is in a transitive/direct dep, and we care
 * whether app execution reaches those dep methods.
 */
public final class DemoApp {

    public static void main(String[] args) {
        System.out.println("DemoApp starting (dep version=" + CryptoHelper.version() + ")");

        // Path 1: reaches a watched vulnerable method in the dependency.
        Object o = OrderService.importOrder("{\"id\":1}");
        System.out.println("importOrder -> " + o);

        // Path 2: another watched method.
        byte[] plain = PaymentClient.decryptToken(new byte[]{1, 2, 3, 4}, "secret");
        System.out.println("decryptToken -> " + plain.length + " bytes");

        // Path 3: dependency method that is NOT on the watchlist — should not report.
        System.out.println("fingerprint -> " + DeserUtil.fingerprint("noise"));

        System.out.println("DemoApp done");
    }
}
