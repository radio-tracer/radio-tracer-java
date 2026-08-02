package io.radiotracer.agent;

import io.radiotracer.agent.report.HitReporter;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maps (class, method, descriptor) → watchlist metadata so advice stays allocation-light.
 */
public final class InstrumentedMethodDispatcher {

    private static final ConcurrentHashMap<String, Watchlist.VulnerableMethod> REGISTRY =
            new ConcurrentHashMap<>();

    private InstrumentedMethodDispatcher() {}

    private static void register(Watchlist.VulnerableMethod method) {
        REGISTRY.put(method.className() + "#" + method.methodName(), method);
        String descriptor = method.descriptor();
        if (descriptor != null) {
            REGISTRY.put(method.className() + "#" + method.methodName() + descriptor, method);
        }
    }

    static void registerAll(List<Watchlist.VulnerableMethod> methods) {
        for (Watchlist.VulnerableMethod m : methods) {
            register(m);
        }
    }

    public static void dispatch(String className, String methodName, String descriptor) {
        Watchlist.VulnerableMethod m = null;
        if (descriptor != null) {
            m = REGISTRY.get(className + "#" + methodName + descriptor);
        }
        if (m == null) {
            m = REGISTRY.get(className + "#" + methodName);
        }
        if (m == null) {
            HitReporter.onMethodEnter(
                    className, methodName, descriptor == null ? "" : descriptor, "", "");
            return;
        }
        HitReporter.onMethodEnter(
                m.className(),
                m.methodName(),
                descriptor != null ? descriptor : "",
                m.cve(),
                m.packageCoord());
    }
}
