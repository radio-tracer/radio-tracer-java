package io.radiotracer.agent.support;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reflection helpers so production code stays free of test-only visibility hooks.
 */
public final class TestAccess {

    private TestAccess() {}

    public static void setStaticField(Class<?> type, String name, Object value) {
        try {
            Field f = type.getDeclaredField(name);
            f.setAccessible(true);
            f.set(null, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to set " + type.getName() + "." + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T getStaticField(Class<?> type, String name) {
        try {
            Field f = type.getDeclaredField(name);
            f.setAccessible(true);
            return (T) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to get " + type.getName() + "." + name, e);
        }
    }

    public static Object invokeStatic(Class<?> type, String name, Class<?>[] paramTypes, Object... args) {
        try {
            Method m = type.getDeclaredMethod(name, paramTypes);
            m.setAccessible(true);
            return m.invoke(null, args);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to invoke " + type.getName() + "." + name, e);
        }
    }

    public static Object newInstance(Class<?> type, Class<?>[] paramTypes, Object... args) {
        try {
            Constructor<?> c = type.getDeclaredConstructor(paramTypes);
            c.setAccessible(true);
            return c.newInstance(args);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to construct " + type.getName(), e);
        }
    }

    public static Object invoke(Object target, String name, Class<?>[] paramTypes, Object... args) {
        try {
            Method m = target.getClass().getDeclaredMethod(name, paramTypes);
            m.setAccessible(true);
            return m.invoke(target, args);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to invoke " + target.getClass().getName() + "." + name, e);
        }
    }

    /** Reset HitReporter static runtime state between tests. */
    public static void resetHitReporter() {
        Class<?> hr;
        try {
            hr = Class.forName("io.radiotracer.agent.report.HitReporter");
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
        }
        ((AtomicLong) getStaticField(hr, "TOTAL_HITS")).set(0);
        ((ConcurrentHashMap<?, ?>) getStaticField(hr, "COUNTS")).clear();
        ((ConcurrentHashMap<?, ?>) getStaticField(hr, "FIRST_SEEN")).clear();
        setStaticField(hr, "reportPath", null);
        setStaticField(hr, "watchlist", java.util.List.of());
        setStaticField(hr, "runLabel", "");
        setStaticField(hr, "out", System.err);
    }

    /** Clear InstrumentedMethodDispatcher registry between tests. */
    public static void clearDispatcherRegistry() {
        Class<?> d;
        try {
            d = Class.forName("io.radiotracer.agent.InstrumentedMethodDispatcher");
        } catch (ClassNotFoundException e) {
            throw new AssertionError(e);
        }
        ((ConcurrentHashMap<?, ?>) getStaticField(d, "REGISTRY")).clear();
    }
}
