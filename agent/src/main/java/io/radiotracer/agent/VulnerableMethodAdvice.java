package io.radiotracer.agent;

import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice injected at the start of each watched method body.
 * Origin bindings supply the declaring type, method name, and JVM descriptor.
 */
public final class VulnerableMethodAdvice {

    private VulnerableMethodAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(
            @Advice.Origin("#t") String className,
            @Advice.Origin("#m") String methodName,
            @Advice.Origin("#d") String descriptor
    ) {
        InstrumentedMethodDispatcher.dispatch(className, methodName, descriptor);
    }
}
