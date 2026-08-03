package io.radiotracer.agent;

import io.radiotracer.agent.report.HitReporter;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.Locale;

/**
 * Java agent entry point.
 * <p>
 * <b>Two different moments:</b>
 * <ol>
 *   <li><b>Instrument (class load):</b> when a watched class is loaded, inject a probe
 *       at the start of each watched method.</li>
 *   <li><b>Report (method call):</b> when that method actually runs, the probe fires.</li>
 * </ol>
 *
 * <pre>
 * java -javaagent:agent.jar=methods=methods.json,report=report.html \
 *      -cp app.jar:deps/* com.example.Main
 * </pre>
 */
public final class ReachabilityAgent {

    private ReachabilityAgent() {}

    public static void premain(String agentArgs, Instrumentation inst) {
        start(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        start(agentArgs, inst);
    }

    private static void start(String agentArgs, Instrumentation inst) {
        try {
            AgentConfig config = AgentConfig.parse(agentArgs);
            Watchlist watchlist = Watchlist.load(config.methodsPath());
            InstrumentedMethodDispatcher.registerAll(watchlist.methods());
            HitReporter.configure(config.reportPath(), watchlist.methods());

            Banner.print(System.err);
            System.err.println("[radio-tracer] agent starting...");
            System.err.println("[radio-tracer] watchlist=" + config.methodsPath().toAbsolutePath()
                    + " methods=" + watchlist.size()
                    + " classes=" + watchlist.watchedClassNames().size());
            if (config.reportPath() != null) {
                System.err.println("[radio-tracer] report=" + config.reportPath().toAbsolutePath());
            } else {
                System.err.println("[radio-tracer] report=none (console table only; no HTML file)");
            }
            if (watchlist.size() == 0) {
                System.err.println("[radio-tracer] watchlist is empty — agent idle (no instrumentation)");
            } else {
                for (Watchlist.VulnerableMethod m : watchlist.methods()) {
                    System.err.println("[radio-tracer]   watching " + m
                            + (m.upgradeTo().isEmpty() ? "" : " upgradeTo=" + m.upgradeTo()));
                }
                install(inst, watchlist, config.verbose());
                System.err.println("[radio-tracer] instrumentation installed at class-load time; "
                        + "hits reported when methods run");
            }

            // Classic Thread API keeps agent bytecode on Java 17+ (not Thread.ofPlatform from 21).
            Thread reportHook = new Thread(HitReporter::writeFinalReport, "radio-tracer-report");
            reportHook.setDaemon(false);
            Runtime.getRuntime().addShutdownHook(reportHook);
        } catch (Throwable t) {
            System.err.println("[radio-tracer] failed to start agent: " + t);
            t.printStackTrace(System.err);
        }
    }

    private static void install(Instrumentation inst, Watchlist watchlist, boolean verbose) {
        ElementMatcher.Junction<TypeDescription> typeMatcher = ElementMatchers.none();
        for (String cn : watchlist.watchedClassNames()) {
            typeMatcher = typeMatcher.or(ElementMatchers.named(cn));
        }

        new AgentBuilder.Default()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .ignore(ElementMatchers.nameStartsWith("io.radiotracer.agent"))
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy"))
                .type(typeMatcher)
                .transform((builder, typeDescription, classLoader, module, protectionDomain) -> {
                    String name = typeDescription.getName();
                    if (verbose) {
                        System.err.println("[radio-tracer] instrumenting class=" + name
                                + " from=" + locationOf(protectionDomain));
                    }

                    ElementMatcher.Junction<MethodDescription> methodMatcher = ElementMatchers.none();
                    for (Watchlist.VulnerableMethod m : watchlist.methodsForClass(name)) {
                        methodMatcher = methodMatcher.or(matcherFor(m));
                    }
                    return builder.visit(Advice.to(VulnerableMethodAdvice.class).on(methodMatcher));
                })
                .with(new TransformErrorListener(verbose))
                .installOn(inst);
    }

    /**
     * Builds a ByteBuddy matcher for one watchlist entry.
     * <p>
     * {@code <init>} selects constructors ({@link ElementMatchers#isConstructor()}).
     * Without a descriptor, <b>all</b> constructors of the class are watched (recall over
     * precision — false positives preferred over missed hits).
     */
    static ElementMatcher.Junction<MethodDescription> matcherFor(Watchlist.VulnerableMethod m) {
        ElementMatcher.Junction<MethodDescription> one;
        if (Watchlist.CONSTRUCTOR_NAME.equals(m.methodName())) {
            one = ElementMatchers.isConstructor();
        } else {
            one = ElementMatchers.named(m.methodName())
                    .and(ElementMatchers.isMethod())
                    .and(ElementMatchers.not(ElementMatchers.isAbstract()))
                    .and(ElementMatchers.not(ElementMatchers.isNative()));
        }
        String desc = m.descriptor();
        if (desc != null) {
            one = one.and(ElementMatchers.hasDescriptor(desc));
        }
        return one;
    }

    private static String locationOf(ProtectionDomain pd) {
        if (pd == null || pd.getCodeSource() == null || pd.getCodeSource().getLocation() == null) {
            return "?";
        }
        return pd.getCodeSource().getLocation().toString();
    }

    private static final class TransformErrorListener extends AgentBuilder.Listener.Adapter {
        private final boolean verbose;

        private TransformErrorListener(boolean verbose) {
            this.verbose = verbose;
        }

        @Override
        public void onError(
                String typeName,
                ClassLoader classLoader,
                JavaModule module,
                boolean loaded,
                Throwable throwable
        ) {
            System.err.println("[radio-tracer] transform error for " + typeName + ": " + throwable);
            if (verbose) {
                throwable.printStackTrace(System.err);
            }
        }
    }

    /** Parses agent {@code -javaagent} argument strings. */
    public record AgentConfig(Path methodsPath, Path reportPath, boolean verbose) {

        public static AgentConfig parse(String agentArgs) {
            if (agentArgs == null || agentArgs.isBlank()) {
                throw new IllegalArgumentException(
                        "Agent requires args. Example: -javaagent:agent.jar=methods=/path/methods.json,report=report.html"
                );
            }

            Path methods = null;
            Path report = null;
            boolean verbose = false;

            if (!agentArgs.contains("=") && !agentArgs.contains(",")) {
                methods = Path.of(agentArgs.trim());
            } else {
                for (String part : agentArgs.split(",")) {
                    String p = part.trim();
                    if (p.isEmpty()) {
                        continue;
                    }
                    int eq = p.indexOf('=');
                    if (eq < 0) {
                        if (methods == null) {
                            methods = Path.of(p);
                        }
                        continue;
                    }
                    String key = p.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                    String value = p.substring(eq + 1).trim();
                    switch (key) {
                        case "methods", "watchlist", "file" -> methods = Path.of(value);
                        case "report", "out", "output" -> report = Path.of(value);
                        case "verbose", "v" -> verbose = Boolean.parseBoolean(value) || "1".equals(value);
                        default -> System.err.println("[radio-tracer] unknown agent arg: " + key);
                    }
                }
            }

            if (methods == null) {
                throw new IllegalArgumentException("Missing methods= path in agent args: " + agentArgs);
            }
            if (!Files.isRegularFile(methods)) {
                throw new IllegalArgumentException("Methods file not found: " + methods.toAbsolutePath());
            }
            return new AgentConfig(methods, report, verbose);
        }
    }
}
