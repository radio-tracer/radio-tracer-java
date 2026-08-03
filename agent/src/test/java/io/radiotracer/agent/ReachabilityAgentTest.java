package io.radiotracer.agent;

import io.radiotracer.agent.fixture.CtorTarget;
import io.radiotracer.agent.support.TestAccess;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReachabilityAgentTest {

    @BeforeEach
    @AfterEach
    void reset() {
        TestAccess.resetHitReporter();
        TestAccess.clearDispatcherRegistry();
    }

    @Test
    void premainAndAgentmainWithValidWatchlist(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("methods.json");
        Files.writeString(methods, """
                {
                  "methods": [
                    {
                      "cve": "CVE-T",
                      "package": "test:fixture",
                      "installedVersion": "1.0",
                      "upgradeTo": "2.0",
                      "severity": "critical",
                      "cvssScore": 9.8,
                      "className": "io.radiotracer.agent.fixture.WatchedTarget",
                      "methodName": "touch",
                      "source": "test",
                      "confidence": "high"
                    },
                    {
                      "cve": "CVE-O",
                      "package": "test:fixture",
                      "className": "io.radiotracer.agent.fixture.WatchedTarget",
                      "methodName": "overload",
                      "descriptor": "(Ljava/lang/String;)I",
                      "upgradeTo": "2.0"
                    }
                  ]
                }
                """);
        Path report = dir.resolve("out.html");
        Instrumentation inst = ByteBuddyAgent.install();

        String args = "methods=" + methods + ",report=" + report + ",verbose=true,label=demo-fixture";
        assertDoesNotThrow(() -> ReachabilityAgent.premain(args, inst));

        Class<?> target = Class.forName("io.radiotracer.agent.fixture.WatchedTarget");
        assertEquals("touched", target.getMethod("touch").invoke(null));
        target.getMethod("overload", String.class).invoke(null, "hi");

        io.radiotracer.agent.report.HitReporter.writeFinalReport();
        assertTrue(Files.isRegularFile(report));
    }

    @Test
    void agentmainWithInvalidArgsDoesNotThrow() {
        Instrumentation inst = ByteBuddyAgent.install();
        assertDoesNotThrow(() -> ReachabilityAgent.agentmain("methods=/no/such/file.json", inst));
    }

    @Test
    void premainWithEmptyLabelUsesAuto(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, """
                {"methods":[{"className":"java.lang.String","methodName":"length","cve":"C","package":"j"}]}
                """);
        Instrumentation inst = ByteBuddyAgent.install();
        assertDoesNotThrow(() ->
                ReachabilityAgent.premain("methods=" + methods + ",label=", inst));
    }

    @Test
    void premainWithSlackWebhookEnabled(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, """
                {"methods":[{"className":"java.lang.String","methodName":"length","cve":"C","package":"j"}]}
                """);
        Instrumentation inst = ByteBuddyAgent.install();
        assertDoesNotThrow(() ->
                ReachabilityAgent.premain(
                        "methods=" + methods
                                + ",slack=https://hooks.slack.com/services/T/B/XXX",
                        inst));
        // blank slack= should log slack=off (not throw)
        assertDoesNotThrow(() ->
                ReachabilityAgent.premain("methods=" + methods + ",slack=", inst));
    }

    @Test
    void startWithoutReportPath(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, """
                {"methods":[{"className":"java.lang.String","methodName":"length","cve":"C","package":"j"}]}
                """);
        Instrumentation inst = ByteBuddyAgent.install();
        assertDoesNotThrow(() ->
                ReachabilityAgent.premain("file=" + methods + ",verbose=false", inst));
    }

    @Test
    void emptyWatchlistStartsIdleWithoutThrowing(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("empty.json");
        Files.writeString(methods, "{\"methods\":[]}");
        Path report = dir.resolve("empty-report.html");
        Instrumentation inst = ByteBuddyAgent.install();
        assertDoesNotThrow(() ->
                ReachabilityAgent.premain(
                        "methods=" + methods + ",report=" + report + ",verbose=true", inst));
        // shutdown hook may write empty report later; no instrumentation expected
    }

    @Test
    void locationOfViaReflection() {
        assertEquals("?", TestAccess.invokeStatic(
                ReachabilityAgent.class, "locationOf",
                new Class<?>[]{ProtectionDomain.class}, new Object[]{null}));

        assertEquals("?", TestAccess.invokeStatic(
                ReachabilityAgent.class, "locationOf",
                new Class<?>[]{ProtectionDomain.class},
                new ProtectionDomain(null, null)));

        Object loc = TestAccess.invokeStatic(
                ReachabilityAgent.class, "locationOf",
                new Class<?>[]{ProtectionDomain.class},
                String.class.getProtectionDomain());
        assertTrue(loc.toString().equals("?") || loc.toString().length() > 0);

        CodeSource cs = new CodeSource(null, (Certificate[]) null);
        assertEquals("?", TestAccess.invokeStatic(
                ReachabilityAgent.class, "locationOf",
                new Class<?>[]{ProtectionDomain.class},
                new ProtectionDomain(cs, null)));
    }

    @Test
    void transformErrorListenerViaReflection() throws Exception {
        Class<?> listenerType = Class.forName(
                "io.radiotracer.agent.ReachabilityAgent$TransformErrorListener");
        Object quiet = TestAccess.newInstance(listenerType, new Class<?>[]{boolean.class}, false);
        Object verbose = TestAccess.newInstance(listenerType, new Class<?>[]{boolean.class}, true);

        Class<?>[] onErrorParams = {
                String.class,
                ClassLoader.class,
                net.bytebuddy.utility.JavaModule.class,
                boolean.class,
                Throwable.class
        };
        RuntimeException boom = new RuntimeException("weave failed");
        TestAccess.invoke(quiet, "onError", onErrorParams,
                "com.Example", null, null, false, boom);
        TestAccess.invoke(verbose, "onError", onErrorParams,
                "com.Example", null, null, true, boom);
    }

    @Test
    void instrumentsAllConstructorsWhenWatchlistUsesInit(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("methods.json");
        Files.writeString(methods, """
                {
                  "methods": [
                    {
                      "cve": "CVE-CTOR",
                      "package": "test:fixture",
                      "upgradeTo": "9.9",
                      "className": "io.radiotracer.agent.fixture.CtorTarget",
                      "methodName": "<init>",
                      "source": "snyk",
                      "confidence": "high"
                    }
                  ]
                }
                """);
        Path report = dir.resolve("ctor-out.html");
        Instrumentation inst = ByteBuddyAgent.install();
        // Install agent before first load of CtorTarget so constructors are instrumented.
        ReachabilityAgent.premain("methods=" + methods + ",report=" + report + ",verbose=true", inst);

        // Direct calls so the IDE/static analysis see the constructors as used
        // (reflection-only newInstance is often treated as dead code).
        new CtorTarget();
        new CtorTarget(42);
        new CtorTarget("hi");

        var results = io.radiotracer.agent.report.HitReporter.buildResults();
        assertEquals(1, results.size());
        assertEquals(io.radiotracer.agent.report.ReachabilityStatus.REACHABLE, results.get(0).status());
        // All three overloads counted under one watchlist entry (no descriptor).
        assertEquals(3, results.get(0).hitCount());

        io.radiotracer.agent.report.HitReporter.writeFinalReport();
        assertTrue(Files.isRegularFile(report));
        String html = Files.readString(report);
        assertTrue(html.contains("CVE-CTOR"));
        assertTrue(html.contains("REACHABLE"));
    }

    @Test
    void matcherForInitSelectsConstructorsOnly() throws Exception {
        var init = new Watchlist.VulnerableMethod(
                "C", "p", "1", "2",
                "io.radiotracer.agent.fixture.CtorTarget",
                Watchlist.CONSTRUCTOR_NAME, null, "s", "high",
                "", null, "");
        var named = new Watchlist.VulnerableMethod(
                "C", "p", "1", "2",
                "io.radiotracer.agent.fixture.CtorTarget",
                "toString", null, "s", "high",
                "", null, "");

        var initMatcher = ReachabilityAgent.matcherFor(init);
        var methodMatcher = ReachabilityAgent.matcherFor(named);

        net.bytebuddy.description.type.TypeDescription type =
                net.bytebuddy.pool.TypePool.Default.ofSystemLoader()
                        .describe("io.radiotracer.agent.fixture.CtorTarget")
                        .resolve();

        long ctorMatches = type.getDeclaredMethods().stream()
                .filter(initMatcher::matches)
                .count();
        long methodMatches = type.getDeclaredMethods().stream()
                .filter(methodMatcher::matches)
                .count();

        assertEquals(3, ctorMatches);
        assertEquals(0, methodMatches); // toString is inherited, not declared on CtorTarget
    }
}
