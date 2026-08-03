package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;
import io.radiotracer.agent.support.TestAccess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HitReporterTest {

    @BeforeEach
    @AfterEach
    void reset() {
        TestAccess.resetHitReporter();
        TestAccess.clearDispatcherRegistry();
    }

    @Test
    void buildResultsMarksReachedAndNotObserved() {
        Watchlist.VulnerableMethod reached = new Watchlist.VulnerableMethod(
                "CVE-1", "g:lib", "1.0", "2.0",
                "com.ex.A", "foo", "()V", "osv", "high",
                "", null, "");
        Watchlist.VulnerableMethod notCalled = new Watchlist.VulnerableMethod(
                "CVE-2", "g:lib", "1.0", "2.1",
                "com.ex.A", "bar", null, "osv", "medium",
                "", null, "");

        HitReporter.configure(null, List.of(reached, notCalled));
        HitReporter.onMethodEnter("com.ex.A", "foo", "()V", "CVE-1", "g:lib");
        HitReporter.onMethodEnter("com.ex.A", "foo", "()V", "CVE-1", "g:lib");

        List<MethodResult> results = HitReporter.buildResults();
        assertEquals(2, results.size());
        assertEquals(ReachabilityStatus.REACHABLE, results.get(0).status());
        assertEquals(2, results.get(0).hitCount());
        assertEquals(ReachabilityStatus.NOT_OBSERVED, results.get(1).status());
    }

    @Test
    void writeFinalReportCreatesHtml(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-9", "org.demo:lib", "3.0.0", "3.1.0",
                "org.demo.X", "run", null, "scan", "high",
                "critical", 9.8, "CVSS:3.1/AV:N");
        Path report = dir.resolve("out.html");
        HitReporter.configure(report, List.of(m));
        HitReporter.onMethodEnter(
                "org.demo.X", "run", "()V", "CVE-9", "org.demo:lib", "critical", 9.8);
        HitReporter.writeFinalReport();
        assertTrue(Files.isRegularFile(report));
        String html = Files.readString(report);
        assertTrue(html.contains("CVE-9"));
        assertTrue(html.contains("critical"));
        assertTrue(html.contains("9.8"));
    }

    @Test
    void onMethodEnterLogsSeverityAndCvss(@TempDir Path dir) throws Exception {
        Path log = dir.resolve("err.txt");
        PrintStream capture = new PrintStream(Files.newOutputStream(log));
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-LOG", "g:lib", "1", "2", "c.L", "hit", "()V", "s", "high",
                "high", 7.5, "");
        HitReporter.configure(null, List.of(m));
        TestAccess.setStaticField(HitReporter.class, "out", capture);
        HitReporter.onMethodEnter("c.L", "hit", "()V", "CVE-LOG", "g:lib", "high", 7.5);
        capture.flush();
        String text = Files.readString(log);
        assertTrue(text.contains("[REACHABLE]"));
        assertTrue(text.contains("severity=high"));
        assertTrue(text.contains("cvss=7.5"));
        assertTrue(text.contains("cve=CVE-LOG"));
        TestAccess.setStaticField(HitReporter.class, "out", System.err);
    }

    @Test
    void formatCvssCoversNullNanInfiniteAndWhole() {
        assertEquals("?", TestAccess.invokeStatic(
                HitReporter.class, "formatCvss", new Class<?>[]{Double.class}, (Object) null));
        assertEquals("?", TestAccess.invokeStatic(
                HitReporter.class, "formatCvss", new Class<?>[]{Double.class}, Double.NaN));
        assertEquals("?", TestAccess.invokeStatic(
                HitReporter.class, "formatCvss", new Class<?>[]{Double.class}, Double.NEGATIVE_INFINITY));
        assertEquals("9", TestAccess.invokeStatic(
                HitReporter.class, "formatCvss", new Class<?>[]{Double.class}, 9.0));
        assertEquals("7.5", TestAccess.invokeStatic(
                HitReporter.class, "formatCvss", new Class<?>[]{Double.class}, 7.5));
    }

    @Test
    void writeFinalReportOverwritesWhenHitsPresent(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-OW", "g:a", "1", "2", "c.O", "m", null, "", "",
                "", null, "");
        Path report = dir.resolve("out.html");
        Files.writeString(report, "STALE");
        HitReporter.configure(report, List.of(m));
        HitReporter.onMethodEnter("c.O", "m", "()V", "CVE-OW", "g:a");
        HitReporter.writeFinalReport();
        String html = Files.readString(report);
        assertTrue(html.contains("CVE-OW"));
        assertFalse(html.contains("STALE"));
    }

    @Test
    void writeFinalReportSkipsEmptyOverwriteOfExisting(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-KEEP", "g:a", "1", "2", "c.K", "m", null, "", "",
                "", null, "");
        Path report = dir.resolve("keep.html");
        Files.writeString(report, "GOOD-REPORT-WITH-HITS");
        HitReporter.configure(report, List.of(m));
        // no onMethodEnter → total hits 0
        HitReporter.writeFinalReport();
        assertEquals("GOOD-REPORT-WITH-HITS", Files.readString(report));
    }

    @Test
    void writeFinalReportWritesEmptyWhenNoPriorFile(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-E", "g:a", "1", "2", "c.E", "m", null, "", "",
                "", null, "");
        Path report = dir.resolve("empty-new.html");
        HitReporter.configure(report, List.of(m));
        HitReporter.writeFinalReport();
        assertTrue(Files.isRegularFile(report));
        assertTrue(Files.readString(report).contains("no reachable")
                || Files.readString(report).contains("REACHABLE"));
    }

    @Test
    void writeFinalReportWithNoHitsAndNoHtmlPath() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-0", "g:a", "1", "2", "c.A", "never", null, "", "",
                "", null, "");
        HitReporter.configure(null, List.of(m));
        HitReporter.writeFinalReport();
        assertEquals(0, HitReporter.buildResults().get(0).hitCount());
    }

    @Test
    void configureNullMethodsList() {
        HitReporter.configure(null, null);
        assertEquals(0, HitReporter.buildResults().size());
    }

    @Test
    void onMethodEnterWithNullDescriptorAndEmptyCve() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-N", "g:a", "1", "2", "c.N", "n", null, "", "",
                "", null, "");
        HitReporter.configure(null, List.of(m));
        HitReporter.onMethodEnter("c.N", "n", null, "", "");
        assertEquals(1, HitReporter.buildResults().get(0).hitCount());
    }

    @Test
    void resolveHitsMatchesDescriptorsThroughPublicApi() {
        Watchlist.VulnerableMethod nameOnly = new Watchlist.VulnerableMethod(
                "C1", "g", "1", "2", "pkg.A", "m", null, "", "",
                "", null, "");
        Watchlist.VulnerableMethod exactHit = new Watchlist.VulnerableMethod(
                "C2", "g", "1", "2", "pkg.B", "go", "()V", "", "",
                "", null, "");
        // Pinned descriptor not present in hits → exact lookup misses, prefix still matches other overload
        Watchlist.VulnerableMethod exactMiss = new Watchlist.VulnerableMethod(
                "C3", "g", "1", "2", "pkg.C", "run", "()V", "", "",
                "", null, "");

        HitReporter.configure(null, List.of(nameOnly, exactHit, exactMiss));
        HitReporter.onMethodEnter("pkg.A", "m", "", "C1", "g");
        HitReporter.onMethodEnter("pkg.A", "m", "(I)V", "C1", "g");
        HitReporter.onMethodEnter("pkg.B", "go", "()V", "C2", "g");
        HitReporter.onMethodEnter("pkg.C", "run", "(I)V", "C3", "g");
        HitReporter.onMethodEnter("pkg.Other", "z", "()V", "Cx", "g");

        List<MethodResult> results = HitReporter.buildResults();
        assertEquals(2, results.get(0).hitCount());
        assertEquals(1, results.get(1).hitCount());
        assertEquals(1, results.get(2).hitCount());
    }

    @Test
    void ensureHtmlPathVariantsViaReflection() {
        Path p = (Path) TestAccess.invokeStatic(
                HitReporter.class, "ensureHtmlPath",
                new Class<?>[]{Path.class}, Path.of("/tmp/hits.log"));
        assertEquals("hits.html", p.getFileName().toString());

        p = (Path) TestAccess.invokeStatic(
                HitReporter.class, "ensureHtmlPath",
                new Class<?>[]{Path.class}, Path.of("/tmp/out.htm"));
        assertEquals("out.htm", p.getFileName().toString());

        p = (Path) TestAccess.invokeStatic(
                HitReporter.class, "ensureHtmlPath",
                new Class<?>[]{Path.class}, Path.of("/tmp/out.html"));
        assertEquals("out.html", p.getFileName().toString());

        p = (Path) TestAccess.invokeStatic(
                HitReporter.class, "ensureHtmlPath",
                new Class<?>[]{Path.class}, Path.of("/tmp/report"));
        assertEquals("report.html", p.getFileName().toString());
    }

    @Test
    void writeReportCreatesParentDirs(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-P", "g:a", "1", "2", "c.P", "p", null, "", "",
                "", null, "");
        Path nested = dir.resolve("a/b/c/report.html");
        HitReporter.configure(nested, List.of(m));
        HitReporter.onMethodEnter("c.P", "p", "()V", "CVE-P", "g:a");
        HitReporter.writeFinalReport();
        assertTrue(Files.isRegularFile(nested));
    }

    @Test
    void writeHtmlWithRelativePathNoParent() throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-R", "g:a", "1", "2", "c.R", "r", null, "", "",
                "", null, "");
        Path relative = Path.of("target-test-report-no-parent.html");
        try {
            HitReporter.configure(relative, List.of(m));
            HitReporter.onMethodEnter("c.R", "r", "()V", "CVE-R", "g:a");
            HitReporter.writeFinalReport();
            assertTrue(Files.isRegularFile(relative) || Files.isRegularFile(relative.toAbsolutePath()));
        } finally {
            Files.deleteIfExists(relative);
        }
    }

    @Test
    void onMethodEnterSwallowsBrokenOutputAndPrintsDeepStack() {
        PrintStream broken = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) {
                throw new RuntimeException("broken out");
            }
        }, true);
        HitReporter.configure(null, List.of());
        TestAccess.setStaticField(HitReporter.class, "out", broken);
        HitReporter.onMethodEnter("c.X", "y", "()V", null, null);

        TestAccess.setStaticField(HitReporter.class, "out", System.err);
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-S", "g:a", "1", "2", "c.S", "s", null, "", "",
                "", null, "");
        HitReporter.configure(null, List.of(m));
        deepHit(12);
        assertEquals(1, HitReporter.buildResults().get(0).hitCount());
    }

    @Test
    void printCallerStackViaReflectionCoversEmptyAndCap() {
        TestAccess.invokeStatic(
                HitReporter.class, "printCallerStack",
                new Class<?>[]{PrintStream.class, StackTraceElement[].class},
                System.err, new StackTraceElement[0]);

        StackTraceElement skip = new StackTraceElement("io.radiotracer.agent.X", "m", "X.java", 1);
        StackTraceElement skipThread = new StackTraceElement("java.lang.Thread", "run", "Thread.java", 1);
        StackTraceElement skipJdk = new StackTraceElement("jdk.internal.misc.Unsafe", "x", "U.java", 1);
        StackTraceElement keep = new StackTraceElement("com.example.App", "main", "App.java", 2);
        StackTraceElement[] many = new StackTraceElement[12];
        for (int i = 0; i < many.length; i++) {
            many[i] = switch (i % 4) {
                case 0 -> skip;
                case 1 -> skipThread;
                case 2 -> skipJdk;
                default -> keep;
            };
        }
        TestAccess.invokeStatic(
                HitReporter.class, "printCallerStack",
                new Class<?>[]{PrintStream.class, StackTraceElement[].class},
                System.err, many);
    }

    @Test
    void writeFinalReportSwallowsIoFailure(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-F", "g:a", "1", "2", "c.F", "f", null, "", "",
                "", null, "");
        Path blocker = dir.resolve("blocker");
        Files.writeString(blocker, "not-a-dir");
        Path impossible = blocker.resolve("out.html");
        HitReporter.configure(impossible, List.of(m));
        HitReporter.onMethodEnter("c.F", "f", "()V", "CVE-F", "g:a");
        HitReporter.writeFinalReport();
    }

    private static void deepHit(int n) {
        if (n <= 0) {
            HitReporter.onMethodEnter("c.S", "s", "()V", "CVE-S", "g:a");
            return;
        }
        deepHit(n - 1);
    }
}
