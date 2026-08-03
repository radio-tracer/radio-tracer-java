package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;
import io.radiotracer.agent.support.TestAccess;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlReportWriterTest {

    @Test
    void renderIncludesCveLibraryUpgradeAndStatuses() {
        Watchlist.VulnerableMethod a = new Watchlist.VulnerableMethod(
                "CVE-A", "g:a", "1.0", "1.1", "c.A", "m1", null, "osv", "high",
                "critical", 9.8, "CVSS:3.1/AV:N");
        String html = HtmlReportWriter.render(
                List.of(new MethodResult(a, ReachabilityStatus.REACHABLE, 3)),
                2, 1, Instant.parse("2026-01-01T00:00:00Z"), 3);
        assertTrue(html.contains("CVE-A"));
        assertTrue(html.contains("g:a@1.0"));
        assertTrue(html.contains("1.1"));
        assertTrue(html.contains("critical"));
        assertTrue(html.contains("9.8"));
        assertTrue(html.contains("<th>Severity</th>"));
        assertTrue(html.contains("<th>CVSS</th>"));
        assertTrue(html.contains("REACHABLE"));
        assertTrue(html.contains("NOT_OBSERVED"));
        assertTrue(html.contains("Confidence"));
        assertTrue(html.contains(ZoneId.systemDefault().getId())
                || html.contains("Generated"));
    }

    @Test
    void renderEmptyReachedRows() {
        String html = HtmlReportWriter.render(List.of(), 3, 3, Instant.now(), 0);
        assertTrue(html.contains("No reachable vulnerable methods observed"));
    }

    @Test
    void renderMergedSumsHitsAcrossJvms() {
        JvmRunSnapshot a = new JvmRunSnapshot();
        a.watchedTotal = 3;
        JvmRunSnapshot.ReachedRow rowA = new JvmRunSnapshot.ReachedRow();
        rowA.cve = "CVE-1";
        rowA.method = "c.A#m";
        rowA.status = "REACHABLE";
        rowA.hitCount = 2;
        a.reached = List.of(rowA);

        JvmRunSnapshot b = new JvmRunSnapshot();
        b.watchedTotal = 3;
        JvmRunSnapshot.ReachedRow rowB = new JvmRunSnapshot.ReachedRow();
        rowB.cve = "CVE-1";
        rowB.method = "c.A#m";
        rowB.status = "REACHABLE";
        rowB.hitCount = 3;
        b.reached = List.of(rowB);

        String html = HtmlReportWriter.renderMerged(List.of(a, b), Instant.parse("2026-01-01T00:00:00Z"));
        assertTrue(html.contains("CVE-1"));
        assertTrue(html.contains("total invocations: 5"));
        assertTrue(html.contains("hit counts summed"));
        assertFalse(html.contains("data-tab="));
    }

    @Test
    void renderMergedEmptyProducesPlaceholder() {
        String html = HtmlReportWriter.renderMerged(List.of(), Instant.now());
        assertTrue(html.contains("Dynamic Reachability Report"));
        assertTrue(html.contains("No reachable"));
        assertTrue(HtmlReportWriter.renderMerged(null, Instant.now()).contains("Dynamic Reachability Report"));
    }

    @Test
    void consoleTableHasHeadersAndEmptyOptionalFields() {
        Watchlist.VulnerableMethod a = new Watchlist.VulnerableMethod(
                "", "g:a", "1.0", "1.1", "c.A", "m1", null, "", "",
                "", null, "");
        String table = HtmlReportWriter.consoleTable(
                List.of(new MethodResult(a, ReachabilityStatus.NOT_OBSERVED, 0)));
        assertTrue(table.contains("CVE"));
        assertTrue(table.contains("Severity"));
        assertTrue(table.contains("CVSS"));
        assertTrue(table.contains("—"));
        assertTrue(table.contains("NOT_OBSERVED"));
    }

    @Test
    void escapesHtmlInFields() {
        Watchlist.VulnerableMethod a = new Watchlist.VulnerableMethod(
                "<script>", "g:a", "1", "2", "c.A", "m", null, "x", "y",
                "", null, "");
        String html = HtmlReportWriter.render(
                List.of(new MethodResult(a, ReachabilityStatus.REACHABLE, 1)),
                1, 0, Instant.now(), 1);
        assertTrue(html.contains("&lt;script&gt;"));
        // Tab UI may include a real <script> block; CVE cell must stay escaped.
        assertTrue(html.contains("<td>&lt;script&gt;</td>")
                || html.contains(">&lt;script&gt;<"));
        assertFalse(html.contains("<td><script>"));
    }

    @Test
    void formatGeneratedAtUtcViaRender() {
        TimeZone previous = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            String html = HtmlReportWriter.render(List.of(), 0, 0, Instant.EPOCH, 0);
            assertTrue(html.contains("UTC"));
            assertTrue(html.contains("+00:00") || html.contains("UTC+00:00") || html.contains("UTC"));
        } finally {
            TimeZone.setDefault(previous);
        }
    }

    /** Covers the non-Z offset branch (skipped on UTC CI runners by default). */
    @Test
    void formatGeneratedAtNonUtcOffsetViaRender() {
        TimeZone previous = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("America/New_York"));
            Instant winter = Instant.parse("2026-01-15T12:00:00Z"); // EST, UTC-5
            String html = HtmlReportWriter.render(List.of(), 0, 0, winter, 0);
            assertTrue(html.contains("America/New_York"));
            assertTrue(html.contains("-05:00") || html.contains("UTC-05:00") || html.contains("-05"));
        } finally {
            TimeZone.setDefault(previous);
        }
    }

    @Test
    void renderHandlesNullMetadataFields() {
        Watchlist.VulnerableMethod b = new Watchlist.VulnerableMethod(
                null, null, null, null, "c.A", "m", null, null, null,
                "", null, "");
        String html = HtmlReportWriter.render(
                List.of(new MethodResult(b, ReachabilityStatus.REACHABLE, 1)),
                1, 0, Instant.now(), 1);
        assertTrue(html.contains("c.A#m") || html.contains("REACHABLE"));
    }

    @Test
    void escNullViaReflection() {
        Object empty = TestAccess.invokeStatic(
                HtmlReportWriter.class, "esc", new Class<?>[]{String.class}, (Object) null);
        assertEquals("", empty);
        Object escaped = TestAccess.invokeStatic(
                HtmlReportWriter.class, "esc", new Class<?>[]{String.class}, "a&b");
        assertTrue(escaped.toString().contains("&amp;"));
        assertEquals("—", HtmlReportWriter.emptyAsDash(null));
        assertEquals("—", HtmlReportWriter.emptyAsDash(""));
        assertEquals("x", HtmlReportWriter.emptyAsDash("x"));
    }
}

