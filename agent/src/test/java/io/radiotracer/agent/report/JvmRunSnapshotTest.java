package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JvmRunSnapshotTest {

    @Test
    void roundTripWriteRead(@TempDir Path dir) throws Exception {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-1", "g:a", "1", "2", "c.A", "foo", "()V", "src", "high",
                "critical", 9.8, "");
        MethodResult r = new MethodResult(m, ReachabilityStatus.REACHABLE, 2);
        JvmRunSnapshot s = JvmRunSnapshot.fromResults("mod-a", 42, List.of(r), 2, Instant.EPOCH);
        Path file = dir.resolve("mod-a-42.json");
        s.write(file);

        JvmRunSnapshot loaded = JvmRunSnapshot.read(file);
        assertEquals("mod-a", loaded.label());
        assertEquals(42, loaded.pid());
        assertEquals(1, loaded.reachableCount());
        assertEquals("CVE-1", loaded.reached().get(0).cve());
        assertTrue(loaded.hasHits());
    }

    @Test
    void mergeReachedSumsHitsForSameCveAndMethod() {
        JvmRunSnapshot.ReachedRow r1 = new JvmRunSnapshot.ReachedRow();
        r1.cve = "CVE-1";
        r1.method = "c.A#m";
        r1.hitCount = 2;
        r1.severity = "high";
        JvmRunSnapshot.ReachedRow r2 = new JvmRunSnapshot.ReachedRow();
        r2.cve = "CVE-1";
        r2.method = "c.A#m";
        r2.hitCount = 3;
        JvmRunSnapshot.ReachedRow r3 = new JvmRunSnapshot.ReachedRow();
        r3.cve = "CVE-2";
        r3.method = "c.B#n";
        r3.hitCount = 1;

        JvmRunSnapshot a = new JvmRunSnapshot();
        a.reached = List.of(r1);
        a.watchedTotal = 5;
        JvmRunSnapshot b = new JvmRunSnapshot();
        b.reached = List.of(r2, r3);
        b.watchedTotal = 5;

        List<JvmRunSnapshot.ReachedRow> merged = JvmRunSnapshot.mergeReached(List.of(a, b));
        assertEquals(2, merged.size());
        assertEquals(5, merged.stream().filter(r -> "CVE-1".equals(r.cve())).findFirst().orElseThrow().hitCount());
        assertEquals("high", merged.stream().filter(r -> "CVE-1".equals(r.cve())).findFirst().orElseThrow().severity());
        assertTrue(JvmRunSnapshot.mergeReached(null).isEmpty());
        assertTrue(JvmRunSnapshot.mergeReached(List.of()).isEmpty());
        assertEquals(5, JvmRunSnapshot.maxWatched(List.of(a, b)));
        assertEquals(0, JvmRunSnapshot.maxWatched(null));
    }

    @Test
    void loadAllSkipsBadJsonAndSorts(@TempDir Path dir) throws Exception {
        assertTrue(JvmRunSnapshot.loadAll(null).isEmpty());
        assertTrue(JvmRunSnapshot.loadAll(dir.resolve("missing")).isEmpty());

        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "C", "g", "1", "2", "c.A", "m", null, "", "",
                "", null, null);
        JvmRunSnapshot a = JvmRunSnapshot.fromResults(
                "b-mod", 2, List.of(new MethodResult(m, ReachabilityStatus.NOT_OBSERVED, 0)), 0, Instant.now());
        JvmRunSnapshot b = JvmRunSnapshot.fromResults(
                "a-mod", 1, List.of(new MethodResult(m, ReachabilityStatus.REACHABLE, 1)), 1, Instant.now());
        a.write(dir.resolve("b-mod-2.json"));
        b.write(dir.resolve("a-mod-1.json"));
        Files.writeString(dir.resolve("broken.json"), "{not-json");

        List<JvmRunSnapshot> all = JvmRunSnapshot.loadAll(dir);
        assertEquals(2, all.size());
        assertEquals("a-mod", all.get(0).label());
        assertFalse(a.hasHits());
    }

    @Test
    void readNormalizesMissingLabelAndReached(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("x.json");
        Files.writeString(f, "{\"version\":1,\"label\":\"\",\"pid\":1,\"reached\":null}");
        assertEquals("unknown", JvmRunSnapshot.read(f).label());
        assertTrue(JvmRunSnapshot.read(f).reached().isEmpty());

        Files.writeString(dir.resolve("null-label.json"), "{\"version\":1,\"label\":null,\"pid\":1}");
        assertEquals("unknown", JvmRunSnapshot.read(dir.resolve("null-label.json")).label());

        Files.writeString(dir.resolve("null.json"), "null");
        assertEquals("unknown", JvmRunSnapshot.read(dir.resolve("null.json")).label());

        JvmRunSnapshot emptyHits = new JvmRunSnapshot();
        emptyHits.totalHits = 1;
        emptyHits.reachableCount = 0;
        assertFalse(emptyHits.hasHits());
        emptyHits.totalHits = 0;
        emptyHits.reachableCount = 1;
        assertFalse(emptyHits.hasHits());
        emptyHits.reached = null;
        assertTrue(emptyHits.reached().isEmpty());
        assertEquals(0, emptyHits.totalHits());
    }

    @Test
    void reachedRowNullAndEmptySafeGetters() {
        JvmRunSnapshot.ReachedRow row = new JvmRunSnapshot.ReachedRow();
        row.cve = null;
        row.severity = null;
        row.cvssScore = null;
        row.library = null;
        row.upgradeTo = null;
        row.method = null;
        row.status = null;
        row.confidence = null;
        row.source = null;
        assertEquals("", row.cve());
        assertEquals("", row.severity());
        assertEquals("", row.cvssScore());
        assertEquals("?", row.library());
        assertEquals("—", row.upgradeTo());
        assertEquals("", row.method());
        assertEquals("REACHABLE", row.status());
        assertEquals("", row.confidence());
        assertEquals("", row.source());

        row.library = "";
        row.upgradeTo = "";
        assertEquals("?", row.library());
        assertEquals("—", row.upgradeTo());
        row.library = "g:a";
        row.upgradeTo = "2";
        row.severity = "high";
        row.cvssScore = "9.8";
        row.method = "m";
        row.status = "REACHABLE";
        row.confidence = "high";
        row.source = "s";
        assertEquals("g:a", row.library());
        assertEquals("2", row.upgradeTo());
        assertEquals("high", row.severity());
        assertEquals("9.8", row.cvssScore());
        assertEquals("m", row.method());
        assertEquals("high", row.confidence());
        assertEquals("s", row.source());
    }

    @Test
    void writeWithRelativePathNoParent() throws Exception {
        Path rel = Path.of("rt-fragment-tmp.json");
        try {
            JvmRunSnapshot s = JvmRunSnapshot.fromResults("x", 1, List.of(), 0, Instant.EPOCH);
            s.write(rel);
            assertTrue(Files.isRegularFile(rel));
        } finally {
            Files.deleteIfExists(rel);
        }
    }
}
