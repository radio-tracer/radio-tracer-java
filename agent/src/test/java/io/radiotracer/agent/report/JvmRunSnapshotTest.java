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
        // parent == null branch of write (relative path in temp cwd)
        Path prev = Path.of("").toAbsolutePath();
        try {
            System.setProperty("user.dir", dir.toString());
            JvmRunSnapshot bare = JvmRunSnapshot.fromResults("x", 1, List.of(), 0, Instant.EPOCH);
            bare.write(Path.of("bare-fragment.json"));
            assertTrue(Files.isRegularFile(dir.resolve("bare-fragment.json"))
                    || Files.isRegularFile(Path.of("bare-fragment.json")));
        } finally {
            Files.deleteIfExists(Path.of("bare-fragment.json"));
            Files.deleteIfExists(dir.resolve("bare-fragment.json"));
        }
        assertFalse(s.hasHits() && s.reachableCount() == 0);
        JvmRunSnapshot zero = new JvmRunSnapshot();
        zero.totalHits = 1;
        zero.reachableCount = 0;
        assertFalse(zero.hasHits());
        zero.totalHits = 0;
        zero.reachableCount = 1;
        assertFalse(zero.hasHits());
    }

    @Test
    void loadAllSkipsBadAndSorts(@TempDir Path dir) throws Exception {
        assertTrue(JvmRunSnapshot.loadAll(dir.resolve("missing")).isEmpty());
        assertTrue(JvmRunSnapshot.loadAll(null).isEmpty());

        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "C", "g", "1", "2", "c.A", "m", null, "", "",
                "", null, null);
        JvmRunSnapshot a = JvmRunSnapshot.fromResults(
                "b-mod", 2, List.of(new MethodResult(m, ReachabilityStatus.NOT_OBSERVED, 0)), 0, Instant.now());
        JvmRunSnapshot b = JvmRunSnapshot.fromResults(
                "a-mod", 1, List.of(new MethodResult(m, ReachabilityStatus.REACHABLE, 1)), 1, Instant.now());
        // force a hit for b
        b.totalHits = 1;
        b.reachableCount = 1;
        b.reached = List.of(JvmRunSnapshot.ReachedRow.from(
                new MethodResult(m, ReachabilityStatus.REACHABLE, 1), m));

        a.write(dir.resolve("b-mod-2.json"));
        b.write(dir.resolve("a-mod-1.json"));
        Files.writeString(dir.resolve("broken.json"), "{not-json");

        List<JvmRunSnapshot> all = JvmRunSnapshot.loadAll(dir);
        assertEquals(2, all.size());
        assertEquals("a-mod", all.get(0).label());
        assertFalse(a.hasHits());
    }

    @Test
    void reachedRowNullSafeGetters() {
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
        row.status = "REACHABLE";
        assertEquals("g:a", row.library());
        assertEquals("2", row.upgradeTo());
        assertEquals("REACHABLE", row.status());
    }

    @Test
    void readNormalizesBlankLabelAndNullReached(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("x.json");
        Files.writeString(f, "{\"version\":1,\"label\":\"\",\"pid\":1,\"reached\":null}");
        JvmRunSnapshot s = JvmRunSnapshot.read(f);
        assertEquals("unknown", s.label());
        assertTrue(s.reached().isEmpty());

        Path noLabel = dir.resolve("nolabel.json");
        // Explicit JSON null forces Gson to set label=null (absent fields may keep defaults).
        Files.writeString(noLabel, "{\"version\":1,\"label\":null,\"pid\":9}");
        JvmRunSnapshot missing = JvmRunSnapshot.read(noLabel);
        assertEquals("unknown", missing.label());
        assertEquals("", missing.generatedAt() == null ? "" : missing.generatedAt());

        Path empty = dir.resolve("empty.json");
        Files.writeString(empty, "null");
        JvmRunSnapshot n = JvmRunSnapshot.read(empty);
        assertEquals("unknown", n.label());
        assertTrue(n.reached().isEmpty());

        JvmRunSnapshot mut = new JvmRunSnapshot();
        mut.reached = null;
        assertTrue(mut.reached().isEmpty());
    }
}
