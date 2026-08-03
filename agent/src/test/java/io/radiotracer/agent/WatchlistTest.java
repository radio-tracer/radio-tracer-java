package io.radiotracer.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WatchlistTest {

    @Test
    void parseMethodsWithUpgradeAndVersions() {
        String json = """
                {
                  "version": 1,
                  "methods": [
                    {
                      "cve": "CVE-1",
                      "package": "g:a",
                      "installedVersion": "1.0.0",
                      "upgradeTo": "1.2.0",
                      "severity": "critical",
                      "cvssScore": 9.8,
                      "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      "className": "com.foo.Bar",
                      "methodName": "baz",
                      "descriptor": "()V",
                      "source": "osv",
                      "confidence": "high"
                    }
                  ]
                }
                """;
        Watchlist wl = Watchlist.parse(new StringReader(json));
        assertEquals(1, wl.size());
        Watchlist.VulnerableMethod m = wl.methods().get(0);
        assertEquals("CVE-1", m.cve());
        assertEquals("g:a", m.packageCoord());
        assertEquals("1.0.0", m.installedVersion());
        assertEquals("1.2.0", m.upgradeTo());
        assertEquals("critical", m.severity());
        assertEquals(9.8, m.cvssScore());
        assertEquals("9.8", m.cvssScoreDisplay());
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", m.cvssVector());
        assertEquals("com.foo.Bar", m.className());
        assertEquals("baz", m.methodName());
        assertEquals("()V", m.descriptor());
        assertTrue(wl.watchedClassNames().contains("com.foo.Bar"));
        assertEquals(1, wl.methodsForClass("com.foo.Bar").size());
        assertEquals(List.of(), wl.methodsForClass("no.Such"));
        assertTrue(m.toString().contains("CVE-1"));
        assertTrue(m.displayMethod().contains("baz"));
    }

    @Test
    void severityAndCvssOptionalWhenAbsent() {
        Watchlist wl = Watchlist.parse(new StringReader("""
                {"methods":[{
                  "className":"a.B",
                  "methodName":"m",
                  "cve":"CVE-X"
                }]}
                """));
        Watchlist.VulnerableMethod m = wl.methods().get(0);
        assertEquals("", m.severity());
        assertEquals(null, m.cvssScore());
        assertEquals("", m.cvssScoreDisplay());
        assertEquals("", m.cvssVector());
    }

    @Test
    void cvssScoreDisplayFormatsWholeNumbersAndGuards() {
        Watchlist.VulnerableMethod whole = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", 7.0, "");
        assertEquals("7", whole.cvssScoreDisplay());
        Watchlist.VulnerableMethod frac = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", 9.8, "");
        assertEquals("9.8", frac.cvssScoreDisplay());
        Watchlist.VulnerableMethod nan = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", Double.NaN, "");
        assertEquals("", nan.cvssScoreDisplay());
        Watchlist.VulnerableMethod inf = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", Double.POSITIVE_INFINITY, "");
        assertEquals("", inf.cvssScoreDisplay());
        Watchlist.VulnerableMethod missing = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "2", "c.A", "m", null, "s", "high",
                "high", null, "");
        assertEquals("", missing.cvssScoreDisplay());
    }

    @Test
    void loadFromFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("methods.json");
        Files.writeString(file, """
                {"version":1,"methods":[
                  {"cve":"CVE-X","package":"p:l","className":"a.B","methodName":"m"}
                ]}
                """);
        Watchlist wl = Watchlist.load(file);
        assertEquals(1, wl.size());
        assertEquals("CVE-X", wl.methods().get(0).cve());
        // no descriptor → display without descriptor suffix only class#method
        assertEquals("a.B#m", wl.methods().get(0).displayMethod());
        assertTrue(wl.methods().get(0).toString().contains("CVE-X"));
    }

    @Test
    void allowsEmptyMethods() throws Exception {
        Watchlist wl = Watchlist.parse(new StringReader("{\"methods\":[]}"));
        assertEquals(0, wl.size());
        assertTrue(wl.watchedClassNames().isEmpty());
    }

    @Test
    void rejectsNullDocumentShape() {
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader("null")));
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader("{}")));
    }

    @Test
    void rejectsMissingClassName() {
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader(
                        "{\"methods\":[{\"methodName\":\"m\"}]}")));
    }

    @Test
    void rejectsBlankClassNameAndMethodName() {
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader(
                        "{\"methods\":[{\"className\":\"   \",\"methodName\":\"m\"}]}")));
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader(
                        "{\"methods\":[{\"className\":\"a.B\",\"methodName\":\"  \"}]}")));
    }

    @Test
    void rejectsMissingMethodName() {
        assertThrows(IllegalArgumentException.class,
                () -> Watchlist.parse(new StringReader(
                        "{\"methods\":[{\"className\":\"a.B\"}]}")));
    }

    @Test
    void blankDescriptorBecomesNullAndBlankFieldsEmpty() {
        Watchlist wl = Watchlist.parse(new StringReader("""
                {"methods":[{
                  "className":" a.B ",
                  "methodName":" m ",
                  "descriptor":"  ",
                  "cve":null
                }]}
                """));
        Watchlist.VulnerableMethod m = wl.methods().get(0);
        assertEquals("a.B", m.className());
        assertEquals("m", m.methodName());
        assertEquals(null, m.descriptor());
        assertEquals("", m.cve());
        assertEquals("a.B#m", m.toString()); // empty cve → no suffix
    }
}
