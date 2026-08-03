package io.radiotracer.agent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
// assertNull already imported

class AgentConfigTest {

    @Test
    void parseBarePath(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        ReachabilityAgent.AgentConfig cfg = ReachabilityAgent.AgentConfig.parse(methods.toString());
        assertEquals(methods, cfg.methodsPath());
        assertNull(cfg.reportPath());
        assertFalse(cfg.verbose());

        // comma without '=' — not the bare-path shortcut
        assertThrows(IllegalArgumentException.class,
                () -> ReachabilityAgent.AgentConfig.parse(methods.getFileName() + ",other"));
    }

    @Test
    void parseKeyValue(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        Path report = dir.resolve("report.html");
        String args = "methods=" + methods + ",report=" + report + ",verbose=true,label=todolist-core";
        ReachabilityAgent.AgentConfig cfg = ReachabilityAgent.AgentConfig.parse(args);
        assertEquals(methods, cfg.methodsPath());
        assertEquals(report, cfg.reportPath());
        assertTrue(cfg.verbose());
        assertEquals("todolist-core", cfg.label());
    }

    @Test
    void parseRunIdAndModuleAliases(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        assertEquals("svc", ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",runId=svc").label());
        assertEquals("mod", ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",module=mod").label());
        assertEquals("", ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",label=").label());
    }

    @Test
    void parseSlackWebhook(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        String url = "https://hooks.slack.com/services/T/B/XXX";
        ReachabilityAgent.AgentConfig cfg = ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",slack=" + url);
        assertEquals(url, cfg.slackWebhook());
        ReachabilityAgent.AgentConfig cfg2 = ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",webhook=" + url);
        assertEquals(url, cfg2.slackWebhook());
        assertNull(ReachabilityAgent.AgentConfig.parse("methods=" + methods).slackWebhook());
    }

    @Test
    void firstNonBlankPrefersPrimaryThenSecondary() {
        assertEquals("a", ReachabilityAgent.AgentConfig.firstNonBlank("a", "b"));
        assertEquals("b", ReachabilityAgent.AgentConfig.firstNonBlank("  ", "b"));
        assertEquals("b", ReachabilityAgent.AgentConfig.firstNonBlank(null, " b "));
        assertNull(ReachabilityAgent.AgentConfig.firstNonBlank(null, null));
        assertNull(ReachabilityAgent.AgentConfig.firstNonBlank("", "  "));
    }

    @Test
    void parseAliasesWatchlistFileOutOutputVerboseOne(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        Path report = dir.resolve("r.html");

        ReachabilityAgent.AgentConfig a = ReachabilityAgent.AgentConfig.parse(
                "watchlist=" + methods + ",out=" + report + ",v=1");
        assertEquals(methods, a.methodsPath());
        assertEquals(report, a.reportPath());
        assertTrue(a.verbose());

        ReachabilityAgent.AgentConfig b = ReachabilityAgent.AgentConfig.parse(
                "file=" + methods + ",output=" + report + ",verbose=false");
        assertEquals(methods, b.methodsPath());
        assertFalse(b.verbose());
    }

    @Test
    void parseBareTokenAmongCommasAndEmptySegments(@TempDir Path dir) throws Exception {
        Path methods = dir.resolve("m.json");
        Files.writeString(methods, "{}");
        // empty segment + bare path token + unknown key
        String args = "," + methods + ",,unknown=xyz";
        ReachabilityAgent.AgentConfig cfg = ReachabilityAgent.AgentConfig.parse(args);
        assertEquals(methods, cfg.methodsPath());

        // second bare token ignored when methods already set
        ReachabilityAgent.AgentConfig cfg2 = ReachabilityAgent.AgentConfig.parse(
                "methods=" + methods + ",anotherBareToken");
        assertEquals(methods, cfg2.methodsPath());
    }

    @Test
    void parseBlankAndNullThrow() {
        assertThrows(IllegalArgumentException.class, () -> ReachabilityAgent.AgentConfig.parse(null));
        assertThrows(IllegalArgumentException.class, () -> ReachabilityAgent.AgentConfig.parse("   "));
        assertThrows(IllegalArgumentException.class, () -> ReachabilityAgent.AgentConfig.parse(""));
    }

    @Test
    void requiresMethodsFile() {
        assertThrows(IllegalArgumentException.class,
                () -> ReachabilityAgent.AgentConfig.parse("report=out.html"));
    }

    @Test
    void missingFileThrows(@TempDir Path dir) {
        assertThrows(IllegalArgumentException.class,
                () -> ReachabilityAgent.AgentConfig.parse(
                        "methods=" + dir.resolve("nope.json")));
    }
}
