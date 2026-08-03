package io.radiotracer.agent.report;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunLabelTest {

    @AfterEach
    void clearProps() {
        System.clearProperty("radio.tracer.label");
        System.clearProperty("radio.tracer.runId");
        System.clearProperty("radio.tracer.module");
        System.clearProperty("basedir");
    }

    @Test
    void resolvePrefersConfigured() {
        assertEquals("explicit", RunLabel.resolve("explicit"));
        assertEquals("trimmed", RunLabel.resolve("  trimmed  "));
    }

    @Test
    void resolveUsesSystemPropertyThenBasedir() {
        System.setProperty("radio.tracer.label", "from-prop");
        assertEquals("from-prop", RunLabel.resolve(null));
        System.clearProperty("radio.tracer.label");
        System.setProperty("radio.tracer.runId", "from-runid");
        assertEquals("from-runid", RunLabel.resolve("  "));
        System.clearProperty("radio.tracer.runId");
        System.setProperty("basedir", "/tmp/project/todolist-core");
        assertEquals("todolist-core", RunLabel.resolve(null));
        System.clearProperty("basedir");
        System.setProperty("radio.tracer.module", "from-module");
        assertEquals("from-module", RunLabel.resolve(null));
    }

    @Test
    void sanitizeDotAndOnlySpecialChars() {
        assertEquals("unknown", RunLabel.sanitize("."));
        assertEquals("unknown", RunLabel.sanitize(".."));
        assertEquals("unknown", RunLabel.sanitize("@@@"));
        assertEquals("unknown", RunLabel.sanitize("///"));
        assertEquals("leaf", RunLabel.sanitize("C:\\foo\\leaf"));
        assertEquals("leaf", RunLabel.sanitize("/abs/path/leaf/"));
    }

    @Test
    void sanitizeForFilename() {
        assertEquals("todolist-core", RunLabel.sanitize("todolist-core"));
        assertEquals("my_mod", RunLabel.sanitize("my mod"));
        assertEquals("leaf", RunLabel.sanitize("/abs/path/leaf"));
        assertEquals("unknown", RunLabel.sanitize("   "));
        assertEquals("unknown", RunLabel.sanitize(".."));
        assertEquals("unknown", RunLabel.sanitize(null));
        String longName = "x".repeat(100);
        assertEquals(80, RunLabel.sanitize(longName).length());
        assertEquals("unknown", RunLabel.display(null));
        assertEquals("unknown", RunLabel.display("  "));
        assertEquals("ok", RunLabel.display(" ok "));
        assertEquals("a", RunLabel.normalizeKey("A"));
        assertTrue(RunLabel.currentPid() > 0);
    }

    @Test
    void resolveFallsBackToPidWhenNothingElse() {
        String prev = System.getProperty("user.dir");
        System.clearProperty("basedir");
        try {
            System.setProperty("user.dir", "");
            String label = RunLabel.resolve(null);
            assertTrue(label.startsWith("pid-"), label);
        } finally {
            if (prev != null) {
                System.setProperty("user.dir", prev);
            }
        }
    }

    @Test
    void lastSegmentViaResolveBasedirTrailingSlash() {
        System.setProperty("basedir", "/tmp/project/mod/");
        assertEquals("mod", RunLabel.resolve(null));
        System.setProperty("basedir", "relative-mod");
        assertEquals("relative-mod", RunLabel.resolve(null));
        System.setProperty("basedir", "///");
        // only slashes → empty leaf → fall through to user.dir or pid
        String label = RunLabel.resolve(null);
        assertTrue(!label.isBlank());
    }
}
