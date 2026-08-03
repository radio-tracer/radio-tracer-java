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
    void resolvePrefersConfiguredThenPropsThenBasedir() {
        assertEquals("explicit", RunLabel.resolve("explicit"));
        assertEquals("trimmed", RunLabel.resolve("  trimmed  "));

        System.setProperty("radio.tracer.label", "from-prop");
        assertEquals("from-prop", RunLabel.resolve(null));
        System.clearProperty("radio.tracer.label");

        System.setProperty("basedir", "/tmp/project/todolist-core/");
        assertEquals("todolist-core", RunLabel.resolve(null));
        // no slash → lastSegment uses whole string
        System.setProperty("basedir", "relative-mod");
        assertEquals("relative-mod", RunLabel.resolve(null));
        // strip leaves empty leaf → fall through to user.dir / pid
        System.setProperty("basedir", "/");
        assertTrue(!RunLabel.resolve(null).isBlank());
    }

    @Test
    void sanitizeForFragmentFilenames() {
        assertEquals("todolist-core", RunLabel.sanitize("todolist-core"));
        assertEquals("my_mod", RunLabel.sanitize("my mod"));
        assertEquals("leaf", RunLabel.sanitize("/abs/path/leaf/"));
        assertEquals("leaf", RunLabel.sanitize("C:\\foo\\leaf"));
        assertEquals("unknown", RunLabel.sanitize(null));
        assertEquals("unknown", RunLabel.sanitize("   "));
        assertEquals("unknown", RunLabel.sanitize("@@@"));
        assertEquals("unknown", RunLabel.sanitize("///"));
        assertEquals(80, RunLabel.sanitize("x".repeat(100)).length());
        assertEquals("unknown", RunLabel.display(null));
        assertEquals("unknown", RunLabel.display("  "));
        assertEquals("ok", RunLabel.display(" ok "));
        assertEquals("a", RunLabel.normalizeKey("A"));
        assertTrue(RunLabel.currentPid() > 0);
    }

    @Test
    void resolveFallsBackWhenBasedirMissing() {
        String prev = System.getProperty("user.dir");
        System.clearProperty("basedir");
        try {
            System.setProperty("user.dir", "");
            assertTrue(RunLabel.resolve(null).startsWith("pid-"));
        } finally {
            if (prev != null) {
                System.setProperty("user.dir", prev);
            }
        }
    }
}
