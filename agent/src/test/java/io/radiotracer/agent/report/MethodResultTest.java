package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MethodResultTest {

    @Test
    void libraryFormatsPackageAndVersion() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "C", "g:a", "1.2.3", "9", "c.A", "m", null, "s", "high");
        MethodResult r = new MethodResult(m, ReachabilityStatus.REACHABLE, 1);
        assertEquals("g:a@1.2.3", r.library());
        assertEquals("9", r.upgradeTo());
        assertEquals("C", r.cve());
    }

    @Test
    void libraryWithoutVersionAndEmptyPackage() {
        Watchlist.VulnerableMethod noVer = new Watchlist.VulnerableMethod(
                "C", "g:a", "", "2", "c.A", "m", null, "", "");
        assertEquals("g:a", new MethodResult(noVer, ReachabilityStatus.NOT_OBSERVED, 0).library());

        Watchlist.VulnerableMethod emptyPkg = new Watchlist.VulnerableMethod(
                "C", "", "1", "", "c.A", "m", null, "", "");
        assertEquals("?", new MethodResult(emptyPkg, ReachabilityStatus.NOT_OBSERVED, 0).library());

        Watchlist.VulnerableMethod nulls = new Watchlist.VulnerableMethod(
                null, null, null, null, "c.A", "m", null, null, null);
        MethodResult r = new MethodResult(nulls, ReachabilityStatus.REACHABLE, 1);
        assertEquals("?", r.library());
        assertEquals("", r.cve());
        assertEquals("—", r.upgradeTo());

        // non-null package + null version → return package only (null branch of ver check)
        Watchlist.VulnerableMethod nullVer = new Watchlist.VulnerableMethod(
                "C", "g:a", null, "9", "c.A", "m", null, "", "");
        assertEquals("g:a", new MethodResult(nullVer, ReachabilityStatus.REACHABLE, 1).library());
    }

    @Test
    void upgradeToDashWhenEmpty() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "C", "g:a", "1", "", "c.A", "m", null, "", "");
        assertEquals("—", new MethodResult(m, ReachabilityStatus.REACHABLE, 1).upgradeTo());
    }

    @Test
    void statusHelpers() {
        assertTrue(ReachabilityStatus.REACHABLE.isReached());
        assertFalse(ReachabilityStatus.NOT_OBSERVED.isReached());
    }
}
