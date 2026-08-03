package io.radiotracer.agent;

import io.radiotracer.agent.report.HitReporter;
import io.radiotracer.agent.report.MethodResult;
import io.radiotracer.agent.report.ReachabilityStatus;
import io.radiotracer.agent.support.TestAccess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InstrumentedMethodDispatcherTest {

    @BeforeEach
    @AfterEach
    void reset() {
        TestAccess.resetHitReporter();
        TestAccess.clearDispatcherRegistry();
    }

    @Test
    void dispatchWithExactDescriptorUsesCveMetadata() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-X", "g:a", "1", "2", "c.A", "foo", "()V", "src", "high",
                "", null, "");
        InstrumentedMethodDispatcher.registerAll(List.of(m));
        HitReporter.configure(null, List.of(m));

        InstrumentedMethodDispatcher.dispatch("c.A", "foo", "()V");

        List<MethodResult> results = HitReporter.buildResults();
        assertEquals(1, results.size());
        assertEquals(ReachabilityStatus.REACHABLE, results.get(0).status());
        assertEquals("CVE-X", results.get(0).cve());
    }

    @Test
    void dispatchFallsBackToNameOnlyWhenDescriptorMisses() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-Y", "g:a", "1", "2", "c.B", "bar", null, "src", "med",
                "", null, "");
        InstrumentedMethodDispatcher.registerAll(List.of(m));
        HitReporter.configure(null, List.of(m));

        InstrumentedMethodDispatcher.dispatch("c.B", "bar", "(I)V");

        assertEquals(1, HitReporter.buildResults().get(0).hitCount());
    }

    @Test
    void dispatchUnknownMethodStillRecordsHitWithoutCve() {
        HitReporter.configure(null, List.of());
        InstrumentedMethodDispatcher.dispatch("c.Unknown", "x", null);
        InstrumentedMethodDispatcher.dispatch("c.Unknown", "y", "()V");
        assertEquals(0, HitReporter.buildResults().size());
    }

    @Test
    void registerWithoutDescriptorOnlyIndexesName() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-Z", "g:a", "", "", "c.C", "z", null, "", "",
                "", null, "");
        InstrumentedMethodDispatcher.registerAll(List.of(m));
        HitReporter.configure(null, List.of(m));
        InstrumentedMethodDispatcher.dispatch("c.C", "z", null);
        assertEquals(ReachabilityStatus.REACHABLE, HitReporter.buildResults().get(0).status());
    }
}
