package io.radiotracer.agent;

import io.radiotracer.agent.report.HitReporter;
import io.radiotracer.agent.report.ReachabilityStatus;
import io.radiotracer.agent.support.TestAccess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VulnerableMethodAdviceTest {

    @BeforeEach
    @AfterEach
    void reset() {
        TestAccess.resetHitReporter();
        TestAccess.clearDispatcherRegistry();
    }

    @Test
    void onEnterDispatchesToReporter() {
        Watchlist.VulnerableMethod m = new Watchlist.VulnerableMethod(
                "CVE-A", "g:a", "1", "2", "pkg.Cls", "run", "()V", "t", "high");
        InstrumentedMethodDispatcher.registerAll(List.of(m));
        HitReporter.configure(null, List.of(m));

        VulnerableMethodAdvice.onEnter("pkg.Cls", "run", "()V");

        assertEquals(ReachabilityStatus.REACHABLE, HitReporter.buildResults().getFirst().status());
        assertEquals(1, HitReporter.buildResults().getFirst().hitCount());
    }
}
