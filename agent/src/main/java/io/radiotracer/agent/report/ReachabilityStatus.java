package io.radiotracer.agent.report;

/** Runtime observation for a watched method under the executed workload. */
public enum ReachabilityStatus {
    /** Watched method body executed at least once. */
    REACHABLE,
    /** On the watchlist but never observed during this run. */
    NOT_OBSERVED;

    public boolean isReached() {
        return this == REACHABLE;
    }
}
