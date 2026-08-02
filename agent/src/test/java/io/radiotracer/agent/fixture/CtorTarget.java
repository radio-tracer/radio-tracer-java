package io.radiotracer.agent.fixture;

/**
 * Fixture with multiple constructors so {@code methodName: "<init>"} can instrument all of them.
 * First referenced in tests only after the agent is installed.
 * <p>
 * Bodies are intentionally minimal — we only need constructors to execute so the agent probe fires.
 */
public final class CtorTarget {

    public CtorTarget() {}

    @SuppressWarnings("unused") // overload signature only
    public CtorTarget(int value) {}

    @SuppressWarnings("unused") // overload signature only
    public CtorTarget(String label) {}
}
