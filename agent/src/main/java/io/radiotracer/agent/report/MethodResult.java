package io.radiotracer.agent.report;

import io.radiotracer.agent.Watchlist;

/** One row in the reachability report table. */
public record MethodResult(
        Watchlist.VulnerableMethod method,
        ReachabilityStatus status,
        long hitCount
) {
    public String cve() {
        String c = method.cve();
        return c == null ? "" : c;
    }

    public String library() {
        String pkg = method.packageCoord();
        if (pkg == null || pkg.isEmpty()) {
            return "?";
        }
        String ver = method.installedVersion();
        if (ver == null || ver.isEmpty()) {
            return pkg;
        }
        return pkg + "@" + ver;
    }

    public String upgradeTo() {
        String u = method.upgradeTo();
        return u == null || u.isEmpty() ? "—" : u;
    }
}
