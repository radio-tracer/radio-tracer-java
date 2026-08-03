package io.radiotracer.agent.report;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Builds a self-contained HTML reachability report. */
public final class HtmlReportWriter {

    private static final DateTimeFormatter LOCAL_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private HtmlReportWriter() {}

    /**
     * @param reachedRows only REACHABLE rows (printed in the table)
     * @param watchedTotal full watchlist size
     * @param notObservedCount watched methods never hit (summary only, not listed)
     */
    public static String render(
            List<MethodResult> reachedRows,
            int watchedTotal,
            long notObservedCount,
            Instant generatedAt,
            long totalHits
    ) {
        int reachable = reachedRows.size();
        StringBuilder rows = new StringBuilder();
        for (MethodResult r : reachedRows) {
            rows.append("<tr class=\"reachable\">")
                    .append("<td>").append(esc(r.cve())).append("</td>")
                    .append("<td>").append(esc(emptyAsDash(r.severity()))).append("</td>")
                    .append("<td class=\"num\">").append(esc(emptyAsDash(r.cvssScore()))).append("</td>")
                    .append("<td>").append(esc(r.library())).append("</td>")
                    .append("<td>").append(esc(r.upgradeTo())).append("</td>")
                    .append("<td><code>").append(esc(r.method().displayMethod())).append("</code></td>")
                    .append("<td class=\"status\">").append(r.status().name()).append("</td>")
                    .append("<td class=\"num\">").append(r.hitCount()).append("</td>")
                    .append("<td>").append(esc(emptyAsDash(r.method().confidence()))).append("</td>")
                    .append("<td>").append(esc(emptyAsDash(r.method().source()))).append("</td>")
                    .append("</tr>\n");
        }
        if (reachedRows.isEmpty()) {
            rows.append("<tr><td colspan=\"10\">No reachable vulnerable methods observed under this run.</td></tr>\n");
        }

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="utf-8"/>
                  <meta name="viewport" content="width=device-width, initial-scale=1"/>
                  <title>Dynamic Reachability Report</title>
                  <style>
                    :root { font-family: ui-sans-serif, system-ui, sans-serif; color: #0f172a; }
                    body { margin: 2rem; background: #f8fafc; }
                    h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
                    .meta { color: #64748b; margin-bottom: 1.5rem; font-size: 0.9rem; }
                    .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
                    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
                            padding: 0.75rem 1rem; min-width: 8rem; }
                    .card .n { font-size: 1.4rem; font-weight: 700; }
                    .card.r .n { color: #b91c1c; }
                    .card.nobs .n { color: #0369a1; }
                    table { width: 100%%; border-collapse: collapse; background: #fff;
                            border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
                    th, td { text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #e2e8f0;
                             font-size: 0.9rem; vertical-align: top; }
                    th { background: #f1f5f9; font-weight: 600; }
                    tr.reachable { background: #fef2f2; }
                    td.status { font-weight: 600; white-space: nowrap; color: #b91c1c; }
                    td.num { text-align: right; font-variant-numeric: tabular-nums; }
                    code { font-size: 0.8rem; word-break: break-all; }
                    .notes { margin-top: 1.25rem; color: #64748b; font-size: 0.85rem;
                             max-width: 56rem; line-height: 1.5; }
                    .notes p { margin: 0 0 0.65rem; }
                    .notes p:last-child { margin-bottom: 0; }
                  </style>
                </head>
                <body>
                  <h1>Dynamic Reachability Report</h1>
                  <p class="meta">Generated %s · total method invocations observed: %d</p>
                  <div class="cards">
                    <div class="card"><div class="n">%d</div>Watched methods</div>
                    <div class="card r"><div class="n">%d</div>REACHABLE (listed)</div>
                    <div class="card nobs"><div class="n">%d</div>NOT_OBSERVED (hidden)</div>
                  </div>
                  <table>
                    <thead>
                      <tr>
                        <th>CVE</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Vulnerable library</th>
                        <th>Upgrade to</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Hits</th>
                        <th>Confidence</th>
                        <th>Source</th>
                      </tr>
                    </thead>
                    <tbody>
                %s    </tbody>
                  </table>
                  <div class="notes">
                    <p>
                      The table lists only <strong>REACHABLE</strong> methods (executed under this workload).
                      The <strong>NOT_OBSERVED</strong> count is summary-only and does not mean the issue is safe.
                    </p>
                    <p>
                      <strong>Severity</strong> and <strong>CVSS</strong> come from the SCA scanner (via the watchlist)
                      and describe advisory risk — they are not proof of exploitability at runtime.
                    </p>
                    <p>
                      <strong>Confidence</strong> is the strength of the CVE→method mapping from the watchlist
                      (for example high = clear fix-commit match, medium = advisory inference, low = weak or speculative).
                      It is not severity and not a measure of exploitability.
                    </p>
                  </div>
                </body>
                </html>
                """.formatted(
                esc(formatGeneratedAt(generatedAt)),
                totalHits,
                watchedTotal,
                reachable,
                notObservedCount,
                rows
        );
    }

    public static String consoleTable(List<MethodResult> results) {
        String[] headers = {
                "CVE", "Severity", "CVSS", "Vulnerable library", "Upgrade to", "Status", "Hits", "Method"
        };
        List<String[]> tableRows = results.stream()
                .map(r -> new String[]{
                        emptyAsDash(r.cve()),
                        emptyAsDash(r.severity()),
                        emptyAsDash(r.cvssScore()),
                        r.library(),
                        r.upgradeTo(),
                        r.status().name(),
                        Long.toString(r.hitCount()),
                        r.method().displayMethod()
                })
                .toList();

        int[] widths = new int[headers.length];
        for (int i = 0; i < headers.length; i++) {
            widths[i] = headers[i].length();
        }
        for (String[] row : tableRows) {
            for (int i = 0; i < row.length; i++) {
                widths[i] = Math.max(widths[i], row[i].length());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append(formatRow(headers, widths)).append('\n');
        sb.append(separator(widths)).append('\n');
        for (String[] row : tableRows) {
            sb.append(formatRow(row, widths)).append('\n');
        }
        return sb.toString();
    }

    private static String formatGeneratedAt(Instant instant) {
        ZoneId zone = ZoneId.systemDefault();
        ZonedDateTime zdt = instant.atZone(zone);
        String offset = zdt.getOffset().getId();
        if ("Z".equals(offset)) {
            offset = "+00:00";
        }
        String shortName = zdt.format(DateTimeFormatter.ofPattern("z"));
        return LOCAL_TIME.format(zdt)
                + " "
                + zone.getId()
                + " ("
                + shortName
                + ", UTC"
                + offset
                + ")";
    }

    private static String formatRow(String[] cols, int[] widths) {
        // Right-align numeric columns: CVSS (2) and Hits (6)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cols.length; i++) {
            if (i > 0) {
                sb.append(" | ");
            }
            if (i == 2 || i == 6) {
                sb.append(String.format("%" + widths[i] + "s", cols[i]));
            } else {
                sb.append(String.format("%-" + widths[i] + "s", cols[i]));
            }
        }
        return sb.toString();
    }

    private static String separator(int[] widths) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < widths.length; i++) {
            if (i > 0) {
                sb.append("-+-");
            }
            sb.append("-".repeat(widths[i]));
        }
        return sb.toString();
    }

    private static String emptyAsDash(String s) {
        return s == null || s.isEmpty() ? "—" : s;
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
