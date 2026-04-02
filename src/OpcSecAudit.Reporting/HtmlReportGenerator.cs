using System.Net;
using System.Text;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Reporting;

/// <summary>
/// Generates a self-contained HTML security audit report with inline CSS.
/// No external dependencies, JavaScript, or stylesheets are referenced.
/// </summary>
public class HtmlReportGenerator : IReportGenerator
{
    private const string ToolVersion = "1.0.0";

    /// <inheritdoc />
    public async Task GenerateAsync(
        AuditResult result,
        string outputPath,
        CancellationToken cancellationToken)
    {
        string html = BuildHtml(result);
        await File.WriteAllTextAsync(outputPath, html, Encoding.UTF8, cancellationToken)
                  .ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the complete HTML document as a string.
    /// </summary>
    /// <param name="result">The audit result to render.</param>
    private static string BuildHtml(AuditResult result)
    {
        string assessment = result.CriticalCount > 0 ? "FAIL"
            : result.WarningCount > 0 ? "REVIEW"
            : "PASS";
        string assessmentColor = assessment switch
        {
            "FAIL" => "#dc2626",
            "REVIEW" => "#d97706",
            _ => "#16a34a"
        };

        var sb = new StringBuilder();
        AppendDocStart(sb);
        AppendHeader(sb);
        sb.Append("""<div class="container">""");
        AppendSummary(sb, result, assessment, assessmentColor);
        AppendServerInfo(sb, result.ServerInfo);
        AppendEndpointsTable(sb, result.DiscoveredEndpoints);
        AppendFindings(sb, result.Findings);
        AppendFooter(sb);
        sb.Append("</div>");
        AppendDocEnd(sb);
        return sb.ToString();
    }

    private static void AppendDocStart(StringBuilder sb)
    {
        sb.Append("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OPC UA Security Audit Report</title>
            <style>
            *,*::before,*::after{box-sizing:border-box}
            body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;background:#f8fafc;color:#1e293b}
            a{color:#2563eb}
            .container{max-width:1100px;margin:0 auto;padding:24px}
            header{background:#0f172a;color:#f1f5f9;padding:20px 24px;margin-bottom:24px}
            header h1{margin:0;font-size:22px;font-weight:700}
            header p{margin:4px 0 0;font-size:13px;color:#94a3b8}
            .card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin-bottom:20px}
            .card h2{margin:0 0 16px;font-size:16px;font-weight:600;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:10px}
            .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
            .summary-item label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#64748b;margin-bottom:2px}
            .summary-item span{font-size:14px;color:#1e293b}
            .badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:12px;font-weight:600;color:#fff}
            .badge-critical{background:#dc2626}
            .badge-warning{background:#d97706}
            .badge-info{background:#2563eb}
            .assessment{display:inline-block;padding:6px 18px;border-radius:6px;font-size:18px;font-weight:700;color:#fff}
            table{width:100%;border-collapse:collapse;font-size:13px}
            th{background:#f1f5f9;text-align:left;padding:8px 12px;font-weight:600;color:#475569;border-bottom:2px solid #e2e8f0}
            td{padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
            tr:last-child td{border-bottom:none}
            tr:nth-child(even) td{background:#f8fafc}
            tr.none-mode td{background:#fee2e2}
            tr.none-mode:nth-child(even) td{background:#fecaca}
            .finding{border-left:4px solid #e2e8f0;padding:14px 16px;margin-bottom:14px;background:#fff;border-radius:0 6px 6px 0;break-inside:avoid}
            .finding.critical{border-left-color:#dc2626}
            .finding.warning{border-left-color:#d97706}
            .finding.info{border-left-color:#2563eb}
            .finding-title{font-weight:600;font-size:14px;margin:6px 0 8px}
            .finding-desc{white-space:pre-wrap;color:#374151;font-size:13px;margin-bottom:8px}
            .finding-rec{color:#047857;font-size:13px;margin-bottom:6px}
            .finding-cwe{font-size:12px;color:#64748b}
            .section-title{font-size:15px;font-weight:700;color:#0f172a;margin:24px 0 10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
            footer{text-align:center;color:#94a3b8;font-size:12px;margin-top:32px;padding-top:16px;border-top:1px solid #e2e8f0}
            @media(max-width:640px){.summary-grid{grid-template-columns:1fr 1fr}}
            @media print{.finding{break-inside:avoid}.card{break-inside:avoid}}
            </style>
            </head>
            <body>
            """);
    }

    private static void AppendHeader(StringBuilder sb)
    {
        sb.Append($"""
            <header>
              <h1>OPC UA Security Audit Report</h1>
              <p>OpcSecAudit v{H(ToolVersion)}</p>
            </header>
            """);
    }

    private static void AppendSummary(
        StringBuilder sb,
        AuditResult result,
        string assessment,
        string assessmentColor)
    {
        sb.Append($"""
            <div class="card">
              <h2>Summary</h2>
              <div class="summary-grid">
                <div class="summary-item"><label>Target</label><span>{H(result.TargetUrl)}</span></div>
                <div class="summary-item"><label>Timestamp (UTC)</label><span>{result.Timestamp:yyyy-MM-dd HH:mm:ss}</span></div>
                <div class="summary-item"><label>Duration</label><span>{result.Duration.TotalSeconds:F1}s</span></div>
                <div class="summary-item"><label>Endpoints</label><span>{result.DiscoveredEndpoints.Count}</span></div>
              </div>
              <div class="summary-grid">
                <div class="summary-item">
                  <label>Critical</label>
                  <span><span class="badge badge-critical">{result.CriticalCount}</span></span>
                </div>
                <div class="summary-item">
                  <label>Warning</label>
                  <span><span class="badge badge-warning">{result.WarningCount}</span></span>
                </div>
                <div class="summary-item">
                  <label>Info</label>
                  <span><span class="badge badge-info">{result.InfoCount}</span></span>
                </div>
                <div class="summary-item">
                  <label>Assessment</label>
                  <span><span class="assessment" style="background:{assessmentColor}">{H(assessment)}</span></span>
                </div>
              </div>
            </div>
            """);
    }

    private static void AppendServerInfo(StringBuilder sb, ServerInfo? info)
    {
        if (info is null)
        {
            return;
        }

        sb.Append($"""
            <div class="card">
              <h2>Server Information</h2>
              <table>
                <tr><th>Product</th><td>{H(info.ProductName)}</td></tr>
                <tr><th>Version</th><td>{H(info.SoftwareVersion)}</td></tr>
                <tr><th>Build</th><td>{H(info.BuildNumber)}</td></tr>
                <tr><th>State</th><td>{H(info.State)}</td></tr>
              </table>
            </div>
            """);
    }

    private static void AppendEndpointsTable(StringBuilder sb, IEnumerable<EndpointInfo> endpoints)
    {
        sb.Append("""
            <div class="card">
              <h2>Discovered Endpoints</h2>
              <table>
                <thead>
                  <tr>
                    <th>Endpoint URL</th>
                    <th>Security Mode</th>
                    <th>Security Policy</th>
                    <th>User Token Types</th>
                  </tr>
                </thead>
                <tbody>
            """);

        foreach (var ep in endpoints)
        {
            bool isNone = string.Equals(ep.SecurityMode, "None", StringComparison.OrdinalIgnoreCase);
            string rowClass = isNone ? """ class="none-mode" """ : string.Empty;
            string shortPolicy = ShortPolicyName(ep.SecurityPolicy);
            string tokenTypes = string.Join(", ", ep.UserTokenPolicies.Select(t => H(t.TokenType)));

            sb.Append($"""
                    <tr{rowClass}>
                      <td>{H(ep.EndpointUrl)}</td>
                      <td>{H(ep.SecurityMode)}</td>
                      <td>{H(shortPolicy)}</td>
                      <td>{tokenTypes}</td>
                    </tr>
                """);
        }

        sb.Append("""
                </tbody>
              </table>
            </div>
            """);
    }

    private static void AppendFindings(StringBuilder sb, IEnumerable<Finding> findings)
    {
        var grouped = findings
            .GroupBy(f => f.Category)
            .OrderBy(g => g.Key);

        foreach (var group in grouped)
        {
            sb.Append($"""<div class="section-title">{H(group.Key)}</div>""");

            foreach (var finding in group.OrderBy(f => f.Id))
            {
                string cssClass = finding.Severity switch
                {
                    Severity.Critical => "critical",
                    Severity.Warning => "warning",
                    _ => "info"
                };
                string badgeClass = finding.Severity switch
                {
                    Severity.Critical => "badge-critical",
                    Severity.Warning => "badge-warning",
                    _ => "badge-info"
                };

                sb.Append($"""
                    <div class="finding {cssClass}">
                      <div><span class="badge {badgeClass}">{H(finding.Severity.ToString().ToUpperInvariant())}</span></div>
                      <div class="finding-title">{H(finding.Id)}: {H(finding.Title)}</div>
                      <div class="finding-desc">{H(finding.Description)}</div>
                      <div class="finding-rec">&#x2192; {H(finding.Recommendation)}</div>
                    """);

                if (finding.CweId is not null)
                {
                    string cweNumber = finding.CweId.Replace("CWE-", string.Empty, StringComparison.OrdinalIgnoreCase);
                    sb.Append($"""
                          <div class="finding-cwe"><a href="https://cwe.mitre.org/data/definitions/{H(cweNumber)}.html" target="_blank">{H(finding.CweId)}</a>{(finding.CweDescription is not null ? $" — {H(finding.CweDescription)}" : string.Empty)}</div>
                        """);
                }

                sb.Append("</div>");
            }
        }
    }

    private static void AppendFooter(StringBuilder sb)
    {
        sb.Append($"""
            <footer>Generated by OpcSecAudit v{H(ToolVersion)} on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</footer>
            """);
    }

    private static void AppendDocEnd(StringBuilder sb)
    {
        sb.Append("""
            </body>
            </html>
            """);
    }

    /// <summary>
    /// HTML-encodes a string to prevent injection in the report.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    private static string H(string? value) =>
        WebUtility.HtmlEncode(value ?? string.Empty);

    /// <summary>
    /// Extracts the short policy name after the <c>#</c> in a security policy URI.
    /// Returns the full URI if no <c>#</c> is present.
    /// </summary>
    /// <param name="policyUri">The full security policy URI.</param>
    private static string ShortPolicyName(string policyUri)
    {
        int idx = policyUri.LastIndexOf('#');
        return idx >= 0 ? policyUri[(idx + 1)..] : policyUri;
    }
}
