using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Cli;

/// <summary>
/// Writes an <see cref="AuditResult"/> to the console with optional ANSI color output.
/// Colors are disabled automatically when stdout is redirected.
/// </summary>
public class ConsoleResultWriter
{
    private const string ToolVersion = "1.0.0";

    /// <summary>
    /// Writes the audit result to stdout.
    /// </summary>
    /// <param name="result">The audit result to display.</param>
    /// <param name="verbose">When <see langword="true"/>, prints a detailed endpoint table before findings.</param>
    /// <param name="noColor">When <see langword="true"/>, suppresses colored output regardless of terminal state.</param>
    public void Write(AuditResult result, bool verbose, bool noColor)
    {
        bool useColor = !noColor && !Console.IsOutputRedirected;

        // Header
        Console.WriteLine($"OpcSecAudit v{ToolVersion} — OPC UA Security Auditor");
        Console.WriteLine($"Target:   {result.TargetUrl}");
        Console.WriteLine($"Started:  {result.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Duration: {result.Duration.TotalSeconds:F1}s");
        Console.WriteLine();

        Console.WriteLine($"Discovered {result.DiscoveredEndpoints.Count} endpoint(s).");

        if (verbose && result.DiscoveredEndpoints.Count > 0)
        {
            Console.WriteLine();
            WriteEndpointsTable(result.DiscoveredEndpoints, useColor);
        }

        Console.WriteLine();
        Separator("Findings");

        if (result.Findings.Count == 0)
        {
            Console.WriteLine("  No findings.");
        }
        else
        {
            foreach (var finding in result.Findings.OrderBy(f => f.Id))
            {
                Console.WriteLine();
                WriteFinding(finding, useColor);
            }
        }

        Console.WriteLine();
        Separator("Summary");
        Console.Write($"Critical: ");
        WriteColored($"{result.CriticalCount}", useColor ? ConsoleColor.Red : null);
        Console.Write($" | Warnings: ");
        WriteColored($"{result.WarningCount}", useColor ? ConsoleColor.Yellow : null);
        Console.Write($" | Info: ");
        Console.WriteLine(result.InfoCount);
        Console.Write("Result: ");

        string assessment = result.CriticalCount > 0 ? "FAIL"
            : result.WarningCount > 0 ? "REVIEW"
            : "PASS";
        ConsoleColor? assessmentColor = assessment switch
        {
            "FAIL" => ConsoleColor.Red,
            "REVIEW" => ConsoleColor.Yellow,
            _ => ConsoleColor.Green
        };
        WriteColored(assessment, useColor ? assessmentColor : null);
        Console.WriteLine();
    }

    private static void WriteEndpointsTable(IEnumerable<EndpointInfo> endpoints, bool useColor)
    {
        Console.WriteLine("Endpoints:");
        Console.WriteLine(new string('─', 80));
        Console.WriteLine($"  {"Security Mode",-16} {"Policy",-20} {"Token Types",-30}");
        Console.WriteLine(new string('─', 80));

        foreach (var ep in endpoints)
        {
            bool isNone = string.Equals(ep.SecurityMode, "None", StringComparison.OrdinalIgnoreCase);
            string shortPolicy = ShortPolicyName(ep.SecurityPolicy);
            string tokens = string.Join(", ", ep.UserTokenPolicies.Select(t => t.TokenType));
            string line = $"  {ep.SecurityMode,-16} {shortPolicy,-20} {tokens,-30}";

            if (isNone && useColor)
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }

            Console.WriteLine(line);

            if (isNone && useColor)
            {
                Console.ResetColor();
            }

            Console.WriteLine($"  {ep.EndpointUrl}");
        }

        Console.WriteLine(new string('─', 80));
    }

    private static void WriteFinding(Finding finding, bool useColor)
    {
        ConsoleColor? severityColor = finding.Severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.Warning => ConsoleColor.Yellow,
            Severity.Info => ConsoleColor.Cyan,
            _ => null
        };

        string label = finding.Severity switch
        {
            Severity.Critical => "CRITICAL",
            Severity.Warning => "WARNING",
            _ => "INFO"
        };

        WriteColored($"[{label}]", useColor ? severityColor : null);
        Console.WriteLine($" {finding.Id}: {finding.Title}");

        // Description — indent each line by 2 spaces
        foreach (var line in finding.Description.Split('\n', StringSplitOptions.TrimEntries))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                Console.WriteLine($"  {line}");
            }
        }

        Console.WriteLine($"  \u2192 {finding.Recommendation}");

        if (finding.CweId is not null)
        {
            Console.WriteLine($"  CWE: {finding.CweId}");
        }
    }

    private static void Separator(string title) =>
        Console.WriteLine($"\u2501\u2501\u2501 {title} \u2501\u2501\u2501");

    private static void WriteColored(string text, ConsoleColor? color)
    {
        if (color is not null)
        {
            Console.ForegroundColor = color.Value;
        }

        Console.Write(text);

        if (color is not null)
        {
            Console.ResetColor();
        }
    }

    private static string ShortPolicyName(string policyUri)
    {
        int idx = policyUri.LastIndexOf('#');
        return idx >= 0 ? policyUri[(idx + 1)..] : policyUri;
    }
}
