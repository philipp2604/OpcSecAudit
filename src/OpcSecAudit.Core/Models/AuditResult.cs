namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents the complete result of a security audit against an OPC UA server.
/// </summary>
public class AuditResult
{
    /// <summary>
    /// Gets the OPC UA endpoint URL that was audited.
    /// </summary>
    public required string TargetUrl { get; init; }

    /// <summary>
    /// Gets the UTC timestamp when the audit was started.
    /// </summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>
    /// Gets the total duration of the audit.
    /// </summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>
    /// Gets the list of discovered endpoints on the target server.
    /// </summary>
    public required List<EndpointInfo> DiscoveredEndpoints { get; init; }

    /// <summary>
    /// Gets the server information, if it could be retrieved. Null if the server did not respond.
    /// </summary>
    public ServerInfo? ServerInfo { get; init; }

    /// <summary>
    /// Gets the list of all findings from the audit.
    /// </summary>
    public required List<Finding> Findings { get; init; }

    /// <summary>
    /// Gets the number of critical findings.
    /// </summary>
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);

    /// <summary>
    /// Gets the number of warning findings.
    /// </summary>
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);

    /// <summary>
    /// Gets the number of informational findings.
    /// </summary>
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
}
