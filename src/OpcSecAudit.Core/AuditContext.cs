using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core;

/// <summary>
/// Shared context passed to all security checkers during an audit.
/// Contains pre-parsed, SDK-independent data derived from the OPC UA endpoint discovery.
/// </summary>
public class AuditContext
{
    /// <summary>
    /// Gets the target OPC UA server URL.
    /// </summary>
    public required string TargetUrl { get; init; }

    /// <summary>
    /// Gets the resolved hostname of the target URL.
    /// </summary>
    public required string ResolvedHostname { get; init; }

    /// <summary>
    /// Gets the port of the target URL.
    /// </summary>
    public required int Port { get; init; }

    /// <summary>
    /// Gets the discovered endpoints as parsed, SDK-independent <see cref="EndpointInfo"/> objects.
    /// </summary>
    public required IReadOnlyList<EndpointInfo> Endpoints { get; init; }

    /// <summary>
    /// Gets server software information if it could be read. Null if unavailable.
    /// </summary>
    public ServerInfo? ServerApplication { get; init; }
}
