namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents information about the OPC UA server software.
/// </summary>
public class ServerInfo
{
    /// <summary>
    /// Gets the product name of the server software.
    /// </summary>
    public required string ProductName { get; init; }

    /// <summary>
    /// Gets the software version string.
    /// </summary>
    public required string SoftwareVersion { get; init; }

    /// <summary>
    /// Gets the build number.
    /// </summary>
    public required string BuildNumber { get; init; }

    /// <summary>
    /// Gets the current server state (e.g., "Running").
    /// </summary>
    public required string State { get; init; }
}
