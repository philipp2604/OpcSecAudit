namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents a single security finding from an audit check.
/// </summary>
public class Finding
{
    /// <summary>
    /// Gets the unique identifier of the finding (e.g., "SEC-EP-001").
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Gets the category this finding belongs to (e.g., "Endpoint Security").
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Gets the severity level of the finding.
    /// </summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// Gets the short title of the finding.
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// Gets the detailed description including concrete values from the audit.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Gets the recommended remediation action.
    /// </summary>
    public required string Recommendation { get; init; }

    /// <summary>
    /// Gets the CWE identifier, if applicable (e.g., "CWE-319"). Null if no CWE mapping exists.
    /// </summary>
    public string? CweId { get; init; }

    /// <summary>
    /// Gets the CWE description, if applicable. Null if no CWE mapping exists.
    /// </summary>
    public string? CweDescription { get; init; }
}
