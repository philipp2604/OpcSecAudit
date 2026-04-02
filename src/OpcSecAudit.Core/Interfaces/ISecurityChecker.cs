using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Interfaces;

/// <summary>
/// Interface for a security checker that evaluates one category of security findings.
/// </summary>
public interface ISecurityChecker
{
    /// <summary>
    /// Gets the human-readable category name (e.g., "Endpoint Security").
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Runs the security checks and returns findings.
    /// </summary>
    /// <param name="context">The audit context containing discovered endpoint data.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A list of findings. May be empty if no issues were found.</returns>
    Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken);
}
