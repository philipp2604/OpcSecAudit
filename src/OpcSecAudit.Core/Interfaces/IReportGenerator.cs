using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Interfaces;

/// <summary>
/// Interface for generating audit reports in various formats.
/// </summary>
public interface IReportGenerator
{
    /// <summary>
    /// Generates a report from the audit result and writes it to the specified path.
    /// </summary>
    /// <param name="result">The audit result to report on.</param>
    /// <param name="outputPath">The file path to write the report to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the report has been written.</returns>
    Task GenerateAsync(AuditResult result, string outputPath, CancellationToken cancellationToken);
}
