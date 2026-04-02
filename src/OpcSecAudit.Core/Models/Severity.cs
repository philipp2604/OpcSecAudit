namespace OpcSecAudit.Core.Models;

/// <summary>
/// Severity levels for security findings.
/// </summary>
public enum Severity
{
    /// <summary>
    /// Informational finding, no immediate risk.
    /// </summary>
    Info,

    /// <summary>
    /// Warning — a potential security weakness that should be addressed.
    /// </summary>
    Warning,

    /// <summary>
    /// Critical — a severe security issue requiring immediate attention.
    /// </summary>
    Critical
}
