namespace OpcSecAudit.Scanner.Interfaces;

/// <summary>
/// Factory that creates anonymous OPC UA sessions for audit checks.
/// Abstracted to allow mocking in unit tests without a real OPC UA server.
/// </summary>
public interface IAuditSessionFactory
{
    /// <summary>
    /// Attempts to create an anonymous OPC UA session to the most permissive endpoint
    /// available at the given target URL.
    /// </summary>
    /// <param name="targetUrl">The OPC UA server URL (e.g., "opc.tcp://192.168.1.50:4840").</param>
    /// <param name="timeoutSeconds">Connection timeout in seconds.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An <see cref="IAuditSession"/> if a session was established; <see langword="null"/> if
    /// the server refused the connection or no anonymous endpoint was found.
    /// </returns>
    Task<IAuditSession?> TryCreateAnonymousSessionAsync(
        string targetUrl,
        int timeoutSeconds,
        CancellationToken cancellationToken);
}
