namespace OpcSecAudit.Scanner.Interfaces;

/// <summary>
/// Represents a live OPC UA session used for reading server address-space values during an audit.
/// Disposing the session closes the underlying OPC UA connection.
/// </summary>
public interface IAuditSession : IAsyncDisposable
{
    /// <summary>
    /// Reads the value of a single node identified by its numeric node ID.
    /// </summary>
    /// <param name="numericNodeId">The numeric node ID (e.g., 2994 for Server_Auditing).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The node value, or <see langword="null"/> if the node could not be read.</returns>
    Task<object?> ReadNodeValueAsync(uint numericNodeId, CancellationToken cancellationToken);
}
