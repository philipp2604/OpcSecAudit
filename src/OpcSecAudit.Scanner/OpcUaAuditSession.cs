using Opc.Ua.Client;
using OpcSecAudit.Scanner.Interfaces;

namespace OpcSecAudit.Scanner;

/// <summary>
/// Wraps a live OPC UA <see cref="ISession"/> and exposes only the narrow interface
/// needed by audit checkers.
/// </summary>
internal sealed class OpcUaAuditSession(ISession inner) : IAuditSession
{
    /// <inheritdoc />
    public async Task<object?> ReadNodeValueAsync(uint numericNodeId, CancellationToken cancellationToken)
    {
        var nodeId = new Opc.Ua.NodeId(numericNodeId);
        var dataValue = await inner.ReadValueAsync(nodeId, cancellationToken).ConfigureAwait(false);
        return dataValue?.Value;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        try
        {
            await inner.CloseAsync().ConfigureAwait(false);
        }
        catch
        {
            // Best-effort close — ignore errors during disposal.
        }

        inner.Dispose();
    }
}
