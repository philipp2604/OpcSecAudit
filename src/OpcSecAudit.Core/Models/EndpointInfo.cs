namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents a discovered OPC UA endpoint and its security configuration.
/// </summary>
public class EndpointInfo
{
    /// <summary>
    /// Gets the endpoint URL.
    /// </summary>
    public required string EndpointUrl { get; init; }

    /// <summary>
    /// Gets the message security mode (None, Sign, SignAndEncrypt).
    /// </summary>
    public required string SecurityMode { get; init; }

    /// <summary>
    /// Gets the security policy URI.
    /// </summary>
    public required string SecurityPolicy { get; init; }

    /// <summary>
    /// Gets the transport profile URI.
    /// </summary>
    public required string TransportProfile { get; init; }

    /// <summary>
    /// Gets the list of accepted user identity token types.
    /// </summary>
    public required List<UserTokenInfo> UserTokenPolicies { get; init; }

    /// <summary>
    /// Gets the server certificate information for this endpoint. Null if no certificate is present.
    /// </summary>
    public CertificateInfo? ServerCertificate { get; init; }
}
