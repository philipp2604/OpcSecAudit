namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents parsed information about an X.509 certificate.
/// </summary>
public class CertificateInfo
{
    /// <summary>
    /// Gets the certificate subject distinguished name.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Gets the certificate issuer distinguished name.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// Gets the certificate thumbprint (SHA-1 hash, hex-encoded).
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Gets the start of the certificate validity period (UTC).
    /// </summary>
    public required DateTime NotBefore { get; init; }

    /// <summary>
    /// Gets the end of the certificate validity period (UTC).
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Gets the RSA key size in bits.
    /// </summary>
    public required int KeySizeBits { get; init; }

    /// <summary>
    /// Gets the signature algorithm (e.g., "sha256RSA", "sha1RSA").
    /// </summary>
    public required string SignatureAlgorithm { get; init; }

    /// <summary>
    /// Gets a value indicating whether the certificate is self-signed.
    /// </summary>
    public required bool IsSelfSigned { get; init; }

    /// <summary>
    /// Gets the list of Subject Alternative Names.
    /// </summary>
    public required List<string> SubjectAltNames { get; init; }
}
