using Microsoft.Extensions.Logging;
using OpcSecAudit.Core;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Scanner.Checkers;

/// <summary>
/// Checks server certificates on all endpoints for security weaknesses.
/// Covers findings SEC-CERT-001 through SEC-CERT-006.
/// </summary>
public class CertificateChecker(ILogger<CertificateChecker> logger) : ISecurityChecker
{
    private static readonly TimeSpan ExpiryWarningWindow = TimeSpan.FromDays(30);

    /// <inheritdoc />
    public string Category => "Server Certificate";

    /// <inheritdoc />
    public Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken)
    {
        logger.LogInformation("Running certificate checks against {Count} endpoints", context.Endpoints.Count);

        List<Finding> findings = new();

        // Deduplicate certificates by thumbprint.
        var seenThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var endpoint in context.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var cert = endpoint.ServerCertificate;

            if (cert is null)
            {
                logger.LogDebug("Endpoint {Url} has no server certificate — skipping cert checks", endpoint.EndpointUrl);
                continue;
            }

            if (!seenThumbprints.Add(cert.Thumbprint))
            {
                logger.LogDebug("Certificate {Thumbprint} already evaluated — skipping duplicate", cert.Thumbprint[..8]);
                continue;
            }

            logger.LogDebug(
                "Evaluating certificate: Subject={Subject}, Thumbprint={Thumbprint}",
                cert.Subject, cert.Thumbprint[..8]);

            string certSummary = $"Subject: {cert.Subject} | Thumbprint: {cert.Thumbprint[..8]}...";
            DateTime now = DateTime.UtcNow;

            // SEC-CERT-001: Expired certificate
            if (cert.NotAfter < now)
            {
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-001",
                    Category = Category,
                    Severity = Severity.Critical,
                    Title = "Server Certificate Expired",
                    Description = $"{certSummary}\nExpired on: {cert.NotAfter:yyyy-MM-dd} UTC " +
                                  $"({(now - cert.NotAfter).Days} days ago).",
                    Recommendation = "Replace the server certificate immediately. " +
                                     "An expired certificate may cause connection failures and indicates poor certificate management.",
                    CweId = "CWE-298",
                    CweDescription = "Improper Validation of Certificate Expiration"
                });
            }
            else if (cert.NotAfter - now <= ExpiryWarningWindow)
            {
                // SEC-CERT-004: Expiring soon (check before CERT-001 would fire, i.e. not yet expired)
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-004",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Server Certificate Expiring Soon",
                    Description = $"{certSummary}\nExpires on: {cert.NotAfter:yyyy-MM-dd} UTC " +
                                  $"({(cert.NotAfter - now).Days} days remaining).",
                    Recommendation = $"Renew the server certificate before it expires on {cert.NotAfter:yyyy-MM-dd}.",
                    CweId = "CWE-298",
                    CweDescription = "Improper Validation of Certificate Expiration"
                });
            }

            // SEC-CERT-002: Weak key size
            if (cert.KeySizeBits < 2048)
            {
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-002",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Weak Certificate Key Size",
                    Description = $"{certSummary}\nKey size: {cert.KeySizeBits} bits (minimum recommended: 2048 bits).",
                    Recommendation = "Generate a new server certificate with at least 2048-bit RSA key (4096-bit recommended).",
                    CweId = "CWE-326",
                    CweDescription = "Inadequate Encryption Strength"
                });
            }

            // SEC-CERT-003: SHA-1 signature
            if (cert.SignatureAlgorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-003",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "SHA-1 Signature Algorithm",
                    Description = $"{certSummary}\nSignature algorithm: {cert.SignatureAlgorithm}.",
                    Recommendation = "Regenerate the server certificate using SHA-256 or stronger signature algorithm. " +
                                     "SHA-1 is considered broken.",
                    CweId = "CWE-328",
                    CweDescription = "Use of Weak Hash"
                });
            }

            // SEC-CERT-005: Self-signed
            if (cert.IsSelfSigned)
            {
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-005",
                    Category = Category,
                    Severity = Severity.Info,
                    Title = "Self-Signed Server Certificate",
                    Description = $"{certSummary}\nThe certificate is self-signed (Issuer equals Subject).",
                    Recommendation = "Consider using a certificate issued by a Certificate Authority for production environments. " +
                                     "Self-signed certificates do not provide third-party trust validation.",
                    CweId = "CWE-295",
                    CweDescription = "Improper Certificate Validation"
                });
            }

            // SEC-CERT-006: Hostname mismatch
            if (!HostnameMatchesCertificate(context.ResolvedHostname, cert))
            {
                findings.Add(new Finding
                {
                    Id = "SEC-CERT-006",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Certificate Hostname Mismatch",
                    Description = $"{certSummary}\nExpected hostname '{context.ResolvedHostname}' not found in " +
                                  $"Subject CN or Subject Alternative Names ({string.Join(", ", cert.SubjectAltNames)}).",
                    Recommendation = "Regenerate the server certificate with the correct hostname in the Subject " +
                                     "or Subject Alternative Names field.",
                    CweId = "CWE-297",
                    CweDescription = "Improper Validation of Certificate with Host Mismatch"
                });
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="hostname"/> matches the certificate's
    /// Subject CN or any Subject Alternative Name entry.
    /// </summary>
    /// <param name="hostname">The hostname to verify against the certificate.</param>
    /// <param name="cert">The certificate to check.</param>
    private static bool HostnameMatchesCertificate(string hostname, CertificateInfo cert)
    {
        // Check SANs first (preferred)
        foreach (var san in cert.SubjectAltNames)
        {
            if (san.Contains(hostname, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Fall back to Subject CN
        // Subject is a DN like "CN=myserver, O=MyOrg" — extract the CN value
        const string cnPrefix = "CN=";
        var parts = cert.Subject.Split(',', StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            if (part.StartsWith(cnPrefix, StringComparison.OrdinalIgnoreCase))
            {
                string cn = part[cnPrefix.Length..].Trim();
                if (string.Equals(cn, hostname, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
