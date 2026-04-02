using Microsoft.Extensions.Logging;
using OpcSecAudit.Core;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Scanner.Checkers;

/// <summary>
/// Checks endpoint security modes and security policy URIs for misconfigurations.
/// Covers findings SEC-EP-001 through SEC-EP-004.
/// </summary>
public class EndpointSecurityChecker(ILogger<EndpointSecurityChecker> logger) : ISecurityChecker
{
    private const string NonePolicy = "http://opcfoundation.org/UA/SecurityPolicy#None";
    private const string Basic128Rsa15Segment = "Basic128Rsa15";
    private const string Basic256Segment = "Basic256";
    private const string Basic256Sha256Segment = "Basic256Sha256";

    /// <inheritdoc />
    public string Category => "Endpoint Security";

    /// <inheritdoc />
    public Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken)
    {
        logger.LogInformation("Running endpoint security checks against {Count} endpoints", context.Endpoints.Count);

        List<Finding> findings = new();
        bool hasNoneEndpoint = false;
        bool hasBasic128 = false;
        bool hasBasic256Legacy = false;

        foreach (var endpoint in context.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool isNoneMode = string.Equals(endpoint.SecurityMode, "None", StringComparison.OrdinalIgnoreCase);
            bool isNonePolicy = string.Equals(endpoint.SecurityPolicy, NonePolicy, StringComparison.OrdinalIgnoreCase);

            // SEC-EP-001: Unencrypted endpoint
            if (isNoneMode && isNonePolicy && !hasNoneEndpoint)
            {
                hasNoneEndpoint = true;
                logger.LogDebug("SEC-EP-001 triggered by endpoint {Url}", endpoint.EndpointUrl);
                findings.Add(new Finding
                {
                    Id = "SEC-EP-001",
                    Category = Category,
                    Severity = Severity.Critical,
                    Title = "Unencrypted Endpoint Available",
                    Description = $"Endpoint '{endpoint.EndpointUrl}' is configured with SecurityMode=None " +
                                  $"and SecurityPolicy=None. All data is transmitted without encryption or integrity protection.",
                    Recommendation = "Disable SecurityMode None in server configuration. " +
                                     "All communication should use Sign or SignAndEncrypt.",
                    CweId = "CWE-319",
                    CweDescription = "Cleartext Transmission of Sensitive Information"
                });
            }

            // SEC-EP-002: Deprecated Basic128Rsa15
            if (endpoint.SecurityPolicy.Contains(Basic128Rsa15Segment, StringComparison.OrdinalIgnoreCase) && !hasBasic128)
            {
                hasBasic128 = true;
                logger.LogDebug("SEC-EP-002 triggered by endpoint {Url}", endpoint.EndpointUrl);
                findings.Add(new Finding
                {
                    Id = "SEC-EP-002",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Deprecated Security Policy Basic128Rsa15",
                    Description = $"Endpoint '{endpoint.EndpointUrl}' uses security policy Basic128Rsa15 " +
                                  $"(URI: {endpoint.SecurityPolicy}), which relies on deprecated 128-bit RSA key exchange.",
                    Recommendation = "Remove Basic128Rsa15 from server configuration. " +
                                     "Use Aes128_Sha256_RsaOaep or Aes256_Sha256_RsaPss.",
                    CweId = "CWE-327",
                    CweDescription = "Use of a Broken or Risky Cryptographic Algorithm"
                });
            }

            // SEC-EP-003: Deprecated Basic256 (but not Basic256Sha256)
            bool isBasic256Legacy = endpoint.SecurityPolicy.Contains(Basic256Segment, StringComparison.OrdinalIgnoreCase)
                                    && !endpoint.SecurityPolicy.Contains(Basic256Sha256Segment, StringComparison.OrdinalIgnoreCase);
            if (isBasic256Legacy && !hasBasic256Legacy)
            {
                hasBasic256Legacy = true;
                logger.LogDebug("SEC-EP-003 triggered by endpoint {Url}", endpoint.EndpointUrl);
                findings.Add(new Finding
                {
                    Id = "SEC-EP-003",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Deprecated Security Policy Basic256",
                    Description = $"Endpoint '{endpoint.EndpointUrl}' uses security policy Basic256 " +
                                  $"(URI: {endpoint.SecurityPolicy}), which uses a deprecated SHA-1-based cipher suite.",
                    Recommendation = "Remove Basic256 from server configuration. " +
                                     "Use Basic256Sha256 or newer policies.",
                    CweId = "CWE-327",
                    CweDescription = "Use of a Broken or Risky Cryptographic Algorithm"
                });
            }
        }

        // SEC-EP-004: Positive confirmation — only when no weak findings were raised
        if (!hasNoneEndpoint && !hasBasic128 && !hasBasic256Legacy)
        {
            logger.LogDebug("SEC-EP-004: all endpoints use approved security policies");
            findings.Add(new Finding
            {
                Id = "SEC-EP-004",
                Category = Category,
                Severity = Severity.Info,
                Title = "Only Secure Policies Configured",
                Description = "All discovered endpoints use approved security policies " +
                              "(Basic256Sha256, Aes128_Sha256_RsaOaep, or Aes256_Sha256_RsaPss). " +
                              "No deprecated or unencrypted policies were found.",
                Recommendation = "No action required. Server is correctly configured with modern security policies."
            });
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }
}
