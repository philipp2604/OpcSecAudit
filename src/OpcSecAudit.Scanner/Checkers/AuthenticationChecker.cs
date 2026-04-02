using Microsoft.Extensions.Logging;
using OpcSecAudit.Core;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Scanner.Checkers;

/// <summary>
/// Checks authentication policies on all endpoints for misconfigurations.
/// Covers findings SEC-AUTH-001 through SEC-AUTH-004.
/// </summary>
public class AuthenticationChecker(ILogger<AuthenticationChecker> logger) : ISecurityChecker
{
    /// <inheritdoc />
    public string Category => "Authentication";

    /// <inheritdoc />
    public Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken)
    {
        logger.LogInformation("Running authentication checks against {Count} endpoints", context.Endpoints.Count);

        List<Finding> findings = new();

        // Collect affected endpoint URLs per condition to group into single findings.
        List<string> auth001Endpoints = new();
        List<string> auth002Endpoints = new();
        List<string> auth003Endpoints = new();
        bool anyCertificateToken = false;

        foreach (var endpoint in context.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();

            bool isNoneMode = string.Equals(endpoint.SecurityMode, "None", StringComparison.OrdinalIgnoreCase);

            foreach (var token in endpoint.UserTokenPolicies)
            {
                bool isAnonymous = string.Equals(token.TokenType, "Anonymous", StringComparison.OrdinalIgnoreCase);
                bool isUserName = string.Equals(token.TokenType, "UserName", StringComparison.OrdinalIgnoreCase);
                bool isCertificate = string.Equals(token.TokenType, "Certificate", StringComparison.OrdinalIgnoreCase);

                if (isCertificate)
                {
                    anyCertificateToken = true;
                }

                // SEC-AUTH-001: Anonymous on unencrypted endpoint
                if (isAnonymous && isNoneMode && !auth001Endpoints.Contains(endpoint.EndpointUrl))
                {
                    auth001Endpoints.Add(endpoint.EndpointUrl);
                }

                // SEC-AUTH-002: Anonymous on encrypted endpoint
                if (isAnonymous && !isNoneMode && !auth002Endpoints.Contains(endpoint.EndpointUrl))
                {
                    auth002Endpoints.Add(endpoint.EndpointUrl);
                }

                // SEC-AUTH-003: UserName token on unencrypted endpoint with no token-level policy
                bool noTokenPolicy = string.IsNullOrEmpty(token.SecurityPolicyUri);
                if (isUserName && isNoneMode && noTokenPolicy && !auth003Endpoints.Contains(endpoint.EndpointUrl))
                {
                    auth003Endpoints.Add(endpoint.EndpointUrl);
                }
            }
        }

        if (auth001Endpoints.Count > 0)
        {
            logger.LogDebug("SEC-AUTH-001 triggered by {Count} endpoint(s)", auth001Endpoints.Count);
            findings.Add(new Finding
            {
                Id = "SEC-AUTH-001",
                Category = Category,
                Severity = Severity.Critical,
                Title = "Unauthenticated Cleartext Access",
                Description = "The following endpoint(s) accept Anonymous authentication over an unencrypted channel " +
                              "(SecurityMode=None), allowing full unauthenticated access with no encryption:\n" +
                              string.Join("\n", auth001Endpoints.Select(u => $"  - {u}")),
                Recommendation = "Disable Anonymous authentication on unencrypted endpoints. " +
                                 "This allows full unauthenticated access with no encryption.",
                CweId = "CWE-306",
                CweDescription = "Missing Authentication for Critical Function"
            });
        }

        if (auth002Endpoints.Count > 0)
        {
            logger.LogDebug("SEC-AUTH-002 triggered by {Count} endpoint(s)", auth002Endpoints.Count);
            findings.Add(new Finding
            {
                Id = "SEC-AUTH-002",
                Category = Category,
                Severity = Severity.Warning,
                Title = "Anonymous Access on Encrypted Endpoint",
                Description = "The following endpoint(s) accept Anonymous authentication even though the channel is encrypted:\n" +
                              string.Join("\n", auth002Endpoints.Select(u => $"  - {u}")),
                Recommendation = "Disable Anonymous authentication. " +
                                 "Require username/password or certificate-based authentication.",
                CweId = "CWE-306",
                CweDescription = "Missing Authentication for Critical Function"
            });
        }

        if (auth003Endpoints.Count > 0)
        {
            logger.LogDebug("SEC-AUTH-003 triggered by {Count} endpoint(s)", auth003Endpoints.Count);
            findings.Add(new Finding
            {
                Id = "SEC-AUTH-003",
                Category = Category,
                Severity = Severity.Warning,
                Title = "Username Credentials Transmitted in Cleartext",
                Description = "The following endpoint(s) accept UserName tokens on an unencrypted channel " +
                              "(SecurityMode=None) with no token-level security policy, meaning credentials travel in cleartext:\n" +
                              string.Join("\n", auth003Endpoints.Select(u => $"  - {u}")),
                Recommendation = "Ensure UserName tokens are only available on endpoints with Sign or SignAndEncrypt, " +
                                 "or configure a token-level security policy.",
                CweId = "CWE-523",
                CweDescription = "Unprotected Transport of Credentials"
            });
        }

        if (!anyCertificateToken)
        {
            logger.LogDebug("SEC-AUTH-004: no endpoint offers Certificate user token");
            findings.Add(new Finding
            {
                Id = "SEC-AUTH-004",
                Category = Category,
                Severity = Severity.Info,
                Title = "Certificate-Based Authentication Not Available",
                Description = "No endpoint offers an X.509 Certificate user identity token. " +
                              "Only weaker token types (Anonymous, UserName) are available.",
                Recommendation = "Consider enabling X.509 certificate-based user authentication " +
                                 "for stronger identity assurance."
            });
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }
}
