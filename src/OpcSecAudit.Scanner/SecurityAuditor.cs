using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using OpcSecAudit.Core;
using OpcSecAudit.Core.Exceptions;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Scanner;

/// <summary>
/// Orchestrates the full security audit: discovers endpoints, runs all security checkers,
/// optionally reads server build information, and assembles the final <see cref="AuditResult"/>.
/// </summary>
public class SecurityAuditor(
    IEnumerable<ISecurityChecker> checkers,
    ILogger<SecurityAuditor> logger)
{
    /// <summary>
    /// Runs a full security audit against the specified OPC UA server.
    /// </summary>
    /// <param name="targetUrl">The OPC UA endpoint URL (e.g., "opc.tcp://192.168.1.50:4840").</param>
    /// <param name="timeoutSeconds">Connection timeout in seconds.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The complete audit result.</returns>
    /// <exception cref="AuditException">Thrown if endpoint discovery fails entirely.</exception>
    public async Task<AuditResult> RunAuditAsync(
        string targetUrl,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        var startTime = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        logger.LogInformation("Starting audit of {Url}", targetUrl);

        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
        {
            throw new AuditException($"Invalid target URL: '{targetUrl}'.");
        }

        int port = uri.Port > 0 ? uri.Port : 4840;
        string hostname = uri.Host;

        ApplicationConfiguration config;
        try
        {
            config = await BuildApplicationConfigurationAsync(timeoutSeconds).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new AuditException("Failed to build OPC UA application configuration.", ex);
        }

        EndpointDescriptionCollection rawEndpoints;
        try
        {
            logger.LogInformation("Discovering endpoints at {Url}", targetUrl);
            using var discoveryClient = await DiscoveryClient.CreateAsync(
                config, uri, DiagnosticsMasks.None, cancellationToken).ConfigureAwait(false);

            rawEndpoints = await discoveryClient.GetEndpointsAsync(null, cancellationToken).ConfigureAwait(false);
            logger.LogInformation("Discovered {Count} endpoint(s)", rawEndpoints.Count);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new AuditException($"Endpoint discovery failed for '{targetUrl}'.", ex);
        }

        var endpointInfos = rawEndpoints.Select(ToEndpointInfo).ToList();

        ServerInfo? serverInfo = await TryReadServerInfoAsync(
            targetUrl, rawEndpoints, config, cancellationToken).ConfigureAwait(false);

        var context = new AuditContext
        {
            TargetUrl = targetUrl,
            ResolvedHostname = hostname,
            Port = port,
            Endpoints = endpointInfos,
            ServerApplication = serverInfo
        };

        var allFindings = new List<Finding>();
        foreach (var checker in checkers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogInformation("Running checker: {Category}", checker.Category);
            try
            {
                var findings = await checker.RunAsync(context, cancellationToken).ConfigureAwait(false);
                allFindings.AddRange(findings);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Checker '{Category}' threw an unexpected exception", checker.Category);
            }
        }

        stopwatch.Stop();

        return new AuditResult
        {
            TargetUrl = targetUrl,
            Timestamp = startTime,
            Duration = stopwatch.Elapsed,
            DiscoveredEndpoints = endpointInfos,
            ServerInfo = serverInfo,
            Findings = allFindings
        };
    }

    /// <summary>
    /// Converts an OPC UA SDK <see cref="EndpointDescription"/> to the Core <see cref="EndpointInfo"/> model.
    /// </summary>
    /// <param name="endpoint">The raw SDK endpoint description.</param>
    private static EndpointInfo ToEndpointInfo(EndpointDescription endpoint)
    {
        CertificateInfo? certInfo = null;
        if (endpoint.ServerCertificate is { Length: > 0 } certBytes)
        {
            certInfo = TryParseCertificate(certBytes);
        }

        return new EndpointInfo
        {
            EndpointUrl = endpoint.EndpointUrl ?? string.Empty,
            SecurityMode = endpoint.SecurityMode.ToString(),
            SecurityPolicy = endpoint.SecurityPolicyUri ?? string.Empty,
            TransportProfile = endpoint.TransportProfileUri ?? string.Empty,
            UserTokenPolicies = (endpoint.UserIdentityTokens ?? [])
                .Select(t => new UserTokenInfo
                {
                    TokenType = t.TokenType.ToString(),
                    SecurityPolicyUri = string.IsNullOrEmpty(t.SecurityPolicyUri) ? null : t.SecurityPolicyUri
                })
                .ToList(),
            ServerCertificate = certInfo
        };
    }

    /// <summary>
    /// Attempts to parse DER-encoded certificate bytes into a <see cref="CertificateInfo"/> object.
    /// Returns <see langword="null"/> on any parse failure.
    /// </summary>
    /// <param name="certBytes">DER-encoded X.509 certificate bytes.</param>
    private static CertificateInfo? TryParseCertificate(byte[] certBytes)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(certBytes);

            int keySizeBits = 0;
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is not null)
            {
                keySizeBits = rsa.KeySize;
            }

            var sans = new List<string>();
            if (cert.Extensions["2.5.29.17"] is X509SubjectAlternativeNameExtension sanExt)
            {
                foreach (var name in sanExt.EnumerateDnsNames())
                {
                    sans.Add(name);
                }
                foreach (var ip in sanExt.EnumerateIPAddresses())
                {
                    sans.Add(ip.ToString());
                }
            }

            return new CertificateInfo
            {
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                KeySizeBits = keySizeBits,
                SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName
                                     ?? cert.SignatureAlgorithm.Value
                                     ?? "Unknown",
                IsSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase),
                SubjectAltNames = sans
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Tries to read <c>ServerStatus</c> / <c>BuildInfo</c> by opening an anonymous session to the
    /// most permissive endpoint available. Returns <see langword="null"/> on any failure.
    /// </summary>
    /// <param name="targetUrl">The target server URL.</param>
    /// <param name="endpoints">The discovered endpoint collection.</param>
    /// <param name="config">OPC UA application configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task<ServerInfo?> TryReadServerInfoAsync(
        string targetUrl,
        EndpointDescriptionCollection endpoints,
        ApplicationConfiguration config,
        CancellationToken cancellationToken)
    {
        var permissive = endpoints
            .Where(e => e.UserIdentityTokens.Any(t => t.TokenType == UserTokenType.Anonymous))
            .OrderBy(e => (int)e.SecurityMode)
            .FirstOrDefault();

        if (permissive is null)
        {
            logger.LogInformation("No anonymous endpoint available to read BuildInfo");
            return null;
        }

        try
        {
            var configuredEndpoint = new ConfiguredEndpoint(
                null, permissive, EndpointConfiguration.Create(config));

            var session = await new DefaultSessionFactory(DefaultTelemetry.Create(_ => { })).CreateAsync(
                config,
                configuredEndpoint,
                updateBeforeConnect: false,
                checkDomain: false,
                sessionName: "OpcSecAudit-BuildInfo",
                sessionTimeout: 10_000u,
                identity: new UserIdentity(),
                preferredLocales: null,
                ct: cancellationToken).ConfigureAwait(false);

            using (session)
            {
                // NodeIds: Server_ServerStatus_BuildInfo_ProductName=2264,
                //          SoftwareVersion=2265, BuildNumber=2266, State=2259
                string productName = await ReadStringNodeAsync(session, new NodeId(2264), cancellationToken)
                                     ?? string.Empty;
                string softwareVersion = await ReadStringNodeAsync(session, new NodeId(2265), cancellationToken)
                                         ?? string.Empty;
                string buildNumber = await ReadStringNodeAsync(session, new NodeId(2266), cancellationToken)
                                     ?? string.Empty;

                var stateVal = await session.ReadValueAsync(new NodeId(2259), cancellationToken)
                    .ConfigureAwait(false);
                string state = stateVal?.Value is ServerState ss ? ss.ToString()
                    : stateVal?.Value?.ToString() ?? "Unknown";

                await session.CloseAsync(cancellationToken).ConfigureAwait(false);

                logger.LogInformation(
                    "Read BuildInfo: Product={Product}, Version={Version}", productName, softwareVersion);

                return new ServerInfo
                {
                    ProductName = productName,
                    SoftwareVersion = softwareVersion,
                    BuildNumber = buildNumber,
                    State = state
                };
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Could not read BuildInfo from {Url} — server info will be unavailable", targetUrl);
            return null;
        }
    }

    /// <summary>
    /// Reads a single string-valued node asynchronously.
    /// Returns <see langword="null"/> on any failure.
    /// </summary>
    /// <param name="session">An active OPC UA session.</param>
    /// <param name="nodeId">The node ID to read.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private static async Task<string?> ReadStringNodeAsync(
        ISession session,
        NodeId nodeId,
        CancellationToken cancellationToken)
    {
        try
        {
            var value = await session.ReadValueAsync(nodeId, cancellationToken).ConfigureAwait(false);
            return value?.Value?.ToString();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Creates a minimal passive <see cref="ApplicationConfiguration"/> for auditing.
    /// </summary>
    /// <param name="timeoutSeconds">Timeout in seconds for OPC UA transport operations.</param>
    private static async Task<ApplicationConfiguration> BuildApplicationConfigurationAsync(int timeoutSeconds)
    {
        string pkiRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OpcSecAudit", "pki");

        var config = new ApplicationConfiguration
        {
            ApplicationName = "OpcSecAudit",
            ApplicationUri = "urn:localhost:OpcSecAudit",
            ApplicationType = ApplicationType.Client,
            SecurityConfiguration = new SecurityConfiguration
            {
                ApplicationCertificate = new CertificateIdentifier
                {
                    StoreType = "Directory",
                    StorePath = Path.Combine(pkiRoot, "own"),
                    SubjectName = "CN=OpcSecAudit"
                },
                TrustedIssuerCertificates = new CertificateTrustList
                {
                    StoreType = "Directory",
                    StorePath = Path.Combine(pkiRoot, "issuer")
                },
                TrustedPeerCertificates = new CertificateTrustList
                {
                    StoreType = "Directory",
                    StorePath = Path.Combine(pkiRoot, "trusted")
                },
                RejectedCertificateStore = new CertificateTrustList
                {
                    StoreType = "Directory",
                    StorePath = Path.Combine(pkiRoot, "rejected")
                },
                AutoAcceptUntrustedCertificates = true,
                RejectSHA1SignedCertificates = false
            },
            TransportConfigurations = new TransportConfigurationCollection(),
            TransportQuotas = new TransportQuotas
            {
                OperationTimeout = timeoutSeconds * 1000
            },
            ClientConfiguration = new ClientConfiguration
            {
                DefaultSessionTimeout = timeoutSeconds * 1000
            }
        };

        await config.ValidateAsync(ApplicationType.Client).ConfigureAwait(false);
        return config;
    }
}
