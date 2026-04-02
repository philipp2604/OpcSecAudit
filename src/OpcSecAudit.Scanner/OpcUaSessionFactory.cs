using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcSecAudit.Scanner.Interfaces;

namespace OpcSecAudit.Scanner;

/// <summary>
/// Creates anonymous OPC UA sessions using the OPC Foundation SDK.
/// Discovers the server's endpoints, selects the most permissive anonymous endpoint,
/// and establishes a session.
/// </summary>
public sealed class OpcUaSessionFactory(ILogger<OpcUaSessionFactory> logger) : IAuditSessionFactory
{
    /// <inheritdoc />
    public async Task<IAuditSession?> TryCreateAnonymousSessionAsync(
        string targetUrl,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        try
        {
            var config = await BuildApplicationConfigurationAsync(timeoutSeconds).ConfigureAwait(false);
            var discoveryUri = new Uri(targetUrl);

            // DiscoveryClient implements IDisposable (not IAsyncDisposable).
            using var discoveryClient = await DiscoveryClient.CreateAsync(
                config, discoveryUri, DiagnosticsMasks.None, cancellationToken).ConfigureAwait(false);

            var endpoints = await discoveryClient.GetEndpointsAsync(
                null, cancellationToken).ConfigureAwait(false);

            // Prefer SecurityMode.None + Anonymous; fall back to any anonymous endpoint.
            EndpointDescription? selectedEndpoint = endpoints
                .Where(e => e.UserIdentityTokens.Any(t => t.TokenType == UserTokenType.Anonymous))
                .OrderBy(e => (int)e.SecurityMode)
                .FirstOrDefault();

            if (selectedEndpoint is null)
            {
                logger.LogInformation("No anonymous endpoint found at {Url}", targetUrl);
                return null;
            }

            var configuredEndpoint = new ConfiguredEndpoint(
                null, selectedEndpoint, EndpointConfiguration.Create(config));

            var session = await new DefaultSessionFactory(DefaultTelemetry.Create(_ => { })).CreateAsync(
                config,
                configuredEndpoint,
                updateBeforeConnect: false,
                checkDomain: false,
                sessionName: "OpcSecAudit",
                sessionTimeout: (uint)(timeoutSeconds * 1000),
                identity: new UserIdentity(),
                preferredLocales: null,
                ct: cancellationToken).ConfigureAwait(false);

            logger.LogInformation(
                "Anonymous session established to {Url} (SecurityMode={Mode})",
                targetUrl, selectedEndpoint.SecurityMode);

            return new OpcUaAuditSession(session);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to establish anonymous session to {Url}", targetUrl);
            return null;
        }
    }

    /// <summary>
    /// Creates a minimal passive <see cref="ApplicationConfiguration"/> for auditing.
    /// Auto-accepts untrusted certificates so we can inspect any server regardless of its PKI setup.
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
