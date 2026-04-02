using Microsoft.Extensions.Logging;
using OpcSecAudit.Core;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Core.Models;
using OpcSecAudit.Scanner.Interfaces;

namespace OpcSecAudit.Scanner.Checkers;

/// <summary>
/// Checks server configuration properties, including port, software identification,
/// anonymous session establishment, and audit logging status.
/// Covers findings SEC-SRV-001 through SEC-SRV-004.
/// </summary>
public class ServerConfigChecker(
    IAuditSessionFactory sessionFactory,
    ILogger<ServerConfigChecker> logger) : ISecurityChecker
{
    /// <summary>Numeric node ID of the Server_Auditing property in the OPC UA address space.</summary>
    private const uint AuditingNodeId = 2994;

    /// <inheritdoc />
    public string Category => "Server Configuration";

    /// <inheritdoc />
    public async Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken)
    {
        logger.LogInformation("Running server configuration checks for {Url}", context.TargetUrl);

        List<Finding> findings = new();

        // SEC-SRV-001: Default discovery port
        if (context.Port == 4840)
        {
            findings.Add(new Finding
            {
                Id = "SEC-SRV-001",
                Category = Category,
                Severity = Severity.Info,
                Title = "Server Running on Default Discovery Port",
                Description = $"The server is reachable on the default OPC UA discovery port 4840 " +
                              $"(URL: {context.TargetUrl}). Default ports increase exposure to automated scanning.",
                Recommendation = "Consider using a non-default port to reduce exposure from automated scanning. " +
                                 "This is informational — not inherently insecure."
            });
        }

        // SEC-SRV-002: Server software identified
        if (context.ServerApplication is { } serverInfo)
        {
            findings.Add(new Finding
            {
                Id = "SEC-SRV-002",
                Category = Category,
                Severity = Severity.Info,
                Title = "Server Software Identified",
                Description = $"Server software information is publicly accessible:\n" +
                              $"  Product:  {serverInfo.ProductName}\n" +
                              $"  Version:  {serverInfo.SoftwareVersion}\n" +
                              $"  Build:    {serverInfo.BuildNumber}\n" +
                              $"  State:    {serverInfo.State}",
                Recommendation = "Be aware that server software identification allows attackers to search for known vulnerabilities. " +
                                 "Restrict access to the BuildInfo node if possible."
            });
        }

        // SEC-SRV-003 + SEC-SRV-004: Requires an actual session
        await RunSessionChecksAsync(context, findings, cancellationToken).ConfigureAwait(false);

        return findings;
    }

    /// <summary>
    /// Attempts to establish an anonymous session and runs SEC-SRV-003 and SEC-SRV-004 checks.
    /// </summary>
    /// <param name="context">The current audit context.</param>
    /// <param name="findings">The findings list to append to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task RunSessionChecksAsync(
        AuditContext context,
        List<Finding> findings,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Attempting anonymous session to {Url} for SEC-SRV-003/004 checks", context.TargetUrl);

        IAuditSession? session = null;
        try
        {
            session = await sessionFactory.TryCreateAnonymousSessionAsync(
                context.TargetUrl,
                timeoutSeconds: 10,
                cancellationToken).ConfigureAwait(false);

            if (session is not null)
            {
                // SEC-SRV-003: Anonymous session established
                findings.Add(new Finding
                {
                    Id = "SEC-SRV-003",
                    Category = Category,
                    Severity = Severity.Warning,
                    Title = "Anonymous Session Established Successfully",
                    Description = $"An anonymous OPC UA session was successfully opened to '{context.TargetUrl}'. " +
                                  "This confirms that unauthenticated clients can browse and interact with the server.",
                    Recommendation = "Disable Anonymous access to prevent unauthorized session creation.",
                    CweId = "CWE-306",
                    CweDescription = "Missing Authentication for Critical Function"
                });

                // SEC-SRV-004: Check audit logging node (reuse same session)
                await CheckAuditingNodeAsync(context, session, findings, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                logger.LogInformation("Anonymous session could not be established — SEC-SRV-003 not triggered");

                // Cannot check auditing without a session
                findings.Add(new Finding
                {
                    Id = "SEC-SRV-004",
                    Category = Category,
                    Severity = Severity.Info,
                    Title = "Audit Logging Status Could Not Be Determined",
                    Description = $"The Server_Auditing node (i=2994) could not be checked because no anonymous " +
                                  $"session could be established to '{context.TargetUrl}'.",
                    Recommendation = "Enable audit logging on the OPC UA server. " +
                                     "Audit events provide traceability for security-relevant operations."
                });
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Session check for SEC-SRV-003/004 failed with an unexpected error");
        }
        finally
        {
            if (session is not null)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Reads the Server_Auditing node and emits SEC-SRV-004 if auditing is disabled or unreadable.
    /// </summary>
    /// <param name="context">The current audit context.</param>
    /// <param name="session">An established audit session.</param>
    /// <param name="findings">The findings list to append to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task CheckAuditingNodeAsync(
        AuditContext context,
        IAuditSession session,
        List<Finding> findings,
        CancellationToken cancellationToken)
    {
        try
        {
            var value = await session.ReadNodeValueAsync(AuditingNodeId, cancellationToken).ConfigureAwait(false);

            if (value is true)
            {
                logger.LogInformation("Audit logging is enabled on {Url}", context.TargetUrl);
            }
            else
            {
                findings.Add(new Finding
                {
                    Id = "SEC-SRV-004",
                    Category = Category,
                    Severity = Severity.Info,
                    Title = "Audit Logging Not Enabled",
                    Description = $"The Server_Auditing node (i=2994) on '{context.TargetUrl}' " +
                                  $"returned '{value ?? "null"}', indicating audit logging is not active.",
                    Recommendation = "Enable audit logging on the OPC UA server. " +
                                     "Audit events provide traceability for security-relevant operations."
                });
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read Server_Auditing node (i=2994) on {Url}", context.TargetUrl);
            findings.Add(new Finding
            {
                Id = "SEC-SRV-004",
                Category = Category,
                Severity = Severity.Info,
                Title = "Audit Logging Not Enabled",
                Description = $"The Server_Auditing node (i=2994) on '{context.TargetUrl}' was not readable " +
                              $"or not present. This may indicate audit logging is not configured.",
                Recommendation = "Enable audit logging on the OPC UA server. " +
                                 "Audit events provide traceability for security-relevant operations."
            });
        }
    }
}
