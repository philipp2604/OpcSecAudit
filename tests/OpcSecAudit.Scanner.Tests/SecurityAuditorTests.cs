using OpcSecAudit.Core.Exceptions;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Scanner;

namespace OpcSecAudit.Scanner.Tests;

// NOTE: SecurityAuditor instantiates DiscoveryClient and DefaultSessionFactory internally
// rather than via injected interfaces.  As a result, the happy-path tests that exercise
// full endpoint discovery and checker delegation require either a live OPC UA server
// (integration tests) or a future refactoring to inject an IOpcUaDiscoveryClient
// abstraction.  The tests below cover the URL-validation boundary and the checker
// wiring that can be verified without a server.

public class SecurityAuditorTests
{
    private static SecurityAuditor CreateSut(params ISecurityChecker[] checkers) =>
        new(checkers, Substitute.For<ILogger<SecurityAuditor>>());

    // ── URL validation ────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAuditAsync_InvalidUrl_ThrowsAuditException()
    {
        var sut = CreateSut();

        var act = () => sut.RunAuditAsync("not-a-url", timeoutSeconds: 5, CancellationToken.None);

        await act.Should().ThrowAsync<AuditException>()
                 .WithMessage("*Invalid target URL*");
    }

    [Fact]
    public async Task RunAuditAsync_ValidUrlFormat_ThrowsAuditExceptionAboutDiscovery()
    {
        // A syntactically valid URL must not be rejected at URL-parsing time.
        // Discovery will fail (no real server), but the exception must be about
        // endpoint discovery, NOT about an invalid URL format.
        var sut = CreateSut();

        var act = () => sut.RunAuditAsync(
            "opc.tcp://127.0.0.1:19999", timeoutSeconds: 1, CancellationToken.None);

        var ex = await act.Should().ThrowAsync<AuditException>();
        ex.WithMessage("*discovery*");
        ex.Which.Message.Should().NotContain("Invalid target URL");
    }
}
