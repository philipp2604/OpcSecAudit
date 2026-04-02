using OpcSecAudit.Core;
using OpcSecAudit.Core.Models;
using OpcSecAudit.Scanner.Checkers;
using OpcSecAudit.Scanner.Interfaces;

namespace OpcSecAudit.Scanner.Tests.Checkers;

public class ServerConfigCheckerTests
{
    private readonly IAuditSessionFactory _sessionFactory =
        Substitute.For<IAuditSessionFactory>();

    private ServerConfigChecker CreateSut() =>
        new(_sessionFactory, Substitute.For<ILogger<ServerConfigChecker>>());

    private static AuditContext MakeContext(
        int port = 4840,
        ServerInfo? serverInfo = null,
        string url = "opc.tcp://192.168.1.1:4840") =>
        new()
        {
            TargetUrl = url,
            ResolvedHostname = "192.168.1.1",
            Port = port,
            Endpoints = [],
            ServerApplication = serverInfo
        };

    private static ServerInfo SomeServerInfo() =>
        new()
        {
            ProductName = "AcmeServer",
            SoftwareVersion = "2.1.0",
            BuildNumber = "42",
            State = "Running"
        };

    private IAuditSession MockSession(object? auditingNodeValue)
    {
        var session = Substitute.For<IAuditSession>();
        session.ReadNodeValueAsync(2994u, Arg.Any<CancellationToken>())
               .Returns(Task.FromResult(auditingNodeValue));
        session.DisposeAsync().Returns(ValueTask.CompletedTask);
        return session;
    }

    private void SetupFactoryToReturn(IAuditSession? session) =>
        _sessionFactory
            .TryCreateAnonymousSessionAsync(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(session));

    // ── SEC-SRV-001 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_PortIs4840_EmitsSecSrv001()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext(port: 4840);

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-SRV-001")
                .Which.Severity.Should().Be(Severity.Info);
    }

    [Fact]
    public async Task RunAsync_PortIsNotDefault_DoesNotEmitSecSrv001()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext(port: 48400, url: "opc.tcp://192.168.1.1:48400");

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-SRV-001");
    }

    // ── SEC-SRV-002 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_ServerInfoAvailable_EmitsSecSrv002()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext(serverInfo: SomeServerInfo());

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        var finding = findings.Should().ContainSingle(f => f.Id == "SEC-SRV-002").Subject;
        finding.Severity.Should().Be(Severity.Info);
        finding.Description.Should().Contain("AcmeServer");
        finding.Description.Should().Contain("2.1.0");
    }

    [Fact]
    public async Task RunAsync_ServerInfoIsNull_DoesNotEmitSecSrv002()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext(serverInfo: null);

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-SRV-002");
    }

    // ── SEC-SRV-003 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_AnonymousSessionSucceeds_EmitsSecSrv003()
    {
        var session = MockSession(auditingNodeValue: false);
        SetupFactoryToReturn(session);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-SRV-003")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_SessionFactoryReturnsNull_DoesNotEmitSecSrv003()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-SRV-003");
    }

    // ── SEC-SRV-004 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_AuditingNodeReturnsFalse_EmitsSecSrv004()
    {
        var session = MockSession(auditingNodeValue: (object)false);
        SetupFactoryToReturn(session);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-SRV-004")
                .Which.Severity.Should().Be(Severity.Info);
    }

    [Fact]
    public async Task RunAsync_AuditingNodeReturnsNull_EmitsSecSrv004()
    {
        var session = MockSession(auditingNodeValue: null);
        SetupFactoryToReturn(session);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-SRV-004");
    }

    [Fact]
    public async Task RunAsync_AuditingNodeReturnsTrue_DoesNotEmitSecSrv004()
    {
        var session = MockSession(auditingNodeValue: (object)true);
        SetupFactoryToReturn(session);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-SRV-004");
    }

    [Fact]
    public async Task RunAsync_NoSessionAvailable_EmitsSecSrv004WithNoSessionDescription()
    {
        SetupFactoryToReturn(null);
        var context = MakeContext();

        var findings = await CreateSut().RunAsync(context, CancellationToken.None);

        var finding = findings.Should().ContainSingle(f => f.Id == "SEC-SRV-004").Subject;
        finding.Description.Should().Contain("no anonymous");
    }
}
