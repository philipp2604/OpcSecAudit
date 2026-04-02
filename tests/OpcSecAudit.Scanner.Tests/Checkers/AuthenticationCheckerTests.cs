using OpcSecAudit.Core;
using OpcSecAudit.Core.Models;
using OpcSecAudit.Scanner.Checkers;

namespace OpcSecAudit.Scanner.Tests.Checkers;

public class AuthenticationCheckerTests
{
    private static readonly AuthenticationChecker Sut =
        new(Substitute.For<ILogger<AuthenticationChecker>>());

    private static AuditContext MakeContext(IReadOnlyList<EndpointInfo> endpoints) =>
        new()
        {
            TargetUrl = "opc.tcp://192.168.1.1:4840",
            ResolvedHostname = "192.168.1.1",
            Port = 4840,
            Endpoints = endpoints
        };

    private static EndpointInfo MakeEndpoint(
        string securityMode,
        IReadOnlyList<UserTokenInfo> tokens,
        string url = "opc.tcp://192.168.1.1:4840") =>
        new()
        {
            EndpointUrl = url,
            SecurityMode = securityMode,
            SecurityPolicy = securityMode == "None"
                ? "http://opcfoundation.org/UA/SecurityPolicy#None"
                : "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            TransportProfile = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            UserTokenPolicies = tokens.ToList()
        };

    private static UserTokenInfo Anon() => new() { TokenType = "Anonymous" };
    private static UserTokenInfo UserName(string? policyUri = null) =>
        new() { TokenType = "UserName", SecurityPolicyUri = policyUri };
    private static UserTokenInfo Certificate() => new() { TokenType = "Certificate" };

    // ── SEC-AUTH-001 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task SecAuth001_Triggered_WhenAnonymousTokenOnNoneEndpoint()
    {
        var context = MakeContext([MakeEndpoint("None", [Anon()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-AUTH-001")
                .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task SecAuth001_NotTriggered_WhenAnonymousTokenOnEncryptedEndpoint()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [Anon()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-AUTH-001");
    }

    [Fact]
    public async Task SecAuth001_DescriptionContainsAllAffectedUrls()
    {
        var ep1 = MakeEndpoint("None", [Anon()], "opc.tcp://srv:4840");
        var ep2 = MakeEndpoint("None", [Anon()], "opc.tcp://srv:4841");
        var context = MakeContext([ep1, ep2]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        var finding = findings.Single(f => f.Id == "SEC-AUTH-001");
        finding.Description.Should().Contain("opc.tcp://srv:4840");
        finding.Description.Should().Contain("opc.tcp://srv:4841");
    }

    // ── SEC-AUTH-002 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task SecAuth002_Triggered_WhenAnonymousTokenOnEncryptedEndpoint()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [Anon()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-AUTH-002")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task SecAuth002_NotTriggered_WhenNoAnonymousOnEncryptedEndpoint()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [UserName()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-AUTH-002");
    }

    // ── SEC-AUTH-003 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task SecAuth003_Triggered_WhenUserNameOnNoneEndpointWithoutTokenPolicy()
    {
        var context = MakeContext([MakeEndpoint("None", [UserName(policyUri: null)])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-AUTH-003")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task SecAuth003_NotTriggered_WhenUserNameHasTokenLevelSecurityPolicy()
    {
        const string tokenPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
        var context = MakeContext([MakeEndpoint("None", [UserName(policyUri: tokenPolicy)])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-AUTH-003");
    }

    [Fact]
    public async Task SecAuth003_NotTriggered_WhenUserNameIsOnEncryptedEndpoint()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [UserName(policyUri: null)])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-AUTH-003");
    }

    // ── SEC-AUTH-004 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task SecAuth004_Triggered_WhenNoCertificateTokenOnAnyEndpoint()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [Anon(), UserName()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-AUTH-004")
                .Which.Severity.Should().Be(Severity.Info);
    }

    [Fact]
    public async Task SecAuth004_NotTriggered_WhenAtLeastOneCertificateTokenExists()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", [Anon(), Certificate()])]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-AUTH-004");
    }
}
