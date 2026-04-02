using OpcSecAudit.Core;
using OpcSecAudit.Core.Models;
using OpcSecAudit.Scanner.Checkers;

namespace OpcSecAudit.Scanner.Tests.Checkers;

public class EndpointSecurityCheckerTests
{
    private static readonly EndpointSecurityChecker Sut =
        new(Substitute.For<ILogger<EndpointSecurityChecker>>());

    private const string NonePolicy = "http://opcfoundation.org/UA/SecurityPolicy#None";
    private const string Basic128Policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
    private const string Basic256Policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
    private const string Basic256Sha256Policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";

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
        string securityPolicy,
        string url = "opc.tcp://192.168.1.1:4840") =>
        new()
        {
            EndpointUrl = url,
            SecurityMode = securityMode,
            SecurityPolicy = securityPolicy,
            TransportProfile = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            UserTokenPolicies = []
        };

    // ── SEC-EP-001 ────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_SecurityModeNoneAndNonePolicy_EmitsSecEp001()
    {
        var context = MakeContext([MakeEndpoint("None", NonePolicy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-EP-001")
                .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task RunAsync_SecurityModeIsSignAndEncrypt_DoesNotEmitSecEp001()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", Basic256Sha256Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-EP-001");
    }

    [Fact]
    public async Task RunAsync_MultipleNoneEndpointsExist_EmitsSecEp001Once()
    {
        var context = MakeContext([
            MakeEndpoint("None", NonePolicy, "opc.tcp://srv:4840"),
            MakeEndpoint("None", NonePolicy, "opc.tcp://srv:4841")
        ]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Count(f => f.Id == "SEC-EP-001").Should().Be(1);
    }

    // ── SEC-EP-002 ────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_Basic128Rsa15PolicyPresent_EmitsSecEp002()
    {
        var context = MakeContext([MakeEndpoint("Sign", Basic128Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-EP-002")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_NoBasic128Rsa15Policy_DoesNotEmitSecEp002()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", Basic256Sha256Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-EP-002");
    }

    [Fact]
    public async Task RunAsync_MultipleBasic128Endpoints_EmitsSecEp002Once()
    {
        var context = MakeContext([
            MakeEndpoint("Sign", Basic128Policy, "opc.tcp://srv:4840"),
            MakeEndpoint("Sign", Basic128Policy, "opc.tcp://srv:4841")
        ]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Count(f => f.Id == "SEC-EP-002").Should().Be(1);
    }

    // ── SEC-EP-003 ────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_Basic256LegacyPolicyPresent_EmitsSecEp003()
    {
        var context = MakeContext([MakeEndpoint("Sign", Basic256Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-EP-003")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_Basic256Sha256PolicyUsed_DoesNotEmitSecEp003()
    {
        // "Basic256Sha256" contains "Basic256" but must NOT trigger SEC-EP-003
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", Basic256Sha256Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-EP-003");
    }

    // ── SEC-EP-004 ────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_AllEndpointsUseApprovedPolicies_EmitsSecEp004()
    {
        var context = MakeContext([MakeEndpoint("SignAndEncrypt", Basic256Sha256Policy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-EP-004")
                .Which.Severity.Should().Be(Severity.Info);
    }

    [Fact]
    public async Task RunAsync_AnyWeakPolicyFound_DoesNotEmitSecEp004()
    {
        var context = MakeContext([MakeEndpoint("None", NonePolicy)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-EP-004");
    }
}
