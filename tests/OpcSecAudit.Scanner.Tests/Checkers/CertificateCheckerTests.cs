using OpcSecAudit.Core;
using OpcSecAudit.Core.Models;
using OpcSecAudit.Scanner.Checkers;

namespace OpcSecAudit.Scanner.Tests.Checkers;

public class CertificateCheckerTests
{
    private static readonly CertificateChecker Sut =
        new(Substitute.For<ILogger<CertificateChecker>>());

    private static AuditContext MakeContext(
        IReadOnlyList<EndpointInfo> endpoints,
        string hostname = "myserver") =>
        new()
        {
            TargetUrl = $"opc.tcp://{hostname}:4840",
            ResolvedHostname = hostname,
            Port = 4840,
            Endpoints = endpoints
        };

    private static EndpointInfo MakeEndpointWithCert(
        CertificateInfo cert,
        string url = "opc.tcp://myserver:4840") =>
        new()
        {
            EndpointUrl = url,
            SecurityMode = "SignAndEncrypt",
            SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            TransportProfile = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
            UserTokenPolicies = [],
            ServerCertificate = cert
        };

    private static CertificateInfo GoodCert(
        string hostname = "myserver",
        DateTime? notAfter = null,
        int keySizeBits = 2048,
        string signatureAlgorithm = "sha256RSA",
        bool isSelfSigned = false,
        List<string>? subjectAltNames = null) =>
        new()
        {
            Subject = $"CN={hostname}, O=TestOrg",
            Issuer = isSelfSigned ? $"CN={hostname}, O=TestOrg" : "CN=TestCA, O=TestOrg",
            Thumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
            NotBefore = DateTime.UtcNow.AddDays(-365),
            NotAfter = notAfter ?? DateTime.UtcNow.AddDays(365),
            KeySizeBits = keySizeBits,
            SignatureAlgorithm = signatureAlgorithm,
            IsSelfSigned = isSelfSigned,
            SubjectAltNames = subjectAltNames ?? [hostname]
        };

    // ── SEC-CERT-001 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_CertificateIsExpired_EmitsSecCert001()
    {
        var cert = GoodCert(notAfter: DateTime.UtcNow.AddDays(-1));
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-001")
                .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task RunAsync_CertificateIsValid_DoesNotEmitSecCert001()
    {
        var cert = GoodCert(notAfter: DateTime.UtcNow.AddDays(365));
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-001");
    }

    // ── SEC-CERT-002 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_KeySizeIsBelow2048_EmitsSecCert002()
    {
        var cert = GoodCert(keySizeBits: 1024);
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-002")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_KeySizeIs2048_DoesNotEmitSecCert002()
    {
        var cert = GoodCert(keySizeBits: 2048);
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-002");
    }

    // ── SEC-CERT-003 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_Sha1SignatureAlgorithm_EmitsSecCert003()
    {
        var cert = GoodCert(signatureAlgorithm: "sha1RSA");
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-003")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_Sha256SignatureAlgorithm_DoesNotEmitSecCert003()
    {
        var cert = GoodCert(signatureAlgorithm: "sha256RSA");
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-003");
    }

    // ── SEC-CERT-004 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_CertExpiresWithin30Days_EmitsSecCert004()
    {
        var cert = GoodCert(notAfter: DateTime.UtcNow.AddDays(15));
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-004")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_CertExpiresInMoreThan30Days_DoesNotEmitSecCert004()
    {
        var cert = GoodCert(notAfter: DateTime.UtcNow.AddDays(60));
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-004");
    }

    // ── SEC-CERT-005 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_CertificateIsSelfSigned_EmitsSecCert005()
    {
        var cert = GoodCert(isSelfSigned: true);
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-005")
                .Which.Severity.Should().Be(Severity.Info);
    }

    [Fact]
    public async Task RunAsync_CertificateIsNotSelfSigned_DoesNotEmitSecCert005()
    {
        var cert = GoodCert(isSelfSigned: false);
        var context = MakeContext([MakeEndpointWithCert(cert)]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-005");
    }

    // ── SEC-CERT-006 ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_HostnameNotInCertificate_EmitsSecCert006()
    {
        var cert = GoodCert(hostname: "otherserver", subjectAltNames: ["otherserver"]);
        var context = MakeContext([MakeEndpointWithCert(cert)], hostname: "myserver");

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().ContainSingle(f => f.Id == "SEC-CERT-006")
                .Which.Severity.Should().Be(Severity.Warning);
    }

    [Fact]
    public async Task RunAsync_HostnameMatchesSubjectCn_DoesNotEmitSecCert006()
    {
        // Subject = "CN=myserver" and SANs is empty — CN match should pass
        var cert = GoodCert(hostname: "myserver", subjectAltNames: []);
        var context = MakeContext([MakeEndpointWithCert(cert)], hostname: "myserver");

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-006");
    }

    [Fact]
    public async Task RunAsync_HostnameMatchesSan_DoesNotEmitSecCert006()
    {
        var cert = GoodCert(hostname: "other", subjectAltNames: ["myserver", "other"]);
        var context = MakeContext([MakeEndpointWithCert(cert)], hostname: "myserver");

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().NotContain(f => f.Id == "SEC-CERT-006");
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_NoServerCertificate_EmitsNoFindings()
    {
        var endpoint = new EndpointInfo
        {
            EndpointUrl = "opc.tcp://myserver:4840",
            SecurityMode = "None",
            SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#None",
            TransportProfile = "",
            UserTokenPolicies = [],
            ServerCertificate = null
        };
        var context = MakeContext([endpoint]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task RunAsync_DuplicateCertificateByThumbprint_EvaluatedOnlyOnce()
    {
        // Both endpoints share the same certificate (same thumbprint).
        var cert = GoodCert(isSelfSigned: true);
        var ep1 = MakeEndpointWithCert(cert, "opc.tcp://myserver:4840");
        var ep2 = MakeEndpointWithCert(cert, "opc.tcp://myserver:4841");
        var context = MakeContext([ep1, ep2]);

        var findings = await Sut.RunAsync(context, CancellationToken.None);

        findings.Count(f => f.Id == "SEC-CERT-005").Should().Be(1);
    }
}
