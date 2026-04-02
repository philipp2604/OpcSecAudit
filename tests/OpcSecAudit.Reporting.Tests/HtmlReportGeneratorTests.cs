using OpcSecAudit.Core.Models;
using OpcSecAudit.Reporting;

namespace OpcSecAudit.Reporting.Tests;

public class HtmlReportGeneratorTests : IDisposable
{
    private readonly string _outputPath = Path.Combine(Path.GetTempPath(), $"OpcSecAuditTest_{Guid.NewGuid():N}.html");
    private readonly HtmlReportGenerator _sut = new();

    public void Dispose()
    {
        if (File.Exists(_outputPath))
        {
            File.Delete(_outputPath);
        }
    }

    private static AuditResult BuildResult(
        List<Finding>? findings = null,
        ServerInfo? serverInfo = null,
        List<EndpointInfo>? endpoints = null) =>
        new()
        {
            TargetUrl = "opc.tcp://192.168.1.1:4840",
            Timestamp = new DateTime(2025, 6, 15, 14, 30, 0, DateTimeKind.Utc),
            Duration = TimeSpan.FromSeconds(2.3),
            DiscoveredEndpoints = endpoints ?? [],
            ServerInfo = serverInfo,
            Findings = findings ?? []
        };

    // ── File output ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_CreatesFileAtSpecifiedPath()
    {
        var result = BuildResult();

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        File.Exists(_outputPath).ShouldBeTrue();
    }

    [Fact]
    public async Task GenerateAsync_WritesValidHtml()
    {
        var result = BuildResult();

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldStartWith("<!DOCTYPE html>");
        html.ShouldContain("</html>");
    }

    // ── Target URL ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_ContainsTargetUrl()
    {
        var result = BuildResult();

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("opc.tcp://192.168.1.1:4840");
    }

    // ── Assessment ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_ShowsFail_WhenCriticalFindingsExist()
    {
        List<Finding> findings = [MakeFinding("SEC-EP-001", Severity.Critical)];
        var result = BuildResult(findings: findings);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("FAIL");
    }

    [Fact]
    public async Task GenerateAsync_ShowsReview_WhenOnlyWarningFindingsExist()
    {
        List<Finding> findings = [MakeFinding("SEC-EP-002", Severity.Warning)];
        var result = BuildResult(findings: findings);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("REVIEW");
        html.ShouldNotContain("FAIL");
    }

    [Fact]
    public async Task GenerateAsync_ShowsPass_WhenNoFindingsExist()
    {
        var result = BuildResult(findings: []);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("PASS");
    }

    // ── Findings content ──────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_ContainsFindingIdAndTitle()
    {
        List<Finding> findings = [MakeFinding("SEC-EP-001", Severity.Critical, "Unencrypted Endpoint Available")];
        var result = BuildResult(findings: findings);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("SEC-EP-001");
        html.ShouldContain("Unencrypted Endpoint Available");
    }

    [Fact]
    public async Task GenerateAsync_ContainsCweLink_WhenFindingHasCweId()
    {
        var finding = new Finding
        {
            Id = "SEC-EP-001",
            Category = "Endpoint Security",
            Severity = Severity.Critical,
            Title = "Unencrypted Endpoint",
            Description = "Test description",
            Recommendation = "Fix it",
            CweId = "CWE-319",
            CweDescription = "Cleartext Transmission"
        };
        var result = BuildResult(findings: [finding]);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("cwe.mitre.org/data/definitions/319.html");
        html.ShouldContain("CWE-319");
    }

    [Fact]
    public async Task GenerateAsync_GroupsFindingsByCategory()
    {
        var findings = new List<Finding>
        {
            MakeFinding("SEC-EP-001", Severity.Critical, category: "Endpoint Security"),
            MakeFinding("SEC-AUTH-001", Severity.Critical, category: "Authentication")
        };
        var result = BuildResult(findings: findings);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("Endpoint Security");
        html.ShouldContain("Authentication");
        // Category heading should appear before finding ID
        html.IndexOf("Endpoint Security", StringComparison.Ordinal)
            .ShouldBeLessThan(html.IndexOf("SEC-EP-001", StringComparison.Ordinal));
    }

    // ── Endpoints table ───────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_HighlightsNoneModeEndpoint()
    {
        var endpoints = new List<EndpointInfo>
        {
            new()
            {
                EndpointUrl = "opc.tcp://192.168.1.1:4840",
                SecurityMode = "None",
                SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#None",
                TransportProfile = "",
                UserTokenPolicies = []
            }
        };
        var result = BuildResult(endpoints: endpoints);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("none-mode");
    }

    [Fact]
    public async Task GenerateAsync_ShowsShortPolicyName()
    {
        var endpoints = new List<EndpointInfo>
        {
            new()
            {
                EndpointUrl = "opc.tcp://192.168.1.1:4840",
                SecurityMode = "SignAndEncrypt",
                SecurityPolicy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                TransportProfile = "",
                UserTokenPolicies = []
            }
        };
        var result = BuildResult(endpoints: endpoints);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("Basic256Sha256");
        html.ShouldNotContain("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    }

    // ── Server info ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_ContainsServerInfo_WhenAvailable()
    {
        var serverInfo = new ServerInfo
        {
            ProductName = "AcmePLC",
            SoftwareVersion = "3.2.1",
            BuildNumber = "9999",
            State = "Running"
        };
        var result = BuildResult(serverInfo: serverInfo);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("AcmePLC");
        html.ShouldContain("3.2.1");
    }

    [Fact]
    public async Task GenerateAsync_OmitsServerInfoSection_WhenNull()
    {
        var result = BuildResult(serverInfo: null);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        // No server info card when null
        html.ShouldNotContain("Server Information");
    }

    // ── HTML encoding ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_HtmlEncodesSpecialCharactersInFindings()
    {
        var finding = new Finding
        {
            Id = "SEC-EP-001",
            Category = "Endpoint Security",
            Severity = Severity.Critical,
            Title = "Title with <script>",
            Description = "Desc with & and \"quotes\"",
            Recommendation = "Rec"
        };
        var result = BuildResult(findings: [finding]);

        await _sut.GenerateAsync(result, _outputPath, CancellationToken.None);

        var html = await File.ReadAllTextAsync(_outputPath);
        html.ShouldContain("&lt;script&gt;");
        html.ShouldContain("&amp;");
        html.ShouldNotContain("<script>");
    }

    private static Finding MakeFinding(
        string id,
        Severity severity,
        string title = "Test Finding",
        string category = "Test Category") =>
        new()
        {
            Id = id,
            Category = category,
            Severity = severity,
            Title = title,
            Description = $"Description for {id}",
            Recommendation = "Fix it"
        };
}
