using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Tests.Models;

public class AuditResultTests
{
    private static Finding MakeFinding(Severity severity, string id = "SEC-TST-001") =>
        new()
        {
            Id = id,
            Category = "Test",
            Severity = severity,
            Title = "Test Finding",
            Description = "Test description.",
            Recommendation = "Test recommendation."
        };

    [Fact]
    public void CriticalCount_ReturnsOnlyCriticalFindings()
    {
        // Arrange
        var result = new AuditResult
        {
            TargetUrl = "opc.tcp://localhost:4840",
            Timestamp = DateTime.UtcNow,
            Duration = TimeSpan.FromSeconds(1),
            DiscoveredEndpoints = [],
            Findings =
            [
                MakeFinding(Severity.Critical, "SEC-1"),
                MakeFinding(Severity.Critical, "SEC-2"),
                MakeFinding(Severity.Warning, "SEC-3"),
                MakeFinding(Severity.Info, "SEC-4")
            ]
        };

        // Assert
        result.CriticalCount.ShouldBe(2);
    }

    [Fact]
    public void WarningCount_ReturnsOnlyWarningFindings()
    {
        // Arrange
        var result = new AuditResult
        {
            TargetUrl = "opc.tcp://localhost:4840",
            Timestamp = DateTime.UtcNow,
            Duration = TimeSpan.FromSeconds(1),
            DiscoveredEndpoints = [],
            Findings =
            [
                MakeFinding(Severity.Critical, "SEC-1"),
                MakeFinding(Severity.Warning, "SEC-2"),
                MakeFinding(Severity.Warning, "SEC-3")
            ]
        };

        // Assert
        result.WarningCount.ShouldBe(2);
    }

    [Fact]
    public void InfoCount_ReturnsOnlyInfoFindings()
    {
        // Arrange
        var result = new AuditResult
        {
            TargetUrl = "opc.tcp://localhost:4840",
            Timestamp = DateTime.UtcNow,
            Duration = TimeSpan.FromSeconds(1),
            DiscoveredEndpoints = [],
            Findings =
            [
                MakeFinding(Severity.Critical, "SEC-1"),
                MakeFinding(Severity.Info, "SEC-2"),
                MakeFinding(Severity.Info, "SEC-3"),
                MakeFinding(Severity.Info, "SEC-4")
            ]
        };

        // Assert
        result.InfoCount.ShouldBe(3);
    }

    [Fact]
    public void AllCounts_AreZero_WhenFindingsListIsEmpty()
    {
        // Arrange
        var result = new AuditResult
        {
            TargetUrl = "opc.tcp://localhost:4840",
            Timestamp = DateTime.UtcNow,
            Duration = TimeSpan.Zero,
            DiscoveredEndpoints = [],
            Findings = []
        };

        // Assert
        result.CriticalCount.ShouldBe(0);
        result.WarningCount.ShouldBe(0);
        result.InfoCount.ShouldBe(0);
    }

    [Fact]
    public void ServerInfo_IsNullByDefault_WhenNotProvided()
    {
        // Arrange
        var result = new AuditResult
        {
            TargetUrl = "opc.tcp://localhost:4840",
            Timestamp = DateTime.UtcNow,
            Duration = TimeSpan.Zero,
            DiscoveredEndpoints = [],
            Findings = []
        };

        // Assert
        result.ServerInfo.ShouldBeNull();
    }
}
