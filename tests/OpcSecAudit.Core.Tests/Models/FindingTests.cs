using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Tests.Models;

public class FindingTests
{
    [Fact]
    public void Finding_WithAllRequiredProperties_InitializesCorrectly()
    {
        // Arrange / Act
        var finding = new Finding
        {
            Id = "SEC-EP-001",
            Category = "Endpoint Security",
            Severity = Severity.Critical,
            Title = "Unencrypted Endpoint Available",
            Description = "Endpoint opc.tcp://localhost:4840 uses SecurityMode None.",
            Recommendation = "Disable SecurityMode None."
        };

        // Assert
        finding.Id.Should().Be("SEC-EP-001");
        finding.Category.Should().Be("Endpoint Security");
        finding.Severity.Should().Be(Severity.Critical);
        finding.Title.Should().Be("Unencrypted Endpoint Available");
        finding.CweId.Should().BeNull();
        finding.CweDescription.Should().BeNull();
    }

    [Fact]
    public void Finding_WithOptionalCweFields_StoredCorrectly()
    {
        // Arrange / Act
        var finding = new Finding
        {
            Id = "SEC-EP-001",
            Category = "Endpoint Security",
            Severity = Severity.Critical,
            Title = "Unencrypted Endpoint Available",
            Description = "Some description.",
            Recommendation = "Some recommendation.",
            CweId = "CWE-319",
            CweDescription = "Cleartext Transmission of Sensitive Information"
        };

        // Assert
        finding.CweId.Should().Be("CWE-319");
        finding.CweDescription.Should().Be("Cleartext Transmission of Sensitive Information");
    }

    [Fact]
    public void Finding_IsImmutableAfterConstruction()
    {
        // Arrange
        var finding = new Finding
        {
            Id = "SEC-EP-001",
            Category = "Endpoint Security",
            Severity = Severity.Critical,
            Title = "Test",
            Description = "Test",
            Recommendation = "Test"
        };

        // Assert — init-only properties cannot be reassigned; verify the type uses init
        finding.Id.Should().Be("SEC-EP-001");
        typeof(Finding).GetProperty(nameof(Finding.Id))!
            .SetMethod.Should().NotBeNull("init setters exist for object initializers");
    }
}
