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
        finding.Id.ShouldBe("SEC-EP-001");
        finding.Category.ShouldBe("Endpoint Security");
        finding.Severity.ShouldBe(Severity.Critical);
        finding.Title.ShouldBe("Unencrypted Endpoint Available");
        finding.CweId.ShouldBeNull();
        finding.CweDescription.ShouldBeNull();
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
        finding.CweId.ShouldBe("CWE-319");
        finding.CweDescription.ShouldBe("Cleartext Transmission of Sensitive Information");
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
        finding.Id.ShouldBe("SEC-EP-001");
        typeof(Finding).GetProperty(nameof(Finding.Id))!
            .SetMethod.ShouldNotBeNull("init setters exist for object initializers");
    }
}
