using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Tests.Models;

public class SeverityTests
{
    [Fact]
    public void Severity_HasThreeExpectedValues()
    {
        var values = Enum.GetValues<Severity>();

        values.Should().HaveCount(3);
        values.Should().Contain(Severity.Info);
        values.Should().Contain(Severity.Warning);
        values.Should().Contain(Severity.Critical);
    }

    [Fact]
    public void Severity_InfoIsLowestOrdinal()
    {
        ((int)Severity.Info).Should().BeLessThan((int)Severity.Warning);
        ((int)Severity.Warning).Should().BeLessThan((int)Severity.Critical);
    }
}
