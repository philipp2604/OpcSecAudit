using OpcSecAudit.Core.Models;

namespace OpcSecAudit.Core.Tests.Models;

public class SeverityTests
{
    [Fact]
    public void Severity_HasThreeExpectedValues()
    {
        var values = Enum.GetValues<Severity>();

        values.Length.ShouldBe(3);
        values.ShouldContain(Severity.Info);
        values.ShouldContain(Severity.Warning);
        values.ShouldContain(Severity.Critical);
    }

    [Fact]
    public void Severity_InfoIsLowestOrdinal()
    {
        ((int)Severity.Info).ShouldBeLessThan((int)Severity.Warning);
        ((int)Severity.Warning).ShouldBeLessThan((int)Severity.Critical);
    }
}
