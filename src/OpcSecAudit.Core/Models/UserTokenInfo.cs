namespace OpcSecAudit.Core.Models;

/// <summary>
/// Represents a user identity token policy on an endpoint.
/// </summary>
public class UserTokenInfo
{
    /// <summary>
    /// Gets the token type (Anonymous, UserName, Certificate, IssuedToken).
    /// </summary>
    public required string TokenType { get; init; }

    /// <summary>
    /// Gets the security policy URI for this token. Null if not specified.
    /// </summary>
    public string? SecurityPolicyUri { get; init; }
}
