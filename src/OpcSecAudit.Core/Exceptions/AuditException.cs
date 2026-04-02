namespace OpcSecAudit.Core.Exceptions;

/// <summary>
/// Exception thrown when an audit operation fails.
/// </summary>
public class AuditException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class.
    /// </summary>
    public AuditException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public AuditException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public AuditException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
