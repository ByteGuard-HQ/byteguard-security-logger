using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for input events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record an input validation failed event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogInputValidationFailed(
        string message,
        IEnumerable<string>? fields,
        string? userId,
        params object?[] args)
    {
        LogInputValidationFailed(message, fields, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an input validation failed event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogInputValidationFailed(
        string message,
        IEnumerable<string>? fields,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedFields = fields is not null
            ? string.Join(", ", fields)
            : null;

        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.InputValidationFailed, commaSeparatedFields, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a discrete input validation fail.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogInputValidationDiscreteFail(
        string message,
        string? field,
        string? userId,
        params object?[] args)
    {
        LogInputValidationDiscreteFail(message, field, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a discrete input validation fail.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogInputValidationDiscreteFail(
        string message,
        string? field,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.InputValidationDiscreteFail, field, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
