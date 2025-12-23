using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for sequence events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record a sequence error (unexpected order of action).
    /// </summary>
    /// <remarks>
    /// Could indicate intentional abuse of the business logic.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSequenceFail(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSequenceFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a sequence error (unexpected order of action).
    /// </summary>
    /// <remarks>
    /// Could indicate intentional abuse of the business logic.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSequenceFail(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SequenceFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }
}
