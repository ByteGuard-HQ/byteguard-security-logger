using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for excess events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record a rate limit or service limit being exceeded event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogExcessRateLimitExceeded(
        string message,
        string? userId,
        int? max,
        params object?[] args)
    {
        LogExcessRateLimitExceeded(message, userId, max, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a rate limit or service limit being exceeded event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogExcessRateLimitExceeded(
        string message,
        string? userId,
        int? max,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.ExcessRateLimitExceeded, userId, max?.ToString());
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
