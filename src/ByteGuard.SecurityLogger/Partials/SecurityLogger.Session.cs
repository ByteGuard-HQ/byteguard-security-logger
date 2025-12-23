using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for session events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionCreated(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSessionCreated(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionCreated(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionCreated, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionRenewed(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSessionRenewed(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionRenewed(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionRenewed, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record session expiration.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionExpired(
        string message,
        string? userId,
        string? reason,
        params object?[] args)
    {
        LogSessionExpired(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session expiration.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionExpired(
        string message,
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionExpired, userId, reason);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionUseAfterExpire(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSessionUseAfterExpire(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSessionUseAfterExpire(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionUseAfterExpire, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }
}
