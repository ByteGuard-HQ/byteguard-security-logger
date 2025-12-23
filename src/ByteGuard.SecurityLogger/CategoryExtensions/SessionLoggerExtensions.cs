using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogegr extensions for session events.
/// </summary>
public static class SessionLoggerExtensions
{
    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreated(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionCreated(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session creation.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreated(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionCreated, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewed(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionRenewed(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session renewal.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewed(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionRenewed, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record session expiration.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpired(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        params object?[] args)
    {
        logger.LogSessionExpired(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record session expiration.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpired(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionExpired, userId, reason);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpire(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionUseAfterExpire(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record attempt to use an expired session.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpire(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionUseAfterExpire, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }
}
