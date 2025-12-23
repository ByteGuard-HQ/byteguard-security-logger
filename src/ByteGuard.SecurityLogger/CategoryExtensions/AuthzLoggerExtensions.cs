using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for authorization events.
/// </summary>
public static class AuthzLoggerExtensions
{
    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzFail(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        logger.LogAuthzFail(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzFail(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzFail, userId, resource);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzChange(
        this ILogger logger,
        string message,
        string? userId,
        string? from,
        string? to,
        params object?[] args)
    {
        logger.LogAuthzChange(message, userId, from, to, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzChange(
        this ILogger logger,
        string message,
        string? userId,
        string? from,
        string? to,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzChange, userId, from, to);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an authorized administration event (e.g. user privilege change).
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="event">Event description.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzAdmin(
        this ILogger logger,
        string message,
        string? userId,
        string? @event,
        params object?[] args)
    {
        logger.LogAuthzAdmin(message, userId, @event, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an authorized administration event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="event">Event description.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzAdmin(
        this ILogger logger,
        string message,
        string? userId,
        string? @event,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzAdmin, userId, @event);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }
}
