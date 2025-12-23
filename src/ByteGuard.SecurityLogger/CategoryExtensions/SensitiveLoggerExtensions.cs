using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for sensitive data events.
/// </summary>
public static class SensitiveLoggerExtensions
{
    /// <summary>
    /// record creation of a sensitive object.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveCreate(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        logger.LogSensitiveCreate(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record creation of a sensitive object.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveCreate(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveCreate, userId, resource);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveRead(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        logger.LogSensitiveRead(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveRead(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveRead, userId, resource);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveUpdate(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        logger.LogSensitiveUpdate(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveUpdate(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveUpdate, userId, resource);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record deletion of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveDelete(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        logger.LogSensitiveDelete(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// REcord deletion of sensitive data.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSensitiveDelete(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveDelete, userId, resource);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }
}
