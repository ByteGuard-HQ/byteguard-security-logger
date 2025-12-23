using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for privilege events.
/// </summary>
public static class PrivilegeLoggerExtensions
{
    /// <summary>
    /// Record a permission level change.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="fromLevel">Original privilege level.</param>
    /// <param name="toLevel">New privilege level.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogPrivilegePermissionsChanged(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        string? fromLevel,
        string? toLevel,
        params object?[] args)
    {
        logger.LogPrivilegePermissionsChanged(message, userId, resource, fromLevel, toLevel, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a permission level change.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="fromLevel">Original privilege level.</param>
    /// <param name="toLevel">New privilege level.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogPrivilegePermissionsChanged(
        this ILogger logger,
        string message,
        string? userId,
        string? resource,
        string? fromLevel,
        string? toLevel,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.PrivilegePermissionsChanged, userId, resource, fromLevel, toLevel);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }
}
