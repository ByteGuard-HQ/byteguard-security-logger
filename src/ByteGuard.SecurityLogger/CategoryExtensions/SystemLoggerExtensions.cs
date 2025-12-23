using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for system events.
/// </summary>
public static class SystemLoggerExtensions
{
    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysStartup(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSysStartup(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysStartup(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysStartup, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysShutdown(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSysShutdown(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysShutdown(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysShutdown, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysRestart(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSysRestart(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysRestart(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysRestart, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysCrash(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSysCrash(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysCrash(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysCrash, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorDisabled(
        this ILogger logger,
        string message,
        string? userId,
        string? monitor,
        params object?[] args)
    {
        logger.LogSysMonitorDisabled(message, userId, monitor, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorDisabled(
        this ILogger logger,
        string message,
        string? userId,
        string? monitor,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysMonitorDisabled, userId, monitor);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorEnabled(
        this ILogger logger,
        string message,
        string? userId,
        string? monitor,
        params object?[] args)
    {
        logger.LogSysMonitorEnabled(message, userId, monitor, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSysMonitorEnabled(
        this ILogger logger,
        string message,
        string? userId,
        string? monitor,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysMonitorEnabled, userId, monitor);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }
}
