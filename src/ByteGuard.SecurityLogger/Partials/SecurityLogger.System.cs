using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for system events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysStartup(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSysStartup(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system startup event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysStartup(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysStartup, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysShutdown(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSysShutdown(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system shutdown event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysShutdown(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysShutdown, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysRestart(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSysRestart(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system restart event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysRestart(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysRestart, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysCrash(
        string message,
        string? userId,
        params object?[] args)
    {
        LogSysCrash(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a system crash event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysCrash(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysCrash, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysMonitorDisabled(
        string message,
        string? userId,
        string? monitor,
        params object?[] args)
    {
        LogSysMonitorDisabled(message, userId, monitor, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record disabling of a system monitor.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysMonitorDisabled(
        string message,
        string? userId,
        string? monitor,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysMonitorDisabled, userId, monitor);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysMonitorEnabled(
        string message,
        string? userId,
        string? monitor,
        params object?[] args)
    {
        LogSysMonitorEnabled(message, userId, monitor, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record enabling of a system monitor.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="monitor">Monitor name.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSysMonitorEnabled(
        string message,
        string? userId,
        string? monitor,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SysMonitorEnabled, userId, monitor);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
