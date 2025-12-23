using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for sensitive data events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// record creation of a sensitive object.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveCreate(
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        LogSensitiveCreate(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record creation of a sensitive object.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveCreate(
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveCreate, userId, resource);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveRead(
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        LogSensitiveRead(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record access (read) of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveRead(
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveRead, userId, resource);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveUpdate(
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        LogSensitiveUpdate(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record modification of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveUpdate(
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveUpdate, userId, resource);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record deletion of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveDelete(
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        LogSensitiveDelete(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record deletion of sensitive data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogSensitiveDelete(
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SensitiveDelete, userId, resource);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
