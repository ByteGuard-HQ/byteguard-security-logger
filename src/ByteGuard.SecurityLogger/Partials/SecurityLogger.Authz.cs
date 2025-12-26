using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for authorization events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzFail(
        string message,
        string? userId,
        string? resource,
        params object?[] args)
    {
        LogAuthzFail(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record and authorization failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzFail(
        string message,
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzFail, userId, resource);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzChange(
        string message,
        string? userId,
        string? from,
        string? to,
        params object?[] args)
    {
        LogAuthzChange(message, userId, from, to, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an authorization change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original authorization.</param>
    /// <param name="to">New authorization.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzChange(
        string message,
        string? userId,
        string? from,
        string? to,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzChange, userId, from, to);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an authorized administration event (e.g. user privilege change).
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="event">Event description.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzAdmin(
        string message,
        string? userId,
        string? @event,
        params object?[] args)
    {
        LogAuthzAdmin(message, userId, @event, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an authorized administration event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="event">Event description.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthzAdmin(
        string message,
        string? userId,
        string? @event,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzAdmin, userId, @event);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
