using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for user events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record creation of a new user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserCreated(
        string message,
        string? userId,
        string? newUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        params object?[] args)
    {
        LogUserCreated(message, userId, newUserId, attributes, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record creation of a new user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserCreated(
        string message,
        string? userId,
        string? newUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedAttributes = attributes is not null
            ? string.Join(",", attributes?.Select(kvp => $"{kvp.Key}:{string.Join(",", kvp.Value)}"))
            : null;

        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserCreated, userId, newUserId, commaSeparatedAttributes);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record update of a user's attributes.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserUpdated(
        string message,
        string? userId,
        string? onUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        params object?[] args)
    {
        LogUserUpdated(message, userId, onUserId, attributes, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record update of a user's attributes.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserUpdated(
        string message,
        string? userId,
        string? onUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedAttributes = attributes is not null
            ? string.Join(",", attributes.Select(kvp => $"{kvp.Key}:{string.Join(",", kvp.Value)}"))
            : null;

        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserUpdated, userId, onUserId, commaSeparatedAttributes);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record archiving of a user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserArchived(
        string message,
        string? userId,
        string? onUserId,
        params object?[] args)
    {
        LogUserArchived(message, userId, onUserId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record archiving of a user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserArchived(
        string message,
        string? userId,
        string? onUserId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserArchived, userId, onUserId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record deletion of a user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserDeleted(
        string message,
        string? userId,
        string? onUserId,
        params object?[] args)
    {
        LogUserDeleted(message, userId, onUserId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record deletion of a user.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogUserDeleted(
        string message,
        string? userId,
        string? onUserId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserDeleted, userId, onUserId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
