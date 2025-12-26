using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for authentication events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginSuccess(
        string message,
        string? userId,
        params object?[] args)
    {
        LogAuthnLoginSuccess(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginSuccess(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccess, userId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginSuccessAfterFail(
        string message,
        string? userId,
        int? retries,
        params object?[] args)
    {
        LogAuthnLoginSuccessAfterFail(message, userId, retries, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginSuccessAfterFail(
        string message,
        string? userId,
        int? retries,
        SecurityEventMetadata? metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccessAfterFail, userId, retries?.ToString());
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginFail(
        string message,
        string? userId,
        params object?[] args)
    {
        LogAuthnLoginFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginFail(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginFailMax(
        string message,
        string? userId,
        int? maxLimit,
        params object?[] args)
    {
        LogAuthnLoginFailMax(message, userId, maxLimit, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginFailMax(
        string message,
        string? userId,
        int? maxLimit,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, maxLimit]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFailMax, userId, maxLimit?.ToString());
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginLock(
        string message,
        string? userId,
        string? reason,
        params object?[] args)
    {
        LogAuthnLoginLock(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnLoginLock(
        string message,
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, reason]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginLock, userId, reason);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnPasswordChange(
        string message,
        string? userId,
        params object?[] args)
    {
        LogAuthnPasswordChange(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnPasswordChange(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChange, userId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnPasswordChangeFail(
        string message,
        string? userId,
        params object?[] args)
    {
        LogAuthnPasswordChangeFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnPasswordChangeFail(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChangeFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnImpossibleTravel(
        string message,
        string? userId,
        string? regionOne,
        string? regionTwo,
        params object?[] args)
    {
        LogAuthnImpossibleTravel(message, userId, regionOne, regionTwo, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnImpossibleTravel(
        string message,
        string? userId,
        string? regionOne,
        string? regionTwo,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, regionOne, regionTwo]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnImpossibleTravel, userId, regionOne, regionTwo);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenCreated(
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        params object?[] args)
    {
        LogAuthnTokenCreated(message, userId, entitlements, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenCreated(
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedEntitlements = entitlements is not null
            ? string.Join(",", entitlements)
            : null;

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenCreated, userId, commaSeparatedEntitlements);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenRevoked(
        string message,
        string? userId,
        string? tokenId,
        params object?[] args)
    {
        LogAuthnTokenRevoked(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenRevoked(
        string message,
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenRevoked, userId, tokenId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenReuse(
        string message,
        string? userId,
        string? tokenId,
        params object?[] args)
    {
        LogAuthnTokenReuse(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenReuse(
        string message,
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenReuse, userId, tokenId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenDelete(
        string message,
        string? userId,
        params object?[] args)
    {
        LogAuthnTokenDelete(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogAuthnTokenDelete(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenDelete, userId);
        metadata ??= new SecurityEventMetadata();

        Log(@event, LogLevel.Warning, message, metadata, args);
    }
}
