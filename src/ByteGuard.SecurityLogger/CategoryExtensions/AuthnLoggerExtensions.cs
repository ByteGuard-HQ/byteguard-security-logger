using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for authentication events.
/// </summary>
public static class AuthnLoggerExtensions
{
    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogAuthnLoginSuccess(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful login event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccess, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccessAfterFail(
        this ILogger logger,
        string message,
        string? userId,
        int? retries,
        params object?[] args)
    {
        logger.LogAuthnLoginSuccessAfterFail(message, userId, retries, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful login event after a previous failure.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccessAfterFail(
        this ILogger logger,
        string message,
        string? userId,
        int? retries,
        SecurityEventMetadata? metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccessAfterFail, userId, retries?.ToString());
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogAuthnLoginFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed login event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFail, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFailMax(
        this ILogger logger,
        string message,
        string? userId,
        int? maxLimit,
        params object?[] args)
    {
        logger.LogAuthnLoginFailMax(message, userId, maxLimit, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed login limit being reached event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFailMax(
        this ILogger logger,
        string message,
        string? userId,
        int? maxLimit,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, maxLimit]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFailMax, userId, maxLimit?.ToString());
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginLock(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        params object?[] args)
    {
        logger.LogAuthnLoginLock(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an account lockout event (e.g. due to multiple failed login attempts).
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginLock(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, reason]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginLock, userId, reason);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogAuthnPasswordChange(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a successful password change event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChange, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogAuthnPasswordChangeFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a failed password change event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChangeFail, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnImpossibleTravel(
        this ILogger logger,
        string message,
        string? userId,
        string? regionOne,
        string? regionTwo,
        params object?[] args)
    {
        logger.LogAuthnImpossibleTravel(message, userId, regionOne, regionTwo, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a user logged in from one city suddenly appearing in another, too far away.
    /// </summary>
    /// <remarks>
    /// This often indicates and account takeover.
    /// </remarks>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnImpossibleTravel(
        this ILogger logger,
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

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenCreated(
        this ILogger logger,
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        params object?[] args)
    {
        logger.LogAuthnTokenCreated(message, userId, entitlements, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token creation event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenCreated(
        this ILogger logger,
        string message,
        string? userId,
        IEnumerable<string>? entitlements,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedEntitlements = entitlements is not null
            ? string.Join(", ", entitlements)
            : null;

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenCreated, userId, commaSeparatedEntitlements);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenRevoked(
        this ILogger logger,
        string message,
        string? userId,
        string? tokenId,
        params object?[] args)
    {
        logger.LogAuthnTokenRevoked(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token revocation event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenRevoked(
        this ILogger logger,
        string message,
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenRevoked, userId, tokenId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenReuse(
        this ILogger logger,
        string message,
        string? userId,
        string? tokenId,
        params object?[] args)
    {
        logger.LogAuthnTokenReuse(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an attempted token reuse event after a token has been revoked.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenReuse(
        this ILogger logger,
        string message,
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenReuse, userId, tokenId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogAuthnTokenDelete(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a token deletion event.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenDelete, userId);
        metadata ??= new SecurityEventMetadata();

        SecurityLoggerExtensions.Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }
}
