using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security specific ILogging extensions.
/// </summary>
public static class SecurityLoggerExtensions
{
    /// <summary>
    /// Login success.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogAuthnLoginSuccess(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Login success.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccess(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = $"{LoggingVocabulary.AuthnLoginSuccess}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Login success after previous fail.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="retries">Number of retries before success.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginSuccessAfterFail(
        this ILogger logger,
        string message,
        string userId,
        int retries,
        params object?[] args)
    {
        logger.LogAuthnLoginSuccessAfterFail(message, userId, retries, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Login success after previous fail.
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
        string userId,
        int retries,
        SecurityEventMetadata? metadata,
        params object?[] args)
    {
        var @event = $"{LoggingVocabulary.AuthnLoginSuccessAfterFail}:{userId}, {retries}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Information, message, metadata, args);
    }/// <summary>
     /// Login failed.
     /// </summary>
     /// <param name="logger">Logger implementation.</param>
     /// <param name="message">Log message.</param>
     /// <param name="userId">User identifier.</param>
     /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogAuthnLoginFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Login failed.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFail(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnLoginFail}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Login failed after retry limit.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="maxLimit">Max limit of retries.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginFailMax(
        this ILogger logger,
        string message,
        string userId,
        int maxLimit,
        params object?[] args)
    {
        logger.LogAuthnLoginFailMax(message, userId, maxLimit, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Login failed after retry limit.
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
        string userId,
        int maxLimit,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, maxLimit]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnLoginFailMax}:{userId},{maxLimit}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Login locked.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Lock reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnLoginLock(
        this ILogger logger,
        string message,
        string userId,
        string reason,
        params object?[] args)
    {
        logger.LogAuthnLoginLock(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Login locked.
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
        string userId,
        string reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, reason]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnLoginLock}:{userId},{reason}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Password changed.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogAuthnPasswordChange(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Password changed.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChange(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnPasswordChange}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Password change failed.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogAuthnPasswordChangeFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Password change failed.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnPasswordChangeFail(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnPasswordChangeFail}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Impossible travel.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="regionOne">First region.</param>
    /// <param name="regionTwo">Second region.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnImpossibleTravel(
        this ILogger logger,
        string message,
        string userId,
        string regionOne,
        string regionTwo,
        params object?[] args)
    {
        logger.LogAuthnImpossibleTravel(message, userId, regionOne, regionTwo, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Impossible travel.
    /// </summary>
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
        string userId,
        string regionOne,
        string regionTwo,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, regionOne, regionTwo]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnImpossibleTravel}:{userId},{regionOne},{regionTwo}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Token created.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="entitlements">Entitlements (e.g. create, read, update, etc.).</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenCreated(
        this ILogger logger,
        string message,
        string userId,
        IEnumerable<string> entitlements,
        params object?[] args)
    {
        logger.LogAuthnTokenCreated(message, userId, entitlements, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Token created.
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
        string userId,
        IEnumerable<string> entitlements,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedEntitlements = entitlements is not null
            ? string.Join(", ", entitlements)
            : null;

        args = args.Concat([userId, commaSeparatedEntitlements]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnTokenCreated}:{userId},{commaSeparatedEntitlements}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Token revoked.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenRevoked(
        this ILogger logger,
        string message,
        string userId,
        string tokenId,
        params object?[] args)
    {
        logger.LogAuthnTokenRevoked(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Token revoked.
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
        string userId,
        string tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnTokenRevoked}:{userId},{tokenId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Token reuse.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="tokenId">Token identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenReuse(
        this ILogger logger,
        string message,
        string userId,
        string tokenId,
        params object?[] args)
    {
        logger.LogAuthnTokenReuse(message, userId, tokenId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Token reuse.
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
        string userId,
        string tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnTokenReuse}:{userId},{tokenId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Token delete.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogAuthnTokenDelete(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Token delete.
    /// </summary>
    /// <param name="logger">Logger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User/service identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthnTokenDelete(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = $"{LoggingVocabulary.AuthnTokenReuse}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Authorization fail.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="resource">Resource identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzFail(
        this ILogger logger,
        string message,
        string userId,
        string resource,
        params object?[] args)
    {
        logger.LogAuthzFail(message, userId, resource, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Authorization fail.
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
        string userId,
        string resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = $"{LoggingVocabulary.AuthzFail}:{userId},{resource}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Authorization change.
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
        string userId,
        string from,
        string to,
        params object?[] args)
    {
        logger.LogAuthzChange(message, userId, from, to, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Authorization change.
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
        string userId,
        string from,
        string to,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = $"{LoggingVocabulary.AuthzChange}:{userId},{from},{to}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, @event, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Authorization admin event.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="event">Event description.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogAuthzAdmin(
        this ILogger logger,
        string message,
        string userId,
        string @event,
        params object?[] args)
    {
        logger.LogAuthzAdmin(message, userId, @event, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Authorization admin event.
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
        string userId,
        string @event,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = $"{LoggingVocabulary.AuthzAdmin}:{userId},{@event}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Decryption failure.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptDecryptFail(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogCryptDecryptFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Decryption failure.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptDecryptFail(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = $"{LoggingVocabulary.CryptDecryptFail}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Encryption failure.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptEncryptFail(
        this ILogger logger,
        string message,
        string userId,
        params object?[] args)
    {
        logger.LogCryptEncryptFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Encryption failure.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogCryptEncryptFail(
        this ILogger logger,
        string message,
        string userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = $"{LoggingVocabulary.CryptEncryptFail}:{userId}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Rate limit exceeded.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogExcessRateLimitExceeded(
        this ILogger logger,
        string message,
        string userId,
        int max,
        params object?[] args)
    {
        logger.LogExcessRateLimitExceeded(message, userId, max, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Rate limit exceeded.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="max">Maximum allowed requests.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogExcessRateLimitExceeded(
        this ILogger logger,
        string message,
        string userId,
        int max,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = $"{LoggingVocabulary.ExcessRateLimitExceeded}:{userId}:{max}";
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Generic log method.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="event">Security event.</param>
    /// <param name="level">Log level.</param>
    /// <param name="message">Log message.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void Log(ILogger logger, string @event, LogLevel level, string message, SecurityEventMetadata metadata, params object?[] args)
    {
        var properties = new Dictionary<string, object?>
        {
            ["AppId"] = "",
            ["Event"] = @event
        };

        PropertiesEnricher.PopulatePropertiesFromMetadata(properties, metadata);

        using var _ = logger.BeginScope(properties);

        logger.Log(level, new EventId(1001, "authn_login_success"), message, args);
    }
}
