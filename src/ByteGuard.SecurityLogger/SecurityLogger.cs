using Microsoft.Extensions.Logging;
using ByteGuard.SecurityLogger.Enrichers;

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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccess, userId);
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
        string? userId,
        int? retries,
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
        string? userId,
        int? retries,
        SecurityEventMetadata? metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginSuccessAfterFail, userId, retries?.ToString());
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFail, userId);
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
        string? userId,
        int? maxLimit,
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
        string? userId,
        int? maxLimit,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, maxLimit]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginFailMax, userId, maxLimit?.ToString());
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
        string? userId,
        string? reason,
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
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, reason]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnLoginLock, userId, reason);
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChange, userId);
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnPasswordChangeFail, userId);
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
        string? userId,
        string? regionOne,
        string? regionTwo,
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
        string? userId,
        string? regionOne,
        string? regionTwo,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, regionOne, regionTwo]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnImpossibleTravel, userId, regionOne, regionTwo);
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
        string? userId,
        IEnumerable<string>? entitlements,
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
        string? userId,
        string? tokenId,
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
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenRevoked, userId, tokenId);
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
        string? userId,
        string? tokenId,
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
        string? userId,
        string? tokenId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId, tokenId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenReuse, userId, tokenId);
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        args = args.Concat([userId]).ToArray();

        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthnTokenDelete, userId);
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
        string? userId,
        string? resource,
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
        string? userId,
        string? resource,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzFail, userId, resource);
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
        string? userId,
        string? from,
        string? to,
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
        string? userId,
        string? from,
        string? to,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var @event = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzChange, userId, from, to);
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
        string? userId,
        string? @event,
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
        string? userId,
        string? @event,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.AuthzAdmin, userId, @event);
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.CryptDecryptFail, userId);
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
        string? userId,
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
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.CryptEncryptFail, userId);
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
        string? userId,
        int? max,
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
        string? userId,
        int? max,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.ExcessRateLimitExceeded, userId, max?.ToString());
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Upload completed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileName">File name.</param>
    /// <param name="fileType">File type.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadComplete(
        this ILogger logger,
        string message,
        string? userId,
        string? fileName,
        string? fileType,
        params object?[] args)
    {
        logger.LogUploadComplete(message, userId, fileName, fileType, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Upload completed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileName">File name.</param>
    /// <param name="fileType">File type.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadComplete(
        this ILogger logger,
        string message,
        string? userId,
        string? fileName,
        string? fileType,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UploadComplete, userId, fileName, fileType);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Upload stored.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original storage location.</param>
    /// <param name="to">New storage location.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadStored(
        this ILogger logger,
        string message,
        string? userId,
        string? from,
        string? to,
        params object?[] args)
    {
        logger.LogUploadStored(message, userId, from, to, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Upload stored.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="from">Original storage location.</param>
    /// <param name="to">New storage location.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadStored(
        this ILogger logger,
        string message,
        string? userId,
        string? from,
        string? to,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UploadStored, userId, from, to);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Upload validation.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="filename">File name.</param>
    /// <param name="validationType">Validation type (e.g. virusscan, signature, size, etc.).</param>
    /// <param name="result">Validation result (e.g. FAILED, incomplete, passed).</param>
    /// <param name="level">Log level.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadValidation(
        this ILogger logger,
        string message,
        string? userId,
        string? filename,
        string? validationType,
        string? result,
        LogLevel level,
        params object?[] args)
    {
        logger.LogUploadValidation(message, userId, filename, validationType, result, level, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Upload validation.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="filename">File name.</param>
    /// <param name="validationType">Validation type (e.g. virusscan, signature, size, etc.).</param>
    /// <param name="result">Validation result (e.g. FAILED, incomplete, passed).</param>
    /// <param name="level">Log level.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadValidation(
        this ILogger logger,
        string message,
        string? userId,
        string? filename,
        string? validationType,
        string? result,
        LogLevel level,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UploadValidation, userId, filename, validationType, result);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, level, message, metadata, args);
    }

    /// <summary>
    /// Upload deleted.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileId">File identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadDelete(
        this ILogger logger,
        string message,
        string? userId,
        string? fileId,
        params object?[] args)
    {
        logger.LogUploadDelete(message, userId, fileId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Upload deleted.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="fileId">File identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUploadDelete(
        this ILogger logger,
        string message,
        string? userId,
        string? fileId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UploadDelete, userId, fileId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Input validation failed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationFailed(
        this ILogger logger,
        string message,
        IEnumerable<string>? fields,
        string? userId,
        params object?[] args)
    {
        logger.LogInputValidationFailed(message, fields, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Input validation failed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="fields">Invalid fields.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationFailed(
        this ILogger logger,
        string message,
        IEnumerable<string>? fields,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var commaSeparatedFields = fields is not null
            ? string.Join(", ", fields)
            : null;

        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.InputValidationFailed, commaSeparatedFields, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Input validation discrete fail.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationDiscreteFail(
        this ILogger logger,
        string message,
        string? field,
        string? userId,
        params object?[] args)
    {
        logger.LogInputValidationDiscreteFail(message, field, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Input validation discrete fail.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="field">Invalid field.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogInputValidationDiscreteFail(
        this ILogger logger,
        string message,
        string? field,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.InputValidationDiscreteFail, field, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Malicious excess 404.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExcess404(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        params object?[] args)
    {
        logger.LogMaliciousExcess404(message, ipAddress, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Malicious excess 404.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExcess404(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousExcess404, ipAddress, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Malicious extraneous.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExtraneous(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        params object?[] args)
    {
        logger.LogMaliciousExtraneous(message, ipAddress, inputName, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Malicious extraneous.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousExtraneous(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousExtraneous, ipAddress, inputName, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Malicious attack tool.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousAttackTool(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        params object?[] args)
    {
        logger.LogMaliciousAttackTool(message, ipAddress, toolName, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Malicious attack tool.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousAttackTool(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousAttackTool, ipAddress, toolName, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Malicious CORS.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousCors(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        string? referrer,
        params object?[] args)
    {
        logger.LogMaliciousCors(message, ipAddress, useragent, referrer, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Malicious CORS.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousCors(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        string? referrer,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousCors, ipAddress, useragent, referrer);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Malicious direct reference.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousDirectReference(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        params object?[] args)
    {
        logger.LogMaliciousDirectReference(message, ipAddress, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Malicious direct reference.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogMaliciousDirectReference(
        this ILogger logger,
        string message,
        string? ipAddress,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousDirectReference, ipAddress, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Privilege permissions changed.
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
    /// Privilege permissions changed.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Sensitive create.
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
    /// Sensitive create.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Sensitive read.
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
    /// Sensitive read.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Sensitive update.
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
    /// Sensitive update.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Sensitive delete.
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
    /// Sensitive delete.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Sequence fail.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSequenceFail(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSequenceFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Sequence fail.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSequenceFail(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SequenceFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Session created.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreated(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionCreated(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Session created.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionCreated(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionCreated, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Session renewed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewed(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionRenewed(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Session renewed.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionRenewed(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionRenewed, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Session expired.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpired(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        params object?[] args)
    {
        logger.LogSessionExpired(message, userId, reason, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Session expired.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="reason">Expiration reason.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionExpired(
        this ILogger logger,
        string message,
        string? userId,
        string? reason,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionExpired, userId, reason);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Session use after expire.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpire(
        this ILogger logger,
        string message,
        string? userId,
        params object?[] args)
    {
        logger.LogSessionUseAfterExpire(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Session use after expire.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogSessionUseAfterExpire(
        this ILogger logger,
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.SessionUseAfterExpire, userId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// System startup.
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
    /// System startup.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// System shutdown.
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
    /// System shutdown.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// System restart.
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
    /// System restart.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// System crash.
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
    /// System crash.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// System monitor disabled.
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
    /// System monitor disabled.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// System monitor enabled.
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
    /// System monitor enabled.
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// User created.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserCreated(
        this ILogger logger,
        string message,
        string? userId,
        string? newUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        params object?[] args)
    {
        logger.LogUserCreated(message, userId, newUserId, attributes, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// User created.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="newUserId">New user identifier.</param>
    /// <param name="attributes">New user attributes.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserCreated(
        this ILogger logger,
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// User updated.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserUpdated(
        this ILogger logger,
        string message,
        string? userId,
        string? onUserId,
        Dictionary<string, IEnumerable<string>>? attributes,
        params object?[] args)
    {
        logger.LogUserUpdated(message, userId, onUserId, attributes, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// User updated.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="attributes">User attributes.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserUpdated(
        this ILogger logger,
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

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// User archived.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserArchived(
        this ILogger logger,
        string message,
        string? userId,
        string? onUserId,
        params object?[] args)
    {
        logger.LogUserArchived(message, userId, onUserId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// User archived.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserArchived(
        this ILogger logger,
        string message,
        string? userId,
        string? onUserId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserArchived, userId, onUserId);
        metadata ??= new SecurityEventMetadata();

        Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// User deleted.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserDeleted(
        this ILogger logger,
        string message,
        string? userId,
        string? onUserId,
        params object?[] args)
    {
        logger.LogUserDeleted(message, userId, onUserId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// User deleted.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="onUserId">On user identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public static void LogUserDeleted(
        this ILogger logger,
        string message,
        string? userId,
        string? onUserId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.UserDeleted, userId, onUserId);
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
