using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for cryptography events.
/// </summary>
public static class CryptLoggerExtensions
{
    /// <summary>
    /// Record a decryption failure event.
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
    /// Record a decryption failure event.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an encryption failure event.
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
    /// Record an encryption failure event.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }
}
