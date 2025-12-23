using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for cryptography events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record a decryption failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogCryptDecryptFail(
        string message,
        string? userId,
        params object?[] args)
    {
        LogCryptDecryptFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a decryption failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogCryptDecryptFail(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.CryptDecryptFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record an encryption failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogCryptEncryptFail(
        string message,
        string? userId,
        params object?[] args)
    {
        LogCryptEncryptFail(message, userId, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record an encryption failure event.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="userId">User identifier.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogCryptEncryptFail(
        string message,
        string? userId,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.CryptEncryptFail, userId);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }
}
