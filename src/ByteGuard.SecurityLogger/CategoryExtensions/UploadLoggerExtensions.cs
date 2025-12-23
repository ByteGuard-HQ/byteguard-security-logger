using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for upload events.
/// </summary>
public static class UploadLoggerExtensions
{
    /// <summary>
    /// Record a successful upload event.
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
    /// Record a successful upload event.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record a successful file storage event.
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
    /// Record a successful file storage event.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }

    /// <summary>
    /// Record the results of a file validation process.
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
    /// Record the results of a file validation process.
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

        SecurityLoggerExtensions.Log(logger, evt, level, message, metadata, args);
    }

    /// <summary>
    /// Record a file deletion event.
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
    /// Record a file deletion event.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Information, message, metadata, args);
    }
}
