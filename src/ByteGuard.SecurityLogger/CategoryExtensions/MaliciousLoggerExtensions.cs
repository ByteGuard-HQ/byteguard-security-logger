using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// ILogger extensions for malicious events.
/// </summary>
public static class MaliciousLoggerExtensions
{
    /// <summary>
    /// Record excessive 404 errors.
    /// </summary>
    /// <remarks>
    /// Could indicate a reconnaissance attempt or automated attack.
    /// </remarks>
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
    /// Record excessive 404 errors.
    /// </summary>
    /// <remarks>
    /// Could indicate a reconnaissance attempt or automated attack.
    /// </remarks>
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record unexpected input or extraneous data.
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
    /// Record unexpected input or extraneous data.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record detection of attack tool usage.
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
    /// Record detection of attack tool usage.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a CORS violation attempt.
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
    /// Record a CORS violation attempt.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a direct object reference attempt.
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
    /// Record a direct object reference attempt.
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

        SecurityLoggerExtensions.Log(logger, evt, LogLevel.Critical, message, metadata, args);
    }
}
