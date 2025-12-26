using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security logger functionality for malicious events.
/// </summary>
public partial class SecurityLogger
{
    /// <summary>
    /// Record excessive 404 errors.
    /// </summary>
    /// <remarks>
    /// Could indicate a reconnaissance attempt or automated attack.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousExcess404(
        string message,
        string? ipAddress,
        string? useragent,
        params object?[] args)
    {
        LogMaliciousExcess404(message, ipAddress, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record excessive 404 errors.
    /// </summary>
    /// <remarks>
    /// Could indicate a reconnaissance attempt or automated attack.
    /// </remarks>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousExcess404(
        string message,
        string? ipAddress,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousExcess404, ipAddress, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Warning, message, metadata, args);
    }

    /// <summary>
    /// Record unexpected input or extraneous data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousExtraneous(
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        params object?[] args)
    {
        LogMaliciousExtraneous(message, ipAddress, inputName, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record unexpected input or extraneous data.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="inputName">Input name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousExtraneous(
        string message,
        string? ipAddress,
        string? inputName,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousExtraneous, ipAddress, inputName, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record detection of attack tool usage.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousAttackTool(
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        params object?[] args)
    {
        LogMaliciousAttackTool(message, ipAddress, toolName, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record detection of attack tool usage.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="toolName">Tool name.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousAttackTool(
        string message,
        string? ipAddress,
        string? toolName,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousAttackTool, ipAddress, toolName, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a CORS violation attempt.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousCors(
        string message,
        string? ipAddress,
        string? useragent,
        string? referrer,
        params object?[] args)
    {
        LogMaliciousCors(message, ipAddress, useragent, referrer, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a CORS violation attempt.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="referrer">Referrer.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousCors(
        string message,
        string? ipAddress,
        string? useragent,
        string? referrer,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousCors, ipAddress, useragent, referrer);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }

    /// <summary>
    /// Record a direct object reference attempt.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousDirectReference(
        string message,
        string? ipAddress,
        string? useragent,
        params object?[] args)
    {
        LogMaliciousDirectReference(message, ipAddress, useragent, new SecurityEventMetadata(), args);
    }

    /// <summary>
    /// Record a direct object reference attempt.
    /// </summary>
    /// <param name="message">Log message.</param>
    /// <param name="ipAddress">IP address.</param>
    /// <param name="useragent">User agent.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void LogMaliciousDirectReference(
        string message,
        string? ipAddress,
        string? useragent,
        SecurityEventMetadata metadata,
        params object?[] args)
    {
        var evt = EventLabelBuilder.BuildEventString(LoggingVocabulary.MaliciousDirectReference, ipAddress, useragent);
        metadata ??= new SecurityEventMetadata();

        Log(evt, LogLevel.Critical, message, metadata, args);
    }
}
