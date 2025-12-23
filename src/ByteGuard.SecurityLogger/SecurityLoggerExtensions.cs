using Microsoft.Extensions.Logging;
using ByteGuard.SecurityLogger.Enrichers;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security specific ILogging extensions.
/// </summary>
public static class SecurityLoggerExtensions
{
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

        logger.Log(level, message, args);
    }
}
