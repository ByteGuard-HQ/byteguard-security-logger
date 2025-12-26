using Microsoft.Extensions.Logging;
using ByteGuard.SecurityLogger.Enrichers;
using ByteGuard.SecurityLogger.Configuration;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Security specific ILogging extensions.
/// </summary>
public partial class SecurityLogger
{
    private readonly ILogger _logger;
    private readonly SecurityLoggerConfiguration _configuration;

    /// <summary>
    /// Instantiate a new security logger.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="configuration">Security logger configuration.</param>
    public SecurityLogger(ILogger logger, SecurityLoggerConfiguration configuration)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        ConfigurationValidator.ThrowIfInvalid(configuration);
    }

    /// <summary>
    /// Generic log method.
    /// </summary>
    /// <param name="event">Security event.</param>
    /// <param name="level">Log level.</param>
    /// <param name="message">Log message.</param>
    /// <param name="metadata">Security event metadata.</param>
    /// <param name="args">An object array that contains zero or more objects to format.</param>
    public void Log(string @event, LogLevel level, string message, SecurityEventMetadata metadata, params object?[] args)
    {
        var properties = new Dictionary<string, object?>
        {
            ["AppId"] = _configuration.AppId,
            ["Event"] = @event
        };

        PropertiesEnricher.PopulatePropertiesFromMetadata(properties, metadata, _configuration);

        using var _ = _logger.BeginScope(properties);

        _logger.Log(level, message, args);
    }
}
