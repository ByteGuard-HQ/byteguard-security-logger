using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging;

namespace ByteGuard.SecurityLogger;

/// <summary>
/// Extension methods for creating a security logger based on an existing ILogger implementation.
/// </summary>
public static class SecurityLoggerFactoryExtensions
{
    /// <summary>
    /// Instantiate a <see cref="SecurityLogger"/> from an existing ILogger implementation.
    /// </summary>
    /// <param name="logger">ILogger implementation.</param>
    /// <param name="configuration">Security logger configuration.</param>
    public static SecurityLogger AsSecurityLogger(this ILogger logger, SecurityLoggerConfiguration configuration) =>
        new SecurityLogger(logger, configuration);
}
