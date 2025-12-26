namespace ByteGuard.SecurityLogger.Configuration;

/// <summary>
/// Class used to validate a given security logger configuration instance.
/// </summary>
public static class ConfigurationValidator
{
    /// <summary>
    /// Validate configuration and throw exceptions if invalid.
    /// </summary>
    /// <param name="configuration">Configuration instance to validate.</param>
    /// <exception cref="ArgumentNullException">Throw if any required objects on the configuration object is <c>null</c>, or if the configuration object itself is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if any of the configuration values are invalid.</exception>
    public static void ThrowIfInvalid(SecurityLoggerConfiguration configuration)
    {
        if (configuration == null)
        {
            throw new ArgumentNullException(nameof(configuration), "Configuration cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(configuration.AppId))
        {
            throw new ArgumentException("AppId cannot be null or empty.", nameof(configuration.AppId));
        }
    }
}
