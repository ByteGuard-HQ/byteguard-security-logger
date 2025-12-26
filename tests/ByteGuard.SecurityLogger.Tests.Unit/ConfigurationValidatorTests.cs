using ByteGuard.SecurityLogger.Configuration;

namespace ByteGuard.SecurityLogger.Tests.Unit;

public class ConfigurationValidatorTests
{
    [Fact(DisplayName = "ThrowIfInvalid throws ArgumentNullException when configuration is null")]
    public void ThrowIfInvalid_ThrowsArgumentNullException_WhenConfigurationIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => ConfigurationValidator.ThrowIfInvalid(null!));
    }

    [Theory(DisplayName = "ThrowIfInvalid throws ArgumentException when AppId is null or empty")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ThrowIfInvalid_ThrowsArgumentException_WhenAppIdIsNullOrEmpty(string appId)
    {
        var configuration = new SecurityLoggerConfiguration { AppId = appId };

        Assert.Throws<ArgumentException>(() => ConfigurationValidator.ThrowIfInvalid(configuration));
    }
}
