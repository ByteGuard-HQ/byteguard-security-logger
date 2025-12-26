using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class ExcessTests
{
    [Fact(DisplayName = "LogExcessRateLimitExceeded without metadata should log message with correct values")]
    public void LogExcessRateLimitExceeded_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var max = 100;

        var expectedEvent = $"excess_rate_limit_exceeded:{userId},{max}";
        var expectedMessage = $"User {userId} exceeded rate limit of {max}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogExcessRateLimitExceeded("User {UserId} exceeded rate limit of {Max}.", userId, max, userId, max);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogExcessRateLimitExceeded with metadata should log message with correct values")]
    public void LogExcessRateLimitExceeded_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var max = 100;

        var expectedEvent = $"excess_rate_limit_exceeded:{userId},{max}";
        var expectedMessage = $"User {userId} exceeded rate limit of {max}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogExcessRateLimitExceeded("User {UserId} exceeded rate limit of {Max}.", userId, max, userId, max);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
