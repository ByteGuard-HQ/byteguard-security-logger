using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class SessionTests
{
    [Fact(DisplayName = "LogSessionCreated without metadata should log message with correct values")]
    public void LogSessionCreated_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"session_created:{userId}";
        var expectedMessage = $"Session created for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionCreated("Session created for user: {UserId}.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionCreated with metadata should log message with correct values")]
    public void LogSessionCreated_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";

        var expectedEvent = $"session_created:{user}";
        var expectedMessage = $"Session created for user: {user}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionCreated("Session created for user: {User}.", user, user);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionRenewed without metadata should log message with correct values")]
    public void LogSessionRenewed_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"session_renewed:{userId}";
        var expectedMessage = $"Session renewed for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionRenewed("Session renewed for user: {UserId}.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionRenewed with metadata should log message with correct values")]
    public void LogSessionRenewed_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";

        var expectedEvent = $"session_renewed:{user}";
        var expectedMessage = $"Session renewed for user: {user}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionRenewed("Session renewed for user: {User}.", user, user);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionExpired without metadata should log message with correct values")]
    public void LogSessionExpired_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var reason = "Inactivity";

        var expectedEvent = $"session_expired:{userId},{reason}";
        var expectedMessage = $"Session expired for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionExpired("Session expired for user: {UserId}.", userId, reason, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionExpired with metadata should log message with correct values")]
    public void LogSessionExpired_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var reason = "Inactivity";

        var expectedEvent = $"session_expired:{userId},{reason}";
        var expectedMessage = $"Session expired for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionExpired("Session expired for user: {User}.", userId, reason, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionUseAfterExpire without metadata should log message with correct values")]
    public void LogSessionUseAfterExpire_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"session_use_after_expire:{userId}";
        var expectedMessage = $"Session used after expiration for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionUseAfterExpire("Session used after expiration for user: {UserId}.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSessionUseAfterExpire with metadata should log message with correct values")]
    public void LogSessionUseAfterExpire_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"session_use_after_expire:{userId}";
        var expectedMessage = $"Session used after expiration for user: {userId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSessionUseAfterExpire("Session used after expiration for user: {UserId}.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
