using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class AuthzTests
{
    [Fact(DisplayName = "LogAuthzFail without metadata should log message with correct values")]
    public void LogAuthzFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"authz_fail:{userId},{resource}";
        var expectedMessage = $"User {userId} failed authorization.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzFail("User {UserId} failed authorization.", userId, resource, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthzFail with metadata should log message with correct values")]
    public void LogAuthzFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"authz_fail:{userId},{resource}";
        var expectedMessage = $"User {userId} failed authorization.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzFail("User {UserId} failed authorization.", userId, resource, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthzChange without metadata should log message with correct values")]
    public void LogAuthzChange_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var from = "read";
        var to = "read_write";

        var expectedEvent = $"authz_change:{userId},{from},{to}";
        var expectedMessage = $"User {userId} changed authorization from {from} to {to}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzChange("User {UserId} changed authorization from {From} to {To}.", userId, from, to, userId, from, to);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthzChange with metadata should log message with correct values")]
    public void LogAuthzChange_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var from = "read";
        var to = "read_write";

        var expectedEvent = $"authz_change:{userId},{from},{to}";
        var expectedMessage = $"User {userId} changed authorization from {from} to {to}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzChange("User {UserId} changed authorization from {From} to {To}.", userId, from, to, userId, from, to);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthzAdmin without metadata should log message with correct values")]
    public void LogAuthzAdmin_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var @event = "PrivilegeElevated";

        var expectedEvent = $"authz_admin:{userId},{@event}";
        var expectedMessage = $"User {userId} performed administrative action {@event}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzAdmin("User {UserId} performed administrative action {Event}.", userId, @event, userId, @event);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthzAdmin with metadata should log message with correct values")]
    public void LogAuthzAdmin_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var @event = "PrivilegeElevated";

        var expectedEvent = $"authz_admin:{userId},{@event}";
        var expectedMessage = $"User {userId} performed administrative action {@event}.";
        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthzAdmin("User {UserId} performed administrative action {Event}.", userId, @event, userId, @event);
        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
