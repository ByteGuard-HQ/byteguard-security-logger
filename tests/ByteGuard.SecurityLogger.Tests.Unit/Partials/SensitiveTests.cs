using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class SensitiveTests
{
    [Fact(DisplayName = "LogSensitiveCreate without metadata should log message with correct values")]
    public void LogSensitiveCreate_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_create:{userId},{resource}";
        var expectedMessage = $"Sensitive data created for user: {userId}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveCreate("Sensitive data created for user: {UserId}, resource: {Resource}.", userId, resource, userId, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveCreate with metadata should log message with correct values")]
    public void LogSensitiveCreate_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_create:{user},{resource}";
        var expectedMessage = $"Sensitive data created for user: {user}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveCreate("Sensitive data created for user: {User}, resource: {Resource}.", user, resource, user, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveRead without metadata should log message with correct values")]
    public void LogSensitiveRead_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_read:{userId},{resource}";
        var expectedMessage = $"Sensitive data read for user: {userId}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveRead("Sensitive data read for user: {UserId}, resource: {Resource}.", userId, resource, userId, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveRead with metadata should log message with correct values")]
    public void LogSensitiveRead_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_read:{user},{resource}";
        var expectedMessage = $"Sensitive data read for user: {user}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveRead("Sensitive data read for user: {User}, resource: {Resource}.", user, resource, user, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveUpdate without metadata should log message with correct values")]
    public void LogSensitiveUpdate_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_update:{userId},{resource}";
        var expectedMessage = $"Sensitive data updated for user: {userId}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveUpdate("Sensitive data updated for user: {UserId}, resource: {Resource}.", userId, resource, userId, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveUpdate with metadata should log message with correct values")]
    public void LogSensitiveUpdate_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_update:{user},{resource}";
        var expectedMessage = $"Sensitive data updated for user: {user}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveUpdate("Sensitive data updated for user: {User}, resource: {Resource}.", user, resource, user, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveDelete without metadata should log message with correct values")]
    public void LogSensitiveDelete_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_delete:{userId},{resource}";
        var expectedMessage = $"Sensitive data deleted for user: {userId}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveDelete("Sensitive data deleted for user: {UserId}, resource: {Resource}.", userId, resource, userId, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogSensitiveDelete with metadata should log message with correct values")]
    public void LogSensitiveDelete_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var resource = "TestResource";

        var expectedEvent = $"sensitive_delete:{user},{resource}";
        var expectedMessage = $"Sensitive data deleted for user: {user}, resource: {resource}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogSensitiveDelete("Sensitive data deleted for user: {User}, resource: {Resource}.", user, resource, user, resource);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
