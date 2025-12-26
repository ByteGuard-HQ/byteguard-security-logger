using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class InputTests
{
    [Fact(DisplayName = "LogInputValidationFailed without metadata should log message with correct values")]
    public void LogInputValidationFailed_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var fields = new List<string> { "Email", "Password" };
        var commaSeparatedFields = string.Join(",", fields);

        var expectedEvent = $"input_validation_failed:({commaSeparatedFields}),{userId}";
        var expectedMessage = $"User {userId} failed input validation for fields: {commaSeparatedFields}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogInputValidationFailed("User {UserId} failed input validation for fields: {Fields}.", fields, userId, userId, commaSeparatedFields);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogInputValidationFailed with metadata should log message with correct values")]
    public void LogInputValidationFailed_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var fields = new List<string> { "Email", "Password" };
        var commaSeparatedFields = string.Join(",", fields);

        var expectedEvent = $"input_validation_failed:({commaSeparatedFields}),{userId}";
        var expectedMessage = $"User {userId} failed input validation for fields: {commaSeparatedFields}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogInputValidationFailed("User {UserId} failed input validation for fields: {Fields}.", fields, userId, userId, commaSeparatedFields);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogInputValidationDiscreteFail without metadata should log message with correct values")]
    public void LogInputValidationDiscreteFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var field = "Email";

        var expectedEvent = $"input_validation_discrete_fail:{field},{userId}";
        var expectedMessage = $"User {userId} failed input validation for field: {field}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogInputValidationDiscreteFail("User {UserId} failed input validation for field: {Field}.", field, userId, userId, field);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogInputValidationDiscreteFail with metadata should log message with correct values")]
    public void LogInputValidationDiscreteFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var field = "Email";

        var expectedEvent = $"input_validation_discrete_fail:{field},{userId}";
        var expectedMessage = $"User {userId} failed input validation for field: {field}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogInputValidationDiscreteFail("User {UserId} failed input validation for field: {Field}.", field, userId, userId, field);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
