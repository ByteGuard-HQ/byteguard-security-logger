using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class MaliciousTests
{
    [Fact(DisplayName = "LogMaliciousExcess404 without metadata should log message with correct values")]
    public void LogMaliciousExcess404_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_excess_404:{ipAddress},{useragent}";
        var expectedMessage = $"Malicious excess 404 for IP address: {ipAddress}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousExcess404("Malicious excess 404 for IP address: {IpAddress}, User-Agent: {UserAgent}.", ipAddress, useragent, ipAddress, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousExcess404 with metadata should log message with correct values")]
    public void LogMaliciousExcess404_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_excess_404:{ipAddress},{useragent}";
        var expectedMessage = $"Malicious excess 404 for IP address: {ipAddress}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousExcess404("Malicious excess 404 for IP address: {IpAddress}, User-Agent: {UserAgent}.", ipAddress, useragent, ipAddress, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousExtraneous without metadata should log message with correct values")]
    public void LogMaliciousExtraneous_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var inputName = "testInput";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_extraneous:{ipAddress},{inputName},{useragent}";
        var expectedMessage = $"Malicious extraneous input for IP address: {ipAddress}, Input Name: {inputName}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousExtraneous("Malicious extraneous input for IP address: {IpAddress}, Input Name: {InputName}, User-Agent: {UserAgent}.", ipAddress, inputName, useragent, ipAddress, inputName, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousExtraneous with metadata should log message with correct values")]
    public void LogMaliciousExtraneous_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var inputName = "testInput";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_extraneous:{ipAddress},{inputName},{useragent}";
        var expectedMessage = $"Malicious extraneous input for IP address: {ipAddress}, Input Name: {inputName}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousExtraneous("Malicious extraneous input for IP address: {IpAddress}, Input Name: {InputName}, User-Agent: {UserAgent}.", ipAddress, inputName, useragent, ipAddress, inputName, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousAttackTool without metadata should log message with correct values")]
    public void LogMaliciousAttackTool_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var toolName = "TestTool";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_attack_tool:{ipAddress},{toolName},{useragent}";
        var expectedMessage = $"Malicious attack tool detected for IP address: {ipAddress}, Tool Name: {toolName}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousAttackTool("Malicious attack tool detected for IP address: {IpAddress}, Tool Name: {ToolName}, User-Agent: {UserAgent}.", ipAddress, toolName, useragent, ipAddress, toolName, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousAttackTool with metadata should log message with correct values")]
    public void LogMaliciousAttackTool_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var toolName = "TestTool";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_attack_tool:{ipAddress},{toolName},{useragent}";
        var expectedMessage = $"Malicious attack tool detected for IP address: {ipAddress}, Tool Name: {toolName}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousAttackTool("Malicious attack tool detected for IP address: {IpAddress}, Tool Name: {ToolName}, User-Agent: {UserAgent}.", ipAddress, toolName, useragent, ipAddress, toolName, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousCors without metadata should log message with correct values")]
    public void LogMaliciousCors_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";
        var referrer = "http://malicious.example.com";

        var expectedEvent = $"malicious_cors:{ipAddress},{useragent},{referrer}";
        var expectedMessage = $"Malicious CORS detected for IP address: {ipAddress}, User-Agent: {useragent}, Referrer: {referrer}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousCors("Malicious CORS detected for IP address: {IpAddress}, User-Agent: {UserAgent}, Referrer: {Referrer}.", ipAddress, useragent, referrer, ipAddress, useragent, referrer);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousCors with metadata should log message with correct values")]
    public void LogMaliciousCors_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";
        var referrer = "http://malicious.example.com";

        var expectedEvent = $"malicious_cors:{ipAddress},{useragent},{referrer}";
        var expectedMessage = $"Malicious CORS detected for IP address: {ipAddress}, User-Agent: {useragent}, Referrer: {referrer}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousCors("Malicious CORS detected for IP address: {IpAddress}, User-Agent: {UserAgent}, Referrer: {Referrer}.", ipAddress, useragent, referrer, ipAddress, useragent, referrer);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousDirectReference without metadata should log message with correct values")]
    public void LogMaliciousDirectReference_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_direct_reference:{ipAddress},{useragent}";
        var expectedMessage = $"Malicious direct reference detected for IP address: {ipAddress}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousDirectReference("Malicious direct reference detected for IP address: {IpAddress}, User-Agent: {UserAgent}.", ipAddress, useragent, ipAddress, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogMaliciousDirectReference with metadata should log message with correct values")]
    public void LogMaliciousDirectReference_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var ipAddress = "192.168.1.1";
        var useragent = "UnitTestAgent/1.0";

        var expectedEvent = $"malicious_direct_reference:{ipAddress},{useragent}";
        var expectedMessage = $"Malicious direct reference detected for IP address: {ipAddress}, User-Agent: {useragent}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogMaliciousDirectReference("Malicious direct reference detected for IP address: {IpAddress}, User-Agent: {UserAgent}.", ipAddress, useragent, ipAddress, useragent);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
