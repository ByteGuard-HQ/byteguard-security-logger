using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using NSubstitute;

namespace ByteGuard.SecurityLogger.Tests.Unit;

public class SecurityLoggerTests
{
    [Fact(DisplayName = "Constructor should throw ArgumentNullException when ILogger is null")]
    public void Constructor_ThrowsArgumentNullException_WhenILoggerIsNull()
    {
        // Arrange
        ILogger logger = null!;
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SecurityLogger(logger, configuration));
    }

    [Fact(DisplayName = "Constructor should throw ArgumentNullException when SecurityLoggerConfiguration is null")]
    public void Constructor_ThrowsArgumentNullException_WhenSecurityLoggerConfigurationIsNull()
    {
        // Arrange
        ILogger logger = Substitute.For<ILogger>();
        SecurityLoggerConfiguration configuration = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SecurityLogger(logger, configuration));
    }

    [Fact(DisplayName = "Constructor should throw ArgumentException when SecurityLoggerConfiguration is invalid")]
    public void Constructor_ThrowsArgumentException_WhenSecurityLoggerConfigurationIsInvalid()
    {
        // Arrange
        ILogger logger = Substitute.For<ILogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = null! };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new SecurityLogger(logger, configuration));
    }

    [Fact(DisplayName = "Log should log message with correct values")]
    public void Log_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.Log("TestEvent", LogLevel.Information, "Test message", new SecurityEventMetadata());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal("Test message", record.Message);
    }

    [Fact(DisplayName = "Log should include AppId and Event in scope properties")]
    public void Log_ShouldIncludeAppIdAndEventInScopeProperties()
    {
        // Arrange
        var expectedAppId = "TestApp";
        var expectedEvent = "TestEvent";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = expectedAppId };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.Log(expectedEvent, LogLevel.Information, "Test message", new SecurityEventMetadata());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.Scopes.FirstOrDefault(scope =>
        {
            var dict = scope as IReadOnlyDictionary<string, object?>;
            return dict != null && dict.ContainsKey("AppId") && dict.ContainsKey("Event");
        });

        Assert.Contains("AppId", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedAppId, ((IReadOnlyDictionary<string, object?>)scope!)["AppId"]);
        Assert.Contains("Event", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedEvent, ((IReadOnlyDictionary<string, object?>)scope!)["Event"]);
    }

    [Fact(DisplayName = "Log should populate properties from SecurityEventMetadata")]
    public void Log_ShouldPopulatePropertiesFromSecurityEventMetadata()
    {
        // Arrange
        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        var expectedMetadata = new SecurityEventMetadata
        {
            UserAgent = "TestUserAgent",
            SourceIp = "1.1.1.1",
            HostIp = "2.2.2.2",
            Hostname = "TestHost",
            Protocol = "HTTPS",
            Port = "443",
            RequestUri = "/test/uri",
            RequestMethod = "GET",
            Region = "TestRegion",
            Geo = "TestGeo"
        };

        // Act
        securityLogger.Log("TestEvent", LogLevel.Information, "Test message", expectedMetadata);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scopes = record.Scopes;
        var scope = scopes.FirstOrDefault(scope =>
        {
            var dict = scope as IReadOnlyDictionary<string, object?>;
            return dict != null && dict.ContainsKey("AppId") && dict.ContainsKey("Event");
        });

        Assert.Contains("UserAgent", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.UserAgent, ((IReadOnlyDictionary<string, object?>)scope!)["UserAgent"]);
        Assert.Contains("SourceIp", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.SourceIp, ((IReadOnlyDictionary<string, object?>)scope!)["SourceIp"]);
        Assert.Contains("HostIp", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.HostIp, ((IReadOnlyDictionary<string, object?>)scope!)["HostIp"]);
        Assert.Contains("Hostname", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.Hostname, ((IReadOnlyDictionary<string, object?>)scope!)["Hostname"]);
        Assert.Contains("Protocol", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.Protocol, ((IReadOnlyDictionary<string, object?>)scope!)["Protocol"]);
        Assert.Contains("Port", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.Port, ((IReadOnlyDictionary<string, object?>)scope!)["Port"]);
        Assert.Contains("RequestUri", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.RequestUri, ((IReadOnlyDictionary<string, object?>)scope!)["RequestUri"]);
        Assert.Contains("RequestMethod", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.RequestMethod, ((IReadOnlyDictionary<string, object?>)scope!)["RequestMethod"]);
        Assert.Contains("Region", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.Region, ((IReadOnlyDictionary<string, object?>)scope!)["Region"]);
        Assert.Contains("Geo", (IReadOnlyDictionary<string, object?>)scope!);
        Assert.Equal(expectedMetadata.Geo, ((IReadOnlyDictionary<string, object?>)scope!)["Geo"]);
    }
}
