using ByteGuard.SecurityLogger.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit;

public class SecurityLoggerFactoryExtensions
{
    [Fact(DisplayName = "AsSecurityLogger returns SecurityLogger instance")]
    public void AsSecurityLogger_ReturnsSecurityLoggerInstance()
    {
        // Arrange
        var fakeLogger = new FakeLogger();
        var configuration = new SecurityLoggerConfiguration { AppId = "TestApp" };

        // Act
        var result = fakeLogger.AsSecurityLogger(configuration);

        // Assert
        Assert.IsType<SecurityLogger>(result);
    }

    [Fact(DisplayName = "AsSecurityLogger returns a SecurityLogger that logs message to the correct ILogger")]
    public void AsSecurityLogger_ReturnsSecurityLoggerThatLogsMessageToCorrectILogger()
    {
        // Arrange
        var expectedEvent = "TestEvent";

        var fakeLogger = new FakeLogger();
        var configuration = new SecurityLoggerConfiguration { AppId = "TestApp" };
        var securityLogger = fakeLogger.AsSecurityLogger(configuration);

        // Act
        securityLogger.Log(expectedEvent, LogLevel.Information, "Test message", new SecurityEventMetadata());

        // Assert
        var record = fakeLogger.Collector.GetSnapshot().Single();

        Assert.Equal("Test message", record.Message);
    }
}
