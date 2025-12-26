using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class PrivilegeTests
{
    [Fact(DisplayName = "LogPrivilegePermissionsChanged without metadata should log message with correct values")]
    public void LogPrivilegePermissionsChanged_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var resource = "TestResource";
        var fromLevel = "User";
        var toLevel = "Admin";

        var expectedEvent = $"privilege_permissions_changed:{userId},{resource},{fromLevel},{toLevel}";
        var expectedMessage = $"Privilege permissions changed for user: {userId}, resource: {resource}, from level: {fromLevel}, to level: {toLevel}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogPrivilegePermissionsChanged("Privilege permissions changed for user: {UserId}, resource: {Resource}, from level: {FromLevel}, to level: {ToLevel}.", userId, resource, fromLevel, toLevel, userId, resource, fromLevel, toLevel);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogPrivilegePermissionsChanged with metadata should log message with correct values")]
    public void LogPrivilegePermissionsChanged_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var resource = "TestResource";
        var fromLevel = "User";
        var toLevel = "Admin";

        var expectedEvent = $"privilege_permissions_changed:{user},{resource},{fromLevel},{toLevel}";
        var expectedMessage = $"Privilege permissions changed for user: {user}, resource: {resource}, from level: {fromLevel}, to level: {toLevel}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogPrivilegePermissionsChanged("Privilege permissions changed for user: {User}, resource: {Resource}, from level: {FromLevel}, to level: {ToLevel}.", user, resource, fromLevel, toLevel, user, resource, fromLevel, toLevel);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
