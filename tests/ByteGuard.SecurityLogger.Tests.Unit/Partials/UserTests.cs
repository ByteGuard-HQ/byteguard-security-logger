using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class UserTests
{
    [Fact(DisplayName = "LogUserCreated without metadata should log message with correct values")]
    public void LogUserCreated_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var newUserId = "NewTestUser";
        var attributes = new Dictionary<string, IEnumerable<string>>
        {
            { "role", new[] { "user" } },
            { "department", new[] { "hr" } }
        };
        var expectedAttributes = "role:user,department:hr";

        var expectedEvent = $"user_created:{userId},{newUserId},{expectedAttributes}";
        var expectedMessage = $"User created with ID {newUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserCreated("User created with ID {NewUserId}.", userId, newUserId, attributes, newUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserCreated with metadata should log message with correct values")]
    public void LogUserCreated_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var newUserId = "NewTestUser";
        var attributes = new Dictionary<string, IEnumerable<string>>
        {
            { "role", new[] { "user" } },
            { "department", new[] { "hr" } }
        };
        var expectedAttributes = "role:user,department:hr";

        var expectedEvent = $"user_created:{user},{newUserId},{expectedAttributes}";
        var expectedMessage = $"User created with ID {newUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserCreated("User created with ID {NewUserId}.", user, newUserId, attributes, newUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserUpdated without metadata should log message with correct values")]
    public void LogUserUpdated_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var onUserId = "NewTestUser";
        var attributes = new Dictionary<string, IEnumerable<string>>
        {
            { "role", new[] { "admin" } },
            { "department", new[] { "hr" } }
        };
        var expectedAttributes = "role:admin,department:hr";

        var expectedEvent = $"user_updated:{userId},{onUserId},{expectedAttributes}";
        var expectedMessage = $"User updated with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserUpdated("User updated with ID {OnUserId}.", userId, onUserId, attributes, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserUpdated with metadata should log message with correct values")]
    public void LogUserUpdated_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var onUserId = "NewTestUser";
        var attributes = new Dictionary<string, IEnumerable<string>>
        {
            { "role", new[] { "admin" } },
            { "department", new[] { "hr" } }
        };
        var expectedAttributes = "role:admin,department:hr";

        var expectedEvent = $"user_updated:{user},{onUserId},{expectedAttributes}";
        var expectedMessage = $"User updated with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserUpdated("User updated with ID {OnUserId}.", user, onUserId, attributes, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserArchived without metadata should log message with correct values")]
    public void LogUserArchived_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var onUserId = "NewTestUser";

        var expectedEvent = $"user_archived:{userId},{onUserId}";
        var expectedMessage = $"User archived with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserArchived("User archived with ID {OnUserId}.", userId, onUserId, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserArchived with metadata should log message with correct values")]
    public void LogUserArchived_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var onUserId = "NewTestUser";

        var expectedEvent = $"user_archived:{user},{onUserId}";
        var expectedMessage = $"User archived with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserArchived("User archived with ID {OnUserId}.", user, onUserId, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserDeleted without metadata should log message with correct values")]
    public void LogUserDeleted_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var onUserId = "NewTestUser";

        var expectedEvent = $"user_deleted:{userId},{onUserId}";
        var expectedMessage = $"User deleted with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserDeleted("User deleted with ID {OnUserId}.", userId, onUserId, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUserDeleted with metadata should log message with correct values")]
    public void LogUserDeleted_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var onUserId = "NewTestUser";

        var expectedEvent = $"user_deleted:{user},{onUserId}";
        var expectedMessage = $"User deleted with ID {onUserId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUserDeleted("User deleted with ID {OnUserId}.", user, onUserId, onUserId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
