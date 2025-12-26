using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class AuthnTests
{
    [Fact(DisplayName = "LogAuthnLoginSuccess without metadata should log message with correct values")]
    public void LogAuthnLoginSuccess_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_login_success:{userId}";
        var expectedMessage = $"User {userId} successfully logged in.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginSuccess("User {UserId} successfully logged in.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginSuccess with metadata should log message with correct values")]
    public void LogAuthnLoginSuccess_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_login_success:{userId}";
        var expectedMessage = $"User {userId} successfully logged in.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginSuccess("User {UserId} successfully logged in.", userId, userId, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginSuccessAfterFail without metadata should log message with correct values")]
    public void LogAuthnLoginSuccessAfterFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var retries = 3;

        var expectedEvent = $"authn_login_successafterfail:{userId},{retries}";
        var expectedMessage = $"User {userId} successfully logged in after {retries} attempt(s).";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginSuccessAfterFail("User {UserId} successfully logged in after {Retries} attempt(s).", userId, retries, userId, retries);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginSuccessAfterFail with metadata should log message with correct values")]
    public void LogAuthnLoginSuccessAfterFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var retries = 3;

        var expectedEvent = $"authn_login_successafterfail:{userId},{retries}";
        var expectedMessage = $"User {userId} successfully logged in after {retries} attempt(s).";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginSuccessAfterFail("User {UserId} successfully logged in after {Retries} attempt(s).", userId, retries, userId, retries, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginFail without metadata should log message with correct values")]
    public void LogAuthnLoginFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_login_fail:{userId}";
        var expectedMessage = $"User {userId} failed to log in.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginFail("User {UserId} failed to log in.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginFail with metadata should log message with correct values")]
    public void LogAuthnLoginFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_login_fail:{userId}";
        var expectedMessage = $"User {userId} failed to log in.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginFail("User {UserId} failed to log in.", userId, userId, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginFailMax without metadata should log message with correct values")]
    public void LogAuthnLoginFailMax_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var maxLimit = 5;

        var expectedEvent = $"authn_login_fail_max:{userId},{maxLimit}";
        var expectedMessage = $"User {userId} failed to log in after {maxLimit} attempts.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginFailMax("User {UserId} failed to log in after {MaxRetries} attempts.", userId, maxLimit, userId, maxLimit);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginFailMax with metadata should log message with correct values")]
    public void LogAuthnLoginFailMax_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var maxLimit = 5;

        var expectedEvent = $"authn_login_fail_max:{userId},{maxLimit}";
        var expectedMessage = $"User {userId} failed to log in after {maxLimit} attempts.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginFailMax("User {UserId} failed to log in after {MaxRetries} attempts.", userId, maxLimit, userId, maxLimit, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginLock without metadata should log message with correct values")]
    public void LogAuthnLoginLock_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var reason = "maxretries";

        var expectedEvent = $"authn_login_lock:{userId},{reason}";
        var expectedMessage = $"User {userId} was locked out with reason {reason}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginLock("User {UserId} was locked out with reason {Reason}.", userId, reason, userId, reason);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnLoginLock with metadata should log message with correct values")]
    public void LogAuthnLoginLock_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var reason = "maxretries";

        var expectedEvent = $"authn_login_lock:{userId},{reason}";
        var expectedMessage = $"User {userId} was locked out with reason {reason}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnLoginLock("User {UserId} was locked out with reason {Reason}.", userId, reason, new(), userId, reason);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnPasswordChange without metadata should log message with correct values")]
    public void LogAuthnPasswordChange_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_password_change:{userId}";
        var expectedMessage = $"User {userId} successfully changed their password.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnPasswordChange("User {UserId} successfully changed their password.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnPasswordChange with metadata should log message with correct values")]
    public void LogAuthnPasswordChange_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_password_change:{userId}";
        var expectedMessage = $"User {userId} successfully changed their password.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnPasswordChange("User {UserId} successfully changed their password.", userId, userId, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnPasswordChangeFail without metadata should log message with correct values")]
    public void LogAuthnPasswordChangeFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_password_change_fail:{userId}";
        var expectedMessage = $"User {userId} failed to change their password.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnPasswordChangeFail("User {UserId} failed to change their password.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnPasswordChangeFail with metadata should log message with correct values")]
    public void LogAuthnPasswordChangeFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_password_change_fail:{userId}";
        var expectedMessage = $"User {userId} failed to change their password.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnPasswordChangeFail("User {UserId} failed to change their password.", userId, userId, new());

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnImpossibleTravel without metadata should log message with correct values")]
    public void LogAuthnImpossibleTravel_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var regionOne = "US-OR";
        var regionTwo = "CN-SH";

        var expectedEvent = $"authn_impossible_travel:{userId},{regionOne},{regionTwo}";
        var expectedMessage = $"User {userId} attempted impossible travel.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnImpossibleTravel("User {UserId} attempted impossible travel.", userId, regionOne, regionTwo, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnImpossibleTravel with metadata should log message with correct values")]
    public void LogAuthnImpossibleTravel_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var regionOne = "US-OR";
        var regionTwo = "CN-SH";

        var expectedEvent = $"authn_impossible_travel:{userId},{regionOne},{regionTwo}";
        var expectedMessage = $"User {userId} attempted impossible travel.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnImpossibleTravel("User {UserId} attempted impossible travel.", userId, regionOne, regionTwo, new(), userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenCreated without metadata should log message with correct values")]

    public void LogAuthnTokenCreated_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var entitlements = new[] { "read", "write" };
        var commaSeparatedEntitlements = "read,write";

        var expectedEvent = $"authn_token_created:{userId},{commaSeparatedEntitlements}";
        var expectedMessage = $"User {userId} created a new token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenCreated("User {UserId} created a new token.", userId, entitlements, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenCreated with metadata should log message with correct values")]
    public void LogAuthnTokenCreated_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var entitlements = new[] { "read", "write" };
        var commaSeparatedEntitlements = "read,write";

        var expectedEvent = $"authn_token_created:{userId},{commaSeparatedEntitlements}";
        var expectedMessage = $"User {userId} created a new token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenCreated("User {UserId} created a new token.", userId, entitlements, new(), userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenRevoked without metadata should log message with correct values")]
    public void LogAuthnTokenRevoked_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var tokenId = "xyc-abc-123-gfk";

        var expectedEvent = $"authn_token_revoked:{userId},{tokenId}";
        var expectedMessage = $"User {userId} revoked a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenRevoked("User {UserId} revoked a token.", userId, tokenId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenRevoked with metadata should log message with correct values")]
    public void LogAuthnTokenRevoked_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var tokenId = "xyc-abc-123-gfk";

        var expectedEvent = $"authn_token_revoked:{userId},{tokenId}";
        var expectedMessage = $"User {userId} revoked a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenRevoked("User {UserId} revoked a token.", userId, tokenId, new(), userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenReuse without metadata should log message with correct values")]
    public void LogAuthnTokenReuse_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var tokenId = "xyc-abc-123-gfk";

        var expectedEvent = $"authn_token_reuse:{userId},{tokenId}";
        var expectedMessage = $"User {userId} reused a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenReuse("User {UserId} reused a token.", userId, tokenId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogAuthnTokenReuse with metadata should log message with correct values")]
    public void LogAuthnTokenReuse_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var tokenId = "xyc-abc-123-gfk";

        var expectedEvent = $"authn_token_reuse:{userId},{tokenId}";
        var expectedMessage = $"User {userId} reused a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenReuse("User {UserId} reused a token.", userId, tokenId, new(), userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Critical, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LognAuthnTokenDelete without metadata should log message with correct values")]
    public void LogAuthnTokenDelete_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_token_delete:{userId}";
        var expectedMessage = $"User {userId} deleted a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenDelete("User {UserId} deleted a token.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LognAuthnTokenDelete with metadata should log message with correct values")]
    public void LogAuthnTokenDelete_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"authn_token_delete:{userId}";
        var expectedMessage = $"User {userId} deleted a token.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogAuthnTokenDelete("User {UserId} deleted a token.", userId, new(), userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
