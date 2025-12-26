using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class CryptTests
{
    [Fact(DisplayName = "LogCryptDecryptFail without metadata should log message with correct values")]
    public void LogCryptDecryptFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"crypt_decrypt_fail:{userId}";
        var expectedMessage = $"User {userId} failed to decrypt.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogCryptDecryptFail("User {UserId} failed to decrypt.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogCryptDecryptFail with metadata should log message with correct values")]
    public void LogCryptDecryptFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"crypt_decrypt_fail:{userId}";
        var expectedMessage = $"User {userId} failed to decrypt.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogCryptDecryptFail("User {UserId} failed to decrypt.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogCryptEncryptFail without metadata should log message with correct values")]
    public void LogCryptEncryptFail_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"crypt_encrypt_fail:{userId}";
        var expectedMessage = $"User {userId} failed to encrypt.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogCryptEncryptFail("User {UserId} failed to encrypt.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogCryptEncryptFail with metadata should log message with correct values")]
    public void LogCryptEncryptFail_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";

        var expectedEvent = $"crypt_encrypt_fail:{userId}";
        var expectedMessage = $"User {userId} failed to encrypt.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogCryptEncryptFail("User {UserId} failed to encrypt.", userId, userId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
