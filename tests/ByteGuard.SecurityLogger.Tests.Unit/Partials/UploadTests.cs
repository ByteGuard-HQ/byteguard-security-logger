using ByteGuard.SecurityLogger.Configuration;
using ByteGuard.SecurityLogger.Tests.Unit.Helpers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Partials;

public class UploadTests
{
    [Fact(DisplayName = "LogUploadComplete without metadata should log message with correct values")]
    public void LogUploadComplete_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var fileName = "TestFile.txt";
        var fileType = "text/plain";

        var expectedEvent = $"upload_complete:{userId},{fileName},{fileType}";
        var expectedMessage = $"Upload complete for file: {fileName}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadComplete("Upload complete for file: {FileName}.", userId, fileName, fileType, fileName);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadComplete with metadata should log message with correct values")]
    public void LogUploadComplete_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var fileName = "TestFile.txt";
        var fileType = "text/plain";

        var expectedEvent = $"upload_complete:{user},{fileName},{fileType}";
        var expectedMessage = $"Upload complete for file: {fileName}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadComplete("Upload complete for file: {FileName}.", user, fileName, fileType, fileName);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadStored without metadata should log message with correct values")]
    public void LogUploadStored_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var from = "/temp/uploads";
        var to = "/permanent/storage";

        var expectedEvent = $"upload_stored:{userId},{from},{to}";
        var expectedMessage = $"Upload stored from {from} to {to}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadStored("Upload stored from {From} to {To}.", userId, from, to, from, to);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadStored with metadata should log message with correct values")]
    public void LogUploadStored_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var from = "/temp/uploads";
        var to = "/permanent/storage";

        var expectedEvent = $"upload_stored:{user},{from},{to}";
        var expectedMessage = $"Upload stored from {from} to {to}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadStored("Upload stored from {From} to {To}.", user, from, to, from, to);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadValidation without metadata should log message with correct values")]
    public void LogUploadValidation_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var fileName = "TestFile.txt";
        var validationType = "signature";
        var result = "passed";
        var logLevel = LogLevel.Information;

        var expectedEvent = $"upload_validation:{userId},{fileName},{validationType},{result}";
        var expectedMessage = $"Upload validation for {fileName} with type {validationType} resulted in {result}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadValidation("Upload validation for {FileName} with type {ValidationType} resulted in {Result}.", userId, fileName, validationType, result, logLevel, fileName, validationType, result);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(logLevel, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadValidation with metadata should log message with correct values")]
    public void LogUploadValidation_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var fileName = "TestFile.txt";
        var validationType = "signature";
        var result = "passed";
        var logLevel = LogLevel.Information;

        var expectedEvent = $"upload_validation:{user},{fileName},{validationType},{result}";
        var expectedMessage = $"Upload validation for {fileName} with type {validationType} resulted in {result}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadValidation("Upload validation for {FileName} with type {ValidationType} resulted in {Result}.", user, fileName, validationType, result, logLevel, fileName, validationType, result);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(logLevel, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadDelete without metadata should log message with correct values")]
    public void LogUploadDelete_WithoutMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var userId = "TestUser";
        var fileId = "File123";

        var expectedEvent = $"upload_delete:{userId},{fileId}";
        var expectedMessage = $"Upload deleted for file {fileId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadDelete("Upload deleted for file {FileId}.", userId, fileId, fileId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }

    [Fact(DisplayName = "LogUploadDelete with metadata should log message with correct values")]
    public void LogUploadDelete_WithMetadata_ShouldLogMessageWithCorrectValues()
    {
        // Arrange
        var user = "TestUser";
        var fileId = "File123";

        var expectedEvent = $"upload_delete:{user},{fileId}";
        var expectedMessage = $"Upload deleted for file {fileId}.";

        var logger = new FakeLogger<SecurityLogger>();
        SecurityLoggerConfiguration configuration = new() { AppId = "TestApp" };
        SecurityLogger securityLogger = new(logger, configuration);

        // Act
        securityLogger.LogUploadDelete("Upload deleted for file {FileId}.", user, fileId, fileId);

        // Assert
        var record = logger.Collector.GetSnapshot().Single();
        var scope = record.GetScopeDictionary();

        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(expectedMessage, record.Message);
        Assert.Contains("Event", scope!);
        Assert.Equal(expectedEvent, scope!["Event"]);
    }
}
