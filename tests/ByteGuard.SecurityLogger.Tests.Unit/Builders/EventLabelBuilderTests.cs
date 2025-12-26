namespace ByteGuard.SecurityLogger.Tests.Unit.Builders;

public class EventLabelBuilderTests
{
    [Fact(DisplayName = "BuildEventString should return event name when no arguments are provided")]
    public void BuildEventString_NoArguments_ReturnsEventName()
    {
        // Arrange
        var eventName = "test_event";

        // Act
        var result = EventLabelBuilder.BuildEventString(eventName);

        // Assert
        Assert.Equal(eventName, result);
    }

    [Theory(DisplayName = "BuildEventString should return event name with arguments when arguments are provided")]
    [InlineData("test_event", new string?[] { "Arg1", "Arg2", null }, "test_event:Arg1,Arg2")]
    [InlineData("test_event", new string?[] { null, "Arg2", null }, "test_event:Arg2")]
    [InlineData("test_event", new string?[] { null }, "test_event")]
    [InlineData("test_event", null, "test_event")]
    public void BuildEventString_WithArguments_ReturnsEventNameWithArguments(string eventName, string?[] eventArgs, string expected)
    {
        // Act
        var result = EventLabelBuilder.BuildEventString(eventName, eventArgs);

        // Assert
        Assert.Equal(expected, result);
    }
}
