namespace ByteGuard.SecurityLogger;

/// <summary>
/// Combines events and event arguments into event strings.
/// </summary>
public static class EventLabelBuilder
{
    /// <summary>
    /// Build an event string from the given event name and event arguments.
    /// </summary>
    /// <param name="eventName">Event name.</param>
    /// <param name="eventArgs">Event arguments.</param>
    /// <returns>An appropriate event string.</returns>
    public static string BuildEventString(string eventName, params string?[] eventArgs)
    {
        if (eventArgs.Length == 0)
            return eventName;

        return $"{eventName}:{string.Join(",", eventArgs)}";
    }
}
