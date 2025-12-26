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
        if (eventArgs is null || eventArgs.Length == 0)
            return eventName;

        var commaSeparatedEventArgs = string.Join(",", eventArgs.Where(arg => !string.IsNullOrEmpty(arg)));

        if (string.IsNullOrWhiteSpace(commaSeparatedEventArgs))
            return eventName;

        return $"{eventName}:{commaSeparatedEventArgs}";
    }
}
