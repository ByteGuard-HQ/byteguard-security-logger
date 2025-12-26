using Microsoft.Extensions.Logging.Testing;

namespace ByteGuard.SecurityLogger.Tests.Unit.Helpers;

public static class FakeLoggerExtensions
{
    public static IReadOnlyDictionary<string, object?> GetScopeDictionary(this FakeLogRecord record)
    {
        var scope = record.Scopes.FirstOrDefault(scope =>
        {
            var dict = scope as IReadOnlyDictionary<string, object?>;
            return dict != null && dict.ContainsKey("Event");
        });

        return (IReadOnlyDictionary<string, object?>)scope!;
    }
}
