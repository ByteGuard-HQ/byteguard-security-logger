# ByteGuard.SecurityLogger ![NuGet Version](https://img.shields.io/nuget/v/ByteGuard.SecurityLogger)

`ByteGuard.SecurityLogger` brings the [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html) to .NET by exposing a set of strongly-typed `ILogger` extension methods for common security and audit events.

Instead of ad-hoc log messages like `"login ok"` or `"unauthorized"`, you log standardized, structured events (e.g. `authn_login_success`, `authz_fail`) with consistent property names. This makes your security logs easier to search, alert on, correlate, and reason about, regardless of whether you send logs to Serilog, NLog, Application Insights, Elasticsearch, or something else.
