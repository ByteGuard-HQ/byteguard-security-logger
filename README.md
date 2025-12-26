# ByteGuard.SecurityLogger ![NuGet Version](https://img.shields.io/nuget/v/ByteGuard.SecurityLogger)

`ByteGuard.SecurityLogger` is a lightweight `ILogger` wrapper that brings the [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html) to .NET by exposing a set of strongly-typed `ILogger` methods for common security and audit events.

Instead of ad-hoc log messages like `"login ok"` or `"unauthorized"`, you log standardized, structured events (e.g. `authn_login_success`, `authz_fail`) with consistent property names. This makes your security logs easier to search, alert on, correlate, and reason about, regardless of whether you send logs to Serilog, NLog, Application Insights, Elasticsearch, or something else.

This package is **provider-agnostic**: it logs through `Microsoft.Extensions.Logging` so you can keep using your existing logging stack (Serilog, NLog, Application Insights, Seq, etc.) via normal logging providers.

## Features

- ✅ OWASP-aligned security event vocabulary
- ✅ Structured logging via `ILogger` scopes/properties
- ✅ Works with any `Microsoft.Extensions.ILogger` provider (_NLog, Serilog, etc._)

## Getting Started

### Installation

This package is published and installed via [NuGet](https://www.nuget.org/packages/ByteGuard.SecurityLogger).

Reference the package in your project:

```bash
dotnet add package ByteGuard.SecurityLogger
```

## Usage

Instantiate a new `SecurityLogger` instance using either the constructor or the `ILogger` extensions: `AsSecurityLogger()`.

```csharp
ILogger logger = /* resolve or create ILogger */

var configuration = new SecurityLoggerConfiguration
{
    AppId = "MyApp"
}

// Using constructor
var securityLogger = new SecurityLogger(logger, configuration);

// Using ILogger extensions
var securityLogger = logger.AsSecurityLogger(configuration);
```

Log your security events:

```csharp
var user = //...

securityLogger.AuthnLoginSuccess(
    "User {UserId} successfully logged in.",
    userId: user.Id,
    args: user.Id
)
```

## API Design

`ByteGuard.SecurityLogger` implements the **full OWASP Logging Vocabulary**: every event type defined by OWASP exists as a corresponding method on `SecurityLogger`.

### One method per event (plus an overload with metadata)

For each OWASP event type, `SecurityLogger` exposes two overloads:

1. A minimal overload for logging the event with just the event label parameters.

```csharp
securityLogger.Log{event}(
    string message,
    /* event label arguments (varies by event) */,
    params object?[] args
)
```

2. An overload that additionally accepts a `SecurityEventMetadata` object for richer, OWASP-recommended context (_client IP, hostname, request URI, etc._).

```csharp
securityLogger.Log{event}(
    string message,
    /* event label arguments (varies by event) */,
    SecurityEventMetadata metadata,
    params object?[] args
)
```

### Parameter order (always the same)

| Parameter             | Description                                                                                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `message`             | The human readable log message (_typically a message template_)                                                                                                                                                                                         |
| Event label arguments | These are the values required to form the OWASP event label, e.g.: `authn_login_success:{userId}` and `authz_fail:{userId,resource}` (_depending on the even type_). These are all nullable and will not be present in the label if provided as `null`. |
| `metadata`            | Additional structured context recommended by OWASP (source IP, host, request URI, etc.) (_Only in the metadata method overload_)                                                                                                                        |
| `args`                | The message template arguments from the 1st parameters                                                                                                                                                                                                  |

### Example

If an event label requires a `userId`, the call becomes:

```csharp
// Providing user ID produces label: authn_login_success:userOne
var userId = "userOne";
securityLogger.LogAuthnLoginSuccess(
    "User {UserId} logged in successfully from {Ip}",   // Message template
    userId,                                             // Label parameters
    userId, ip);                                        // Template args

// Without providing user ID produces label: authn_login_success
securityLogger.LogAuthnLoginSuccess(
    "User {UserId} logged in successfully from {Ip}",   // Message template
    null,                                               // Label parameters
    userId, ip);                                        // Template args
```

If you want to add OWASP-style context, use the metadata overload:

```csharp
securityLogger.LogAuthnLoginSuccess(
    "User {UserId} logged in successfully from {Ip}",   // Message template
    userId,                                             // Label parameters
    new SecurityEventMetadata                           // Event metadata
    {
        SourceIp = ip,
        Hostname = host,
        RequestUri = requestUri
    },
    userId, ip);                                        // Template args
```

> ℹ️ **Note:** The exact label arguments vary per event type, based on the OWASP Logging Vocabulary definition.

## Configuration

The `SecurityLogger` supports the following configurations:

| Configuration            | Required | Default | Description                                                                                                                                                                                                                                            |
| ------------------------ | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AppId`                  | Yes      | N/A     | Application identifier added to the log message, to ensure logs are easy to find for the given application                                                                                                                                             |
| `DisableSourceIpLogging` | No       | `true`  | Whether to log the `SourceIp` if provided (_logging user IP address may be useful for detection and response, but may be considered personally identifiable information when combined with other data and subject to regulation or deletion requests_) |

## Supported events

All supported events can be seen in the [WIKI](https://github.com/ByteGuard-HQ/byteguard-security-logger/wiki/Supported-events)

## License

_ByteGuard.SecurityLogger is Copyright © ByteGuard Contributors - Provided under the MIT license._
