# OpcSecAudit — Code Conventions

This document defines all coding standards, style rules, and development practices for the OpcSecAudit project.
Claude Code must follow these conventions without exception.

## Language & Framework

- **Target Framework:** `net10.0`
- **C# Version:** 14 (`<LangVersion>preview</LangVersion>` if required)
- **Nullable Reference Types:** enabled (`<Nullable>enable</Nullable>`)
- **Implicit Usings:** enabled (`<ImplicitUsings>enable</ImplicitUsings>`)
- **Language:** English everywhere — class names, properties, methods, comments, XML docs, CLI output, report text, error messages, Finding titles and descriptions. No German anywhere in the codebase.

## C# Style & Modern Features

Use modern C# / .NET 10 features throughout:

- **File-scoped namespaces** — always, no block-scoped namespaces.
- **Primary constructors** — use on classes and structs where they simplify DI or initialization. Fall back to traditional constructors only when primary constructors reduce clarity.
- **Collection expressions** — prefer `[1, 2, 3]` over `new List<int> { 1, 2, 3 }` and `[]` over `Array.Empty<T>()`.
- **Raw string literals** — use `"""..."""` for multi-line strings, especially HTML templates in the report generator.
- **`required` modifier** — use on properties that must be set at construction time. Prefer `required init` over constructor parameters for data classes with many properties.
- **Pattern matching** — use `is`, `switch` expressions, property patterns, and relational patterns where they improve readability.
- **`var`** — use when the type is obvious from the right-hand side. Use explicit types when the type is not immediately clear.
- **Target-typed `new()`** — use `List<Finding> findings = new()` when the type is declared on the left side.
- **Records** — consider `record` or `record struct` for pure data types if appropriate, but regular classes are fine for the domain model.

## Formatting

- 4 spaces indentation, no tabs.
- Allman-style braces (opening brace on its own line).
- One blank line between members.
- No trailing whitespace.
- Newline at end of file.
- An `.editorconfig` file must be included in the repository root enforcing these rules.

## XML Documentation

**Every `public` member gets XML documentation — no exceptions.** This includes:

- Classes, structs, records, interfaces, enums
- Methods, properties, constructors, events
- Enum values

Use `<summary>`, `<param>`, `<returns>`, `<exception>`, `<remarks>` as appropriate.

Redundant comments are acceptable and expected. A property named `Subject` still gets:

```csharp
/// <summary>
/// Gets the subject of the certificate.
/// </summary>
public required string Subject { get; init; }
```

All XML documentation is in English.

## Error Handling

- **No exceptions for flow control.** Exceptions are for exceptional situations only.
- **One custom exception type:** `AuditException` in `OpcSecAudit.Core`. Use it for all audit-specific errors (connection failures, unexpected server responses, etc.).
- **`CancellationToken`** must be accepted and propagated by every `async` method, all the way from CLI to the deepest call.
- Catch specific exceptions, never bare `catch` or `catch (Exception)` unless at the top-level CLI handler.

## Logging

- Use `Microsoft.Extensions.Logging.Abstractions` (`ILogger<T>`) for all logging.
- Inject `ILogger<T>` via constructor / primary constructor in all services.
- Log levels:
  - `LogDebug` — detailed diagnostic info (endpoint details, cert fields)
  - `LogInformation` — progress messages ("Discovering endpoints...", "Running certificate checks...")
  - `LogWarning` — non-fatal issues (timeout on optional check)
  - `LogError` — failures that abort a check or the audit
- Use structured logging with message templates: `logger.LogInformation("Discovered {Count} endpoints", endpoints.Count)` — never string interpolation in log calls.
- The CLI project configures a console logger with colored output (unless `--no-color`).

## Testing

- **Framework:** xUnit
- **Assertions:** FluentAssertions
- **Coverage:** Every public method has at least one unit test. Every Finding has a test that triggers it and a test that confirms it does NOT trigger on a clean configuration.
- **Test naming:** `MethodName_Scenario_ExpectedResult` — e.g., `RunAsync_EndpointWithSecurityModeNone_ReturnsCriticalFinding`
- **Test structure:** Arrange / Act / Assert, separated by blank lines.
- **Mocking:** Use `NSubstitute` for mocking interfaces. Never mock the domain model — construct real `Finding`, `AuditResult`, etc. in tests.
- **No test should require a real OPC UA server.** All OPC UA SDK types must be mocked or substituted.
- Test projects mirror the src structure:
  - `OpcSecAudit.Core.Tests` → tests for domain model, `AuditException`
  - `OpcSecAudit.Scanner.Tests` → tests for each checker, for `SecurityAuditor`
  - `OpcSecAudit.Reporting.Tests` → tests for HTML report generation

## Architecture & Dependency Rules

- **`OpcSecAudit.Core`** — Domain model, interfaces, `AuditException`. Dependencies: `Microsoft.Extensions.Logging.Abstractions`. No other external packages unless MIT-licensed and strictly necessary.
- **`OpcSecAudit.Scanner`** — OPC UA connection logic and all security checkers. References: `Core` + `OPCFoundation.NetStandard.Opc.Ua` (MIT).
- **`OpcSecAudit.Reporting`** — Report generators. References: `Core` only.
- **`OpcSecAudit.Cli`** — Entry point. References: `Scanner` + `Reporting` + `System.CommandLine`.
- **No circular dependencies.** Dependency flow is strictly: `Cli → Scanner → Core` and `Cli → Reporting → Core`.
- **Interfaces** that are consumed across projects live in `Core`. Implementations live in their respective projects.

## Dependency Licensing

All NuGet dependencies must be MIT-licensed or equivalently permissive (Apache-2.0, BSD). No copyleft (GPL/LGPL) dependencies. Verify before adding any new package.

## CI Pipeline

GitHub Actions workflow (`.github/workflows/ci.yml`):

1. **Trigger:** Push to `main`, pull requests to `main`.
2. **Matrix:** Ubuntu latest.
3. **Steps:**
   - Checkout
   - Setup .NET 10 SDK
   - `dotnet restore`
   - `dotnet build --no-restore --configuration Release --warnaserrors`
   - `dotnet test --no-build --configuration Release --logger "trx"` 
   - `dotnet publish src/OpcSecAudit.Cli --no-build --configuration Release --output ./publish`
4. **Warnings as errors** in Release builds (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` in Directory.Build.props).

## Git & Repository

- `.gitignore` for .NET projects (bin, obj, .vs, user files).
- `Directory.Build.props` in the repo root for shared MSBuild properties (TargetFramework, Nullable, ImplicitUsings, TreatWarningsAsErrors).
- Commit messages in English.
