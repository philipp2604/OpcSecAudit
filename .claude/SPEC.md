# OpcSecAudit — Technical Specification

OPC UA Security Auditor — connects to an OPC UA server, evaluates its security configuration, and produces a findings report.

## Overview

OpcSecAudit is a command-line tool that audits OPC UA servers for security misconfigurations. It discovers endpoints, analyzes security modes, authentication policies, server certificates, and server configuration. Results are displayed in the console and optionally exported as a self-contained HTML report.

This is a portfolio project targeting OT security roles. Code quality, architecture, and test coverage matter.

## Project Structure

```
OpcSecAudit/
├── OpcSecAudit.sln
├── Directory.Build.props
├── .editorconfig
├── .gitignore
├── README.md
├── CONVENTIONS.md
├── SPEC.md
├── src/
│   ├── OpcSecAudit.Core/
│   │   ├── OpcSecAudit.Core.csproj
│   │   ├── Models/
│   │   │   ├── Severity.cs
│   │   │   ├── Finding.cs
│   │   │   ├── AuditResult.cs
│   │   │   ├── EndpointInfo.cs
│   │   │   ├── CertificateInfo.cs
│   │   │   ├── ServerInfo.cs
│   │   │   └── UserTokenInfo.cs
│   │   ├── Interfaces/
│   │   │   ├── ISecurityChecker.cs
│   │   │   └── IReportGenerator.cs
│   │   └── Exceptions/
│   │       └── AuditException.cs
│   ├── OpcSecAudit.Scanner/
│   │   ├── OpcSecAudit.Scanner.csproj
│   │   ├── AuditContext.cs
│   │   ├── SecurityAuditor.cs
│   │   └── Checkers/
│   │       ├── EndpointSecurityChecker.cs
│   │       ├── AuthenticationChecker.cs
│   │       ├── CertificateChecker.cs
│   │       └── ServerConfigChecker.cs
│   ├── OpcSecAudit.Reporting/
│   │   ├── OpcSecAudit.Reporting.csproj
│   │   └── HtmlReportGenerator.cs
│   └── OpcSecAudit.Cli/
│       ├── OpcSecAudit.Cli.csproj
│       ├── Program.cs
│       └── ConsoleResultWriter.cs
├── tests/
│   ├── OpcSecAudit.Core.Tests/
│   │   ├── OpcSecAudit.Core.Tests.csproj
│   │   └── Models/
│   │       ├── FindingTests.cs
│   │       ├── AuditResultTests.cs
│   │       └── SeverityTests.cs
│   ├── OpcSecAudit.Scanner.Tests/
│   │   ├── OpcSecAudit.Scanner.Tests.csproj
│   │   └── Checkers/
│   │       ├── EndpointSecurityCheckerTests.cs
│   │       ├── AuthenticationCheckerTests.cs
│   │       ├── CertificateCheckerTests.cs
│   │       └── ServerConfigCheckerTests.cs
│   └── OpcSecAudit.Reporting.Tests/
│       ├── OpcSecAudit.Reporting.Tests.csproj
│       └── HtmlReportGeneratorTests.cs
└── .github/
    └── workflows/
        └── ci.yml
```

## NuGet Packages

| Package | Project | Purpose | License |
|---------|---------|---------|---------|
| `Microsoft.Extensions.Logging.Abstractions` | Core | `ILogger<T>` interface | MIT |
| `OPCFoundation.NetStandard.Opc.Ua` | Scanner | OPC UA client SDK | MIT |
| `System.CommandLine` | Cli | CLI argument parsing | MIT |
| `Microsoft.Extensions.Logging.Console` | Cli | Console log provider | MIT |
| `xunit` | Tests | Test framework | Apache-2.0 |
| `xunit.runner.visualstudio` | Tests | Test runner | Apache-2.0 |
| `Microsoft.NET.Test.Sdk` | Tests | Test host | MIT |
| `FluentAssertions` | Tests | Assertion library | Apache-2.0 |
| `NSubstitute` | Tests | Mocking framework | BSD-3 |

## Directory.Build.props

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>preview</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
  </PropertyGroup>
</Project>
```

---

## Domain Model (OpcSecAudit.Core)

### Severity.cs

```csharp
/// <summary>
/// Severity levels for security findings.
/// </summary>
public enum Severity
{
    /// <summary>
    /// Informational finding, no immediate risk.
    /// </summary>
    Info,

    /// <summary>
    /// Warning — a potential security weakness that should be addressed.
    /// </summary>
    Warning,

    /// <summary>
    /// Critical — a severe security issue requiring immediate attention.
    /// </summary>
    Critical
}
```

### Finding.cs

```csharp
/// <summary>
/// Represents a single security finding from an audit check.
/// </summary>
public class Finding
{
    /// <summary>
    /// Gets the unique identifier of the finding (e.g., "SEC-EP-001").
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Gets the category this finding belongs to (e.g., "Endpoint Security").
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Gets the severity level of the finding.
    /// </summary>
    public required Severity Severity { get; init; }

    /// <summary>
    /// Gets the short title of the finding.
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// Gets the detailed description including concrete values from the audit.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Gets the recommended remediation action.
    /// </summary>
    public required string Recommendation { get; init; }

    /// <summary>
    /// Gets the CWE identifier, if applicable (e.g., "CWE-319"). Null if no CWE mapping exists.
    /// </summary>
    public string? CweId { get; init; }

    /// <summary>
    /// Gets the CWE description, if applicable. Null if no CWE mapping exists.
    /// </summary>
    public string? CweDescription { get; init; }
}
```

### AuditResult.cs

```csharp
/// <summary>
/// Represents the complete result of a security audit against an OPC UA server.
/// </summary>
public class AuditResult
{
    /// <summary>
    /// Gets the OPC UA endpoint URL that was audited.
    /// </summary>
    public required string TargetUrl { get; init; }

    /// <summary>
    /// Gets the UTC timestamp when the audit was started.
    /// </summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>
    /// Gets the total duration of the audit.
    /// </summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>
    /// Gets the list of discovered endpoints on the target server.
    /// </summary>
    public required List<EndpointInfo> DiscoveredEndpoints { get; init; }

    /// <summary>
    /// Gets the server information, if it could be retrieved. Null if the server did not respond.
    /// </summary>
    public ServerInfo? ServerInfo { get; init; }

    /// <summary>
    /// Gets the list of all findings from the audit.
    /// </summary>
    public required List<Finding> Findings { get; init; }

    /// <summary>
    /// Gets the number of critical findings.
    /// </summary>
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);

    /// <summary>
    /// Gets the number of warning findings.
    /// </summary>
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);

    /// <summary>
    /// Gets the number of informational findings.
    /// </summary>
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
}
```

### EndpointInfo.cs

```csharp
/// <summary>
/// Represents a discovered OPC UA endpoint and its security configuration.
/// </summary>
public class EndpointInfo
{
    /// <summary>
    /// Gets the endpoint URL.
    /// </summary>
    public required string EndpointUrl { get; init; }

    /// <summary>
    /// Gets the message security mode (None, Sign, SignAndEncrypt).
    /// </summary>
    public required string SecurityMode { get; init; }

    /// <summary>
    /// Gets the security policy URI.
    /// </summary>
    public required string SecurityPolicy { get; init; }

    /// <summary>
    /// Gets the transport profile URI.
    /// </summary>
    public required string TransportProfile { get; init; }

    /// <summary>
    /// Gets the list of accepted user identity token types.
    /// </summary>
    public required List<UserTokenInfo> UserTokenPolicies { get; init; }

    /// <summary>
    /// Gets the server certificate information for this endpoint. Null if no certificate is present.
    /// </summary>
    public CertificateInfo? ServerCertificate { get; init; }
}
```

### UserTokenInfo.cs

```csharp
/// <summary>
/// Represents a user identity token policy on an endpoint.
/// </summary>
public class UserTokenInfo
{
    /// <summary>
    /// Gets the token type (Anonymous, UserName, Certificate, IssuedToken).
    /// </summary>
    public required string TokenType { get; init; }

    /// <summary>
    /// Gets the security policy URI for this token. Null if not specified.
    /// </summary>
    public string? SecurityPolicyUri { get; init; }
}
```

### CertificateInfo.cs

```csharp
/// <summary>
/// Represents parsed information about an X.509 certificate.
/// </summary>
public class CertificateInfo
{
    /// <summary>
    /// Gets the certificate subject distinguished name.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Gets the certificate issuer distinguished name.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// Gets the certificate thumbprint (SHA-1 hash).
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Gets the start of the certificate validity period.
    /// </summary>
    public required DateTime NotBefore { get; init; }

    /// <summary>
    /// Gets the end of the certificate validity period.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Gets the key size in bits.
    /// </summary>
    public required int KeySizeBits { get; init; }

    /// <summary>
    /// Gets the signature algorithm (e.g., "sha256RSA", "sha1RSA").
    /// </summary>
    public required string SignatureAlgorithm { get; init; }

    /// <summary>
    /// Gets a value indicating whether the certificate is self-signed.
    /// </summary>
    public required bool IsSelfSigned { get; init; }

    /// <summary>
    /// Gets the list of Subject Alternative Names.
    /// </summary>
    public required List<string> SubjectAltNames { get; init; }
}
```

### ServerInfo.cs

```csharp
/// <summary>
/// Represents information about the OPC UA server software.
/// </summary>
public class ServerInfo
{
    /// <summary>
    /// Gets the product name of the server software.
    /// </summary>
    public required string ProductName { get; init; }

    /// <summary>
    /// Gets the software version.
    /// </summary>
    public required string SoftwareVersion { get; init; }

    /// <summary>
    /// Gets the build number.
    /// </summary>
    public required string BuildNumber { get; init; }

    /// <summary>
    /// Gets the current server state (e.g., "Running").
    /// </summary>
    public required string State { get; init; }
}
```

### AuditException.cs

```csharp
/// <summary>
/// Exception thrown when an audit operation fails.
/// </summary>
public class AuditException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class.
    /// </summary>
    public AuditException() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public AuditException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuditException"/> class with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public AuditException(string message, Exception innerException) : base(message, innerException) { }
}
```

---

## Interfaces (OpcSecAudit.Core)

### ISecurityChecker.cs

```csharp
/// <summary>
/// Interface for a security checker that evaluates one category of security findings.
/// </summary>
public interface ISecurityChecker
{
    /// <summary>
    /// Gets the human-readable category name (e.g., "Endpoint Security").
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Runs the security checks and returns findings.
    /// </summary>
    /// <param name="context">The audit context containing discovered endpoint data.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A list of findings. May be empty if no issues were found.</returns>
    Task<IReadOnlyList<Finding>> RunAsync(AuditContext context, CancellationToken cancellationToken);
}
```

### IReportGenerator.cs

```csharp
/// <summary>
/// Interface for generating audit reports in various formats.
/// </summary>
public interface IReportGenerator
{
    /// <summary>
    /// Generates a report from the audit result and writes it to the specified path.
    /// </summary>
    /// <param name="result">The audit result to report on.</param>
    /// <param name="outputPath">The file path to write the report to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task GenerateAsync(AuditResult result, string outputPath, CancellationToken cancellationToken);
}
```

---

## Scanner (OpcSecAudit.Scanner)

### AuditContext.cs

```csharp
/// <summary>
/// Shared context passed to all security checkers during an audit.
/// </summary>
public class AuditContext
{
    /// <summary>
    /// Gets the target OPC UA server URL.
    /// </summary>
    public required string TargetUrl { get; init; }

    /// <summary>
    /// Gets the resolved hostname of the target URL.
    /// </summary>
    public required string ResolvedHostname { get; init; }

    /// <summary>
    /// Gets the port of the target URL.
    /// </summary>
    public required int Port { get; init; }

    /// <summary>
    /// Gets the endpoint descriptions returned by the server.
    /// </summary>
    public required EndpointDescriptionCollection Endpoints { get; init; }

    /// <summary>
    /// Gets the application description returned by the server, if available.
    /// </summary>
    public ApplicationDescription? ServerApplication { get; init; }
}
```

`EndpointDescriptionCollection` and `ApplicationDescription` are types from the OPC UA SDK (`Opc.Ua`).

### SecurityAuditor.cs

The main orchestrator. Sequence:

1. Parse and validate the target URL.
2. Create an OPC UA `ApplicationConfiguration` with security disabled (we are a passive auditor, not enforcing our own certs).
3. Call `CoreClientUtils.DiscoverEndpoints()` or use `Session.Create` approach to get the `EndpointDescriptionCollection`.
4. Build the `AuditContext`.
5. Run each `ISecurityChecker` sequentially, collecting all findings.
6. Attempt to read `ServerStatus` / `BuildInfo` by connecting a session to the most permissive endpoint (Anonymous + None if available, otherwise Anonymous + any). If connection fails, skip gracefully — this is optional data.
7. Build and return the `AuditResult`.

The `SecurityAuditor` receives `IEnumerable<ISecurityChecker>` and `ILogger<SecurityAuditor>` via constructor injection.

```csharp
/// <summary>
/// Orchestrates the security audit by discovering endpoints and running all security checkers.
/// </summary>
public class SecurityAuditor(
    IEnumerable<ISecurityChecker> checkers,
    ILogger<SecurityAuditor> logger)
{
    /// <summary>
    /// Runs a full security audit against the specified OPC UA server.
    /// </summary>
    /// <param name="targetUrl">The OPC UA endpoint URL (e.g., "opc.tcp://192.168.1.50:4840").</param>
    /// <param name="timeoutSeconds">Connection timeout in seconds.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The complete audit result.</returns>
    /// <exception cref="AuditException">Thrown if endpoint discovery fails entirely.</exception>
    public async Task<AuditResult> RunAuditAsync(
        string targetUrl,
        int timeoutSeconds,
        CancellationToken cancellationToken);
}
```

### Checker Implementations

Each checker is a separate class implementing `ISecurityChecker`. They receive `ILogger<T>` via primary constructor.

---

#### EndpointSecurityChecker

**Category:** `"Endpoint Security"`

**Checks:**

| Finding ID | Severity | Trigger Condition | Title | Recommendation | CWE |
|------------|----------|-------------------|-------|----------------|-----|
| SEC-EP-001 | Critical | Any endpoint has `SecurityMode == None` AND `SecurityPolicyUri == "http://opcfoundation.org/UA/SecurityPolicy#None"` | Unencrypted Endpoint Available | Disable SecurityMode None in server configuration. All communication should use Sign or SignAndEncrypt. | CWE-319 / Cleartext Transmission of Sensitive Information |
| SEC-EP-002 | Warning | Any endpoint uses `SecurityPolicyUri` containing `Basic128Rsa15` | Deprecated Security Policy Basic128Rsa15 | Remove Basic128Rsa15 from server configuration. Use Aes128_Sha256_RsaOaep or Aes256_Sha256_RsaPss. | CWE-327 / Use of a Broken or Risky Cryptographic Algorithm |
| SEC-EP-003 | Warning | Any endpoint uses `SecurityPolicyUri` containing `Basic256` but NOT `Basic256Sha256` | Deprecated Security Policy Basic256 | Remove Basic256 from server configuration. Use Basic256Sha256 or newer policies. | CWE-327 / Use of a Broken or Risky Cryptographic Algorithm |
| SEC-EP-004 | Info | ALL endpoints use only approved policies: `Basic256Sha256`, `Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss`, or the None policy is absent | Only Secure Policies Configured | No action required. Server is correctly configured with modern security policies. | — |

**Description field:** Must include the concrete endpoint URL, SecurityMode, and SecurityPolicyUri that triggered the finding.

**SEC-EP-004 logic:** This is a positive finding. Emit it only if NONE of SEC-EP-001, SEC-EP-002, SEC-EP-003 were triggered. It confirms the server is well-configured.

---

#### AuthenticationChecker

**Category:** `"Authentication"`

**Checks:**

| Finding ID | Severity | Trigger Condition | Title | Recommendation | CWE |
|------------|----------|-------------------|-------|----------------|-----|
| SEC-AUTH-001 | Critical | An endpoint with `SecurityMode == None` accepts `Anonymous` token type | Unauthenticated Cleartext Access | Disable Anonymous authentication on unencrypted endpoints. This allows full unauthenticated access with no encryption. | CWE-306 / Missing Authentication for Critical Function |
| SEC-AUTH-002 | Warning | An endpoint with `SecurityMode != None` accepts `Anonymous` token type | Anonymous Access on Encrypted Endpoint | Disable Anonymous authentication. Require username/password or certificate-based authentication. | CWE-306 / Missing Authentication for Critical Function |
| SEC-AUTH-003 | Warning | An endpoint with `SecurityMode == None` accepts `UserName` token type (and the token's own SecurityPolicyUri is also None or empty) | Username Credentials Transmitted in Cleartext | Ensure UserName tokens are only available on endpoints with Sign or SignAndEncrypt, or configure a token-level security policy. | CWE-523 / Unprotected Transport of Credentials |
| SEC-AUTH-004 | Info | No endpoint offers `Certificate` user token type | Certificate-Based Authentication Not Available | Consider enabling X.509 certificate-based user authentication for stronger identity assurance. | — |

**Description field:** Must include the endpoint URL and the specific token policy that triggered the finding.

**Iteration logic:** These checks iterate over ALL endpoints × ALL user token policies on each endpoint. A single finding is emitted per unique condition — do not emit SEC-AUTH-002 ten times for ten endpoints. Group them: emit one finding per condition and list all affected endpoints in the description.

---

#### CertificateChecker

**Category:** `"Server Certificate"`

**Checks:**

The checker extracts the server certificate from each unique `EndpointDescription.ServerCertificate` byte array. Parse it as `X509Certificate2`. Deduplicate by thumbprint — most endpoints share the same cert.

| Finding ID | Severity | Trigger Condition | Title | Recommendation | CWE |
|------------|----------|-------------------|-------|----------------|-----|
| SEC-CERT-001 | Critical | `NotAfter < DateTime.UtcNow` | Server Certificate Expired | Replace the server certificate immediately. An expired certificate may cause connection failures and indicates poor certificate management. | CWE-298 / Improper Validation of Certificate Expiration |
| SEC-CERT-002 | Warning | RSA key size < 2048 bits | Weak Certificate Key Size | Generate a new server certificate with at least 2048-bit RSA key (4096-bit recommended). | CWE-326 / Inadequate Encryption Strength |
| SEC-CERT-003 | Warning | Signature algorithm contains "sha1" (case-insensitive) | SHA-1 Signature Algorithm | Regenerate the server certificate using SHA-256 or stronger signature algorithm. SHA-1 is considered broken. | CWE-328 / Use of Weak Hash |
| SEC-CERT-004 | Warning | `NotAfter` is within 30 days from `DateTime.UtcNow` (but not yet expired) | Server Certificate Expiring Soon | Renew the server certificate before it expires on {NotAfter}. | CWE-298 / Improper Validation of Certificate Expiration |
| SEC-CERT-005 | Info | `Subject == Issuer` (self-signed) | Self-Signed Server Certificate | Consider using a certificate issued by a Certificate Authority for production environments. Self-signed certificates do not provide third-party trust validation. | CWE-295 / Improper Certificate Validation |
| SEC-CERT-006 | Warning | The hostname from the target URL does not appear in the Subject CN or any Subject Alternative Name | Certificate Hostname Mismatch | Regenerate the server certificate with the correct hostname in the Subject or Subject Alternative Names field. | CWE-297 / Improper Validation of Certificate with Host Mismatch |

**Description field:** Must include Subject, Thumbprint (first 8 chars), and the specific value that triggered the finding (e.g., "Key size: 1024 bits", "Expires: 2025-01-15").

**Edge case:** Endpoints with `SecurityMode == None` may have no certificate. Skip those — do not error.

---

#### ServerConfigChecker

**Category:** `"Server Configuration"`

**Checks:**

| Finding ID | Severity | Trigger Condition | Title | Recommendation | CWE |
|------------|----------|-------------------|-------|----------------|-----|
| SEC-SRV-001 | Info | Parsed port from target URL equals 4840 | Server Running on Default Discovery Port | Consider using a non-default port to reduce exposure from automated scanning. This is informational — not inherently insecure. | — |
| SEC-SRV-002 | Info | Server BuildInfo was successfully read | Server Software Identified | Be aware that server software identification allows attackers to search for known vulnerabilities. Restrict access to the BuildInfo node if possible. | — |
| SEC-SRV-003 | Warning | An Anonymous session was successfully established (attempt connection with Anonymous identity to the most permissive endpoint) | Anonymous Session Established Successfully | Disable Anonymous access to prevent unauthorized session creation. | CWE-306 / Missing Authentication for Critical Function |
| SEC-SRV-004 | Info | The `Server_Auditing` node (NodeId: `i=2994`) in the address space is either not present, not readable, or its value is `false` | Audit Logging Not Enabled | Enable audit logging on the OPC UA server. Audit events provide traceability for security-relevant operations. | — |

**SEC-SRV-002 description:** Include ProductName, SoftwareVersion, BuildNumber in the finding description.

**SEC-SRV-003 logic:** This check actually tries to open a Session. This is the only check that establishes a session. The session must be closed immediately after the check. If connection fails (rejected, timeout), do NOT emit this finding.

**SEC-SRV-004 logic:** Read the `Auditing` property from the Server object in the address space. NodeId for the Auditing property is `i=2994`. This requires a session — reuse the Anonymous session from SEC-SRV-003 if it succeeded. If no session could be established, skip this check and emit SEC-SRV-004 with a note that the check could not be performed because no session was available.

---

## Reporting (OpcSecAudit.Reporting)

### HtmlReportGenerator

Implements `IReportGenerator`. Produces a single, self-contained HTML file with inline CSS. No external dependencies, no JavaScript, no external stylesheets.

**Report Structure:**

1. **Header:** "OPC UA Security Audit Report" + Tool version
2. **Summary Box:**
   - Target URL
   - Timestamp (UTC)
   - Duration
   - Finding counts: Critical (red), Warning (orange/amber), Info (blue)
   - Overall assessment: if CriticalCount > 0 → "FAIL" (red), elif WarningCount > 0 → "REVIEW" (amber), else → "PASS" (green)
3. **Server Information** (if available):
   - Product, Version, Build, State
4. **Discovered Endpoints Table:**
   - Columns: Endpoint URL, Security Mode, Security Policy (short name, not full URI), User Token Types
   - Highlight rows with SecurityMode None in red/pink background
5. **Findings by Category:**
   - Grouped by category, each category as a section with heading
   - Each finding as a card/box with:
     - Severity badge (colored: red/amber/blue)
     - Finding ID + Title
     - Description (may contain multiple lines for multiple affected endpoints)
     - Recommendation
     - CWE reference (as a link to `https://cwe.mitre.org/data/definitions/{number}.html`)
6. **Footer:** "Generated by OpcSecAudit v{version} on {timestamp}"

**CSS Guidelines:**
- Professional, clean design. Dark header, light body.
- Color scheme: Critical = `#dc2626` (red), Warning = `#d97706` (amber), Info = `#2563eb` (blue), Pass = `#16a34a` (green).
- Use a system font stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`.
- Tables with alternating row colors.
- Print-friendly: findings should not break across pages (`break-inside: avoid`).
- Responsive: readable on mobile screens.

**Implementation:** Use `StringBuilder` with raw string literals (`"""`). No template engine dependency.

---

## CLI (OpcSecAudit.Cli)

### Program.cs

Uses `System.CommandLine` to define a single `scan` command:

```
opcsecaudit scan <target-url> [options]

Arguments:
  <target-url>    OPC UA server URL (e.g., opc.tcp://192.168.1.50:4840)

Options:
  -o, --output <path>    Export HTML report to the specified file path
  -t, --timeout <sec>    Connection timeout in seconds (default: 5)
  --verbose              Show detailed endpoint information in console output
  --no-color             Disable colored console output
  --version              Show version information
  -h, --help             Show help
```

**Exit codes:**
- 0: Audit completed, no critical findings
- 1: Audit completed, critical findings present
- 2: Audit failed (connection error, invalid URL, etc.)

### ConsoleResultWriter

Separate class responsible for writing `AuditResult` to the console. Receives `ILogger` is NOT used here — this class writes directly to `Console` with optional ANSI colors.

**Console output format (normal mode):**

```
OpcSecAudit v1.0.0 — OPC UA Security Auditor
Target: opc.tcp://192.168.1.50:4840
Started: 2025-06-15 14:30:00 UTC
Duration: 2.3s

Discovered 5 endpoints.

━━━ Findings ━━━

[CRITICAL] SEC-EP-001: Unencrypted Endpoint Available
  Endpoint: opc.tcp://192.168.1.50:4840
  SecurityMode: None | Policy: None
  → Disable SecurityMode None in server configuration.
  CWE: CWE-319

[WARNING] SEC-AUTH-002: Anonymous Access on Encrypted Endpoint
  Endpoints: opc.tcp://192.168.1.50:4840 (SignAndEncrypt/Basic256Sha256)
  → Disable Anonymous authentication.
  CWE: CWE-306

[INFO] SEC-CERT-005: Self-Signed Server Certificate
  Subject: CN=MyServer | Thumbprint: A1B2C3D4...
  → Consider using a CA-issued certificate.
  CWE: CWE-295

━━━ Summary ━━━
Critical: 1 | Warnings: 1 | Info: 1
Result: FAIL
```

**Verbose mode** (`--verbose`): After "Discovered N endpoints.", print a table of all endpoints with SecurityMode, Policy, and Token Types before the findings.

**Colors:**
- `CRITICAL` — red
- `WARNING` — yellow
- `INFO` — cyan
- `FAIL` — red
- `REVIEW` — yellow  
- `PASS` — green
- Disabled when `--no-color` is set or when stdout is not a terminal (check `Console.IsOutputRedirected`).

### DI Setup in Program.cs

```csharp
// Build service collection
var services = new ServiceCollection();
services.AddLogging(builder => builder.AddConsole());
services.AddSingleton<ISecurityChecker, EndpointSecurityChecker>();
services.AddSingleton<ISecurityChecker, AuthenticationChecker>();
services.AddSingleton<ISecurityChecker, CertificateChecker>();
services.AddSingleton<ISecurityChecker, ServerConfigChecker>();
services.AddSingleton<SecurityAuditor>();
services.AddSingleton<IReportGenerator, HtmlReportGenerator>();
services.AddSingleton<ConsoleResultWriter>();
```

---

## CI Pipeline (.github/workflows/ci.yml)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Restore
        run: dotnet restore

      - name: Build
        run: dotnet build --no-restore --configuration Release

      - name: Test
        run: dotnet test --no-build --configuration Release --logger "trx;LogFileName=results.trx"

      - name: Publish
        run: dotnet publish src/OpcSecAudit.Cli/OpcSecAudit.Cli.csproj --no-build --configuration Release --output ./publish

      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-results
          path: '**/results.trx'
```

---

## README.md

The README should include:

1. **Title and badge** — project name, CI status badge
2. **One-paragraph description** — what it does
3. **Features list** — the four audit categories briefly
4. **Quick start** — build from source, run against a server
5. **Usage examples** — basic scan, scan with report, verbose mode
6. **Finding reference** — table of all 18 findings with ID, Severity, Title
7. **Building** — `dotnet build`, `dotnet test`, `dotnet publish`
8. **License** — MIT
9. **Disclaimer** — "This tool is for authorized security assessments only."

---

## Implementation Order

For Claude Code, implement in this sequence:

1. `Directory.Build.props`, `.editorconfig`, `.gitignore`, `OpcSecAudit.sln`
2. `OpcSecAudit.Core` — all models, interfaces, `AuditException`
3. `OpcSecAudit.Core.Tests` — tests for models
4. `OpcSecAudit.Scanner` — `AuditContext`, all 4 checkers, `SecurityAuditor`
5. `OpcSecAudit.Scanner.Tests` — tests for all checkers (mocked OPC UA types)
6. `OpcSecAudit.Reporting` — `HtmlReportGenerator`
7. `OpcSecAudit.Reporting.Tests` — tests for report generation
8. `OpcSecAudit.Cli` — `Program.cs`, `ConsoleResultWriter`
9. `.github/workflows/ci.yml`
10. `README.md`

After each project: run `dotnet build` to verify compilation. After each test project: run `dotnet test` to verify all tests pass.
