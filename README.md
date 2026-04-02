# OpcSecAudit

[![CI](https://github.com/USER/OpcSecAudit/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/OpcSecAudit/actions/workflows/ci.yml)

**OpcSecAudit** is a command-line tool that connects to an OPC UA server, evaluates its security configuration, and produces a findings report. It performs passive, non-destructive checks across four security categories — endpoint security, authentication, server certificates, and server configuration — then presents the results on the console and optionally exports a self-contained HTML report.

---

## Features

| Category | Checks |
| --- | --- |
| **Endpoint Security** | Unencrypted endpoints, deprecated cipher suites (Basic128Rsa15, Basic256) |
| **Authentication** | Anonymous access on unencrypted channels, cleartext username credentials, missing certificate auth |
| **Server Certificate** | Expired or expiring certificates, weak key sizes, SHA-1 signatures, self-signed certs, hostname mismatches |
| **Server Configuration** | Default discovery port, software version exposure, anonymous session establishment, audit logging status |

---

## Quick Start

### Build from source

```bash
git clone https://github.com/USER/OpcSecAudit.git
cd OpcSecAudit
dotnet build --configuration Release
```

### Run against a server

```bash
dotnet run --project src/OpcSecAudit.Cli -- scan opc.tcp://192.168.1.50:4840
```

Or use the published binary:

```bash
dotnet publish src/OpcSecAudit.Cli --configuration Release --output ./out
./out/OpcSecAudit scan opc.tcp://192.168.1.50:4840
```

---

## Usage

```text
OpcSecAudit — OPC UA Security Auditor

Usage:
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

### Examples

```bash
# Basic scan
opcsecaudit scan opc.tcp://192.168.1.50:4840

# Scan and export HTML report
opcsecaudit scan opc.tcp://192.168.1.50:4840 -o report.html

# Verbose output with 10-second timeout
opcsecaudit scan opc.tcp://192.168.1.50:4840 --verbose --timeout 10

# Disable colors for piping or logging
opcsecaudit scan opc.tcp://192.168.1.50:4840 --no-color > results.txt
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed — no critical findings |
| `1` | Audit completed — critical findings present |
| `2` | Audit failed (connection error, invalid URL, etc.) |

---

## Finding Reference

| ID | Severity | Category | Title |
| --- | --- | --- | --- |
| SEC-EP-001 | Critical | Endpoint Security | Unencrypted Endpoint Available |
| SEC-EP-002 | Warning | Endpoint Security | Deprecated Security Policy Basic128Rsa15 |
| SEC-EP-003 | Warning | Endpoint Security | Deprecated Security Policy Basic256 |
| SEC-EP-004 | Info | Endpoint Security | Only Secure Policies Configured |
| SEC-AUTH-001 | Critical | Authentication | Unauthenticated Cleartext Access |
| SEC-AUTH-002 | Warning | Authentication | Anonymous Access on Encrypted Endpoint |
| SEC-AUTH-003 | Warning | Authentication | Username Credentials Transmitted in Cleartext |
| SEC-AUTH-004 | Info | Authentication | Certificate-Based Authentication Not Available |
| SEC-CERT-001 | Critical | Server Certificate | Server Certificate Expired |
| SEC-CERT-002 | Warning | Server Certificate | Weak Certificate Key Size |
| SEC-CERT-003 | Warning | Server Certificate | SHA-1 Signature Algorithm |
| SEC-CERT-004 | Warning | Server Certificate | Server Certificate Expiring Soon |
| SEC-CERT-005 | Info | Server Certificate | Self-Signed Server Certificate |
| SEC-CERT-006 | Warning | Server Certificate | Certificate Hostname Mismatch |
| SEC-SRV-001 | Info | Server Configuration | Server Running on Default Discovery Port |
| SEC-SRV-002 | Info | Server Configuration | Server Software Identified |
| SEC-SRV-003 | Warning | Server Configuration | Anonymous Session Established Successfully |
| SEC-SRV-004 | Info | Server Configuration | Audit Logging Not Enabled |

---

## Building

```bash
# Restore, build, test
dotnet restore
dotnet build
dotnet test

# Publish self-contained binary (Linux x64)
dotnet publish src/OpcSecAudit.Cli \
  --configuration Release \
  --runtime linux-x64 \
  --self-contained true \
  --output ./publish
```

---

## Project Structure

```text
OpcSecAudit/
├── src/
│   ├── OpcSecAudit.Core/        # Domain models, interfaces, exceptions (no SDK dependency)
│   ├── OpcSecAudit.Scanner/     # OPC UA SDK integration, 4 security checkers, auditor
│   ├── OpcSecAudit.Reporting/   # Self-contained HTML report generator
│   └── OpcSecAudit.Cli/         # CLI entry point (System.CommandLine)
└── tests/
    ├── OpcSecAudit.Core.Tests/
    ├── OpcSecAudit.Scanner.Tests/
    └── OpcSecAudit.Reporting.Tests/
```

---

## License

MIT — see [LICENSE.txt](LICENSE.txt).

---

> **Disclaimer:** This tool is for authorized security assessments only. Only run OpcSecAudit against OPC UA servers you own or have explicit written permission to test.
