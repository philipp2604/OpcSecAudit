# Claude Code — Initial Prompt for OpcSecAudit

You are implementing a new C# / .NET 10 project called **OpcSecAudit** — an OPC UA Security Auditor CLI tool.

## Context Files

Read these two files completely before writing any code. They are your single source of truth:

1. `SPEC.md` — Full technical specification: project structure, domain model (with complete C# code for all classes), all 18 security findings with exact trigger logic, checker architecture, CLI arguments, HTML report layout, CI pipeline, NuGet packages, and implementation order.
2. `CONVENTIONS.md` — All coding standards: C# 14 / .NET 10 features to use, formatting rules, XML documentation requirements, testing conventions, dependency rules, logging patterns, and error handling.

**Follow both documents precisely. Do not deviate, improvise, or skip anything.**

## How to Work

1. Read `SPEC.md` and `CONVENTIONS.md` in full.
2. Follow the **Implementation Order** section at the bottom of `SPEC.md` exactly — step by step.
3. After creating each project: run `dotnet build` to verify it compiles without errors or warnings.
4. After creating each test project: run `dotnet test` to verify all tests pass.
5. Do not move to the next step until the current step builds and tests green.

## Key Rules

- **English everywhere** — code, comments, XML docs, CLI output, finding descriptions, report text. No German.
- **Every public member gets XML documentation** — no exceptions, even if it seems redundant.
- **Every finding needs tests** — one test that triggers the finding, one test that confirms it does NOT trigger on clean input.
- **No real OPC UA server in tests** — mock/substitute all OPC UA SDK types.
- **Target framework is `net10.0`** with `<LangVersion>preview</LangVersion>`.
- **Warnings are errors** in Release configuration.

## Starting Point

Create the project in the current working directory. Start with `Directory.Build.props`, `.editorconfig`, `.gitignore`, and the solution file, then proceed through the implementation order.

Begin.
