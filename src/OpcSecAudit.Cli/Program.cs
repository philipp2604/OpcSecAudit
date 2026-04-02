using System.CommandLine;
using System.CommandLine.Parsing;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpcSecAudit.Cli;
using OpcSecAudit.Core.Exceptions;
using OpcSecAudit.Core.Interfaces;
using OpcSecAudit.Reporting;
using OpcSecAudit.Scanner;
using OpcSecAudit.Scanner.Checkers;
using OpcSecAudit.Scanner.Interfaces;

Console.OutputEncoding = Encoding.UTF8;

// ── Dependency injection ──────────────────────────────────────────────────────

var services = new ServiceCollection();
services.AddLogging(builder =>
{
    builder.SetMinimumLevel(LogLevel.Warning);
    builder.AddConsole();
});
services.AddSingleton<IAuditSessionFactory, OpcUaSessionFactory>();
services.AddSingleton<ISecurityChecker, EndpointSecurityChecker>();
services.AddSingleton<ISecurityChecker, AuthenticationChecker>();
services.AddSingleton<ISecurityChecker, CertificateChecker>();
services.AddSingleton<ISecurityChecker, ServerConfigChecker>();
services.AddSingleton<SecurityAuditor>();
services.AddSingleton<IReportGenerator, HtmlReportGenerator>();
services.AddSingleton<ConsoleResultWriter>();

using var serviceProvider = services.BuildServiceProvider();

// ── CLI definition ────────────────────────────────────────────────────────────

var targetArgument = new Argument<string>("target-url")
{
    Description = "OPC UA server URL (e.g., opc.tcp://192.168.1.50:4840)"
};

var outputOption = new Option<string?>("--output", ["-o"])
{
    Description = "Export HTML report to the specified file path"
};

var timeoutOption = new Option<int>("--timeout", ["-t"])
{
    Description = "Connection timeout in seconds (default: 5)"
};

var verboseOption = new Option<bool>("--verbose", [])
{
    Description = "Show detailed endpoint information in console output"
};

var noColorOption = new Option<bool>("--no-color", [])
{
    Description = "Disable colored console output"
};

var scanCommand = new Command("scan", "Run a security audit against an OPC UA server  (run 'scan --help' for all options)");
scanCommand.Add(targetArgument);
scanCommand.Add(outputOption);
scanCommand.Add(timeoutOption);
scanCommand.Add(verboseOption);
scanCommand.Add(noColorOption);

var rootCommand = new RootCommand(
    "OpcSecAudit — OPC UA Security Auditor\n\n" +
    "Run 'scan --help' to see all scan options (-o/--output, -t/--timeout, --verbose, --no-color).");
rootCommand.Add(scanCommand);

scanCommand.SetAction(async (ParseResult parseResult, CancellationToken ct) =>
{
    var targetUrl = parseResult.GetRequiredValue(targetArgument);
    var outputPath = parseResult.GetValue(outputOption);
    var timeout = parseResult.GetValue(timeoutOption);
    if (timeout <= 0)
    {
        timeout = 5;
    }

    var verbose = parseResult.GetValue(verboseOption);
    var noColor = parseResult.GetValue(noColorOption);

    var auditor = serviceProvider.GetRequiredService<SecurityAuditor>();
    var writer = serviceProvider.GetRequiredService<ConsoleResultWriter>();
    var reportGenerator = serviceProvider.GetRequiredService<IReportGenerator>();

    try
    {
        var result = await auditor.RunAuditAsync(targetUrl, timeout, ct);
        writer.Write(result, verbose, noColor);

        if (outputPath is not null)
        {
            await reportGenerator.GenerateAsync(result, outputPath, ct);
            Console.WriteLine($"\nReport saved to: {outputPath}");
        }

        return result.CriticalCount > 0 ? 1 : 0;
    }
    catch (OperationCanceledException)
    {
        Console.Error.WriteLine("Audit cancelled.");
        return 2;
    }
    catch (AuditException ex)
    {
        Console.Error.WriteLine($"Audit failed: {ex.Message}");
        return 2;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Unexpected error: {ex.Message}");
        return 2;
    }
});

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
var parseResult = CommandLineParser.Parse(rootCommand, args, new ParserConfiguration());
return await parseResult.InvokeAsync(new InvocationConfiguration(), cts.Token);
