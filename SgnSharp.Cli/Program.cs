using System.Reflection;
using SgnSharp;
using SgnSharp.Types;

var optionsResult = CliOptions.Parse(args);
if (optionsResult.IsFailure)
{
    Console.Error.WriteLine(optionsResult.Error);
    Console.Error.WriteLine();
    Console.Error.WriteLine(CliOptions.GetUsage());
    return 1;
}

var options = optionsResult.Value;
if (options.ShowHelp)
{
    Console.WriteLine(CliOptions.GetUsage());
    return 0;
}

if (options.ShowVersion)
{
    var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
    Console.WriteLine($"SgnSharp.Cli {version}");
    return 0;
}

if (options.UseAscii || !string.IsNullOrWhiteSpace(options.BadChars))
{
    Console.Error.WriteLine("The --ascii and --badchars options are not supported yet.");
    return 2;
}

if (options.InputPath is null)
{
    Console.Error.WriteLine("Input file is required.");
    Console.Error.WriteLine();
    Console.Error.WriteLine(CliOptions.GetUsage());
    return 1;
}

byte[] payload;
try
{
    payload = File.ReadAllBytes(options.InputPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to read input file: {ex.Message}");
    return 1;
}

var encoder = new Encoder(
    options.Arch,
    seed: options.Seed,
    obfuscationLimit: options.MaxObfuscation,
    plainDecoder: options.PlainDecoder,
    encodingCount: options.EncodingCount,
    saveRegisters: options.SaveRegisters
);

var encodeResult = encoder.Encode(payload);
if (encodeResult.IsFailure)
{
    Console.Error.WriteLine(encodeResult.Error);
    return 1;
}

var outputPath = options.OutputPath ?? GetDefaultOutputPath(options.InputPath);
try
{
    File.WriteAllBytes(outputPath, encodeResult.Value);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to write output file: {ex.Message}");
    return 1;
}

if (options.Verbose)
{
    Console.WriteLine($"Input: {options.InputPath}");
    Console.WriteLine($"Output: {outputPath}");
    Console.WriteLine($"Architecture: {(int)options.Arch}");
    Console.WriteLine($"Encoding count: {options.EncodingCount}");
    Console.WriteLine($"Max obfuscation: {options.MaxObfuscation}");
    Console.WriteLine($"Plain decoder: {options.PlainDecoder}");
    Console.WriteLine($"Save registers: {options.SaveRegisters}");
    Console.WriteLine($"Seed: 0x{encoder.Seed:x2}");
    Console.WriteLine($"Input size: {payload.Length} bytes");
    Console.WriteLine($"Output size: {encodeResult.Value.Length} bytes");
}

return 0;

static string GetDefaultOutputPath(string inputPath)
{
    var directory = Path.GetDirectoryName(inputPath) ?? ".";
    var fileName = Path.GetFileName(inputPath);
    return Path.Combine(directory, $"{fileName}.sgn");
}

internal sealed record CliOptions(
    string? InputPath = null,
    string? OutputPath = null,
    Arch Arch = Arch.x64,
    uint EncodingCount = 1,
    uint MaxObfuscation = 50,
    bool PlainDecoder = false,
    bool UseAscii = false,
    bool SaveRegisters = false,
    string? BadChars = null,
    bool Verbose = false,
    bool ShowHelp = false,
    bool ShowVersion = false,
    byte? Seed = null)
{
    public static Result<CliOptions> Parse(string[] args)
    {
        var options = new CliOptions();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg is "-h" or "--help")
            {
                options = options with { ShowHelp = true };
                continue;
            }

            if (arg is "-v" or "--verbose")
            {
                options = options with { Verbose = true };
                continue;
            }

            if (arg is "--version")
            {
                options = options with { ShowVersion = true };
                continue;
            }

            if (arg is "--plain")
            {
                options = options with { PlainDecoder = true };
                continue;
            }

            if (arg is "--ascii")
            {
                options = options with { UseAscii = true };
                continue;
            }

            if (arg is "-S" or "--safe")
            {
                options = options with { SaveRegisters = true };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "-i", "--input", out var input))
            {
                options = options with { InputPath = input };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "-o", "--out", out var output))
            {
                options = options with { OutputPath = output };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "-a", "--arch", out var archValue))
            {
                var arch = archValue switch
                {
                    "32" => Arch.x86,
                    "64" => Arch.x64,
                    _ => (Arch?)null
                };

                if (arch is null)
                {
                    return Result<CliOptions>.Failure("Invalid architecture. Use 32 or 64.");
                }

                options = options with { Arch = arch.Value };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "-c", "--enc", out var encValue))
            {
                if (!uint.TryParse(encValue, out var encCount) || encCount < 1)
                {
                    return Result<CliOptions>.Failure("Invalid encoding count.");
                }

                options = options with { EncodingCount = encCount };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "-M", "--max", out var maxValue))
            {
                if (!uint.TryParse(maxValue, out var max) || max == 0)
                {
                    return Result<CliOptions>.Failure("Invalid max obfuscation value.");
                }

                options = options with { MaxObfuscation = max };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "--badchars", out var badChars))
            {
                options = options with { BadChars = badChars };
                continue;
            }

            if (TryReadValue(arg, args, ref i, "--seed", out var seedValue))
            {
                var parsedSeed = ParseHexByte(seedValue);
                if (parsedSeed.IsFailure)
                {
                    return Result<CliOptions>.Failure(parsedSeed.Error);
                }

                options = options with { Seed = parsedSeed.Value };
                continue;
            }

            return Result<CliOptions>.Failure($"Unknown argument: {arg}");
        }

        return options;
    }

    private static Result<byte> ParseHexByte(string value)
    {
        var normalized = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;

        if (normalized.Length is < 1 or > 2 ||
            !byte.TryParse(normalized, System.Globalization.NumberStyles.HexNumber, null, out var parsed))
        {
            return Result<byte>.Failure("Seed must be a hex byte value (e.g., 0x2A).");
        }

        return parsed;
    }

    private static bool TryReadValue(
        string arg,
        string[] args,
        ref int index,
        string shortName,
        string longName,
        out string value)
    {
        value = string.Empty;
        if ((!string.IsNullOrEmpty(shortName) &&
             arg.Equals(shortName, StringComparison.OrdinalIgnoreCase)) ||
            arg.Equals(longName, StringComparison.OrdinalIgnoreCase))
        {
            if (index + 1 >= args.Length)
            {
                return false;
            }

            value = args[++index];
            return true;
        }

        var prefix = longName + "=";
        if (arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            value = arg[prefix.Length..];
            return true;
        }

        var shortPrefix = shortName + "=";
        if (arg.StartsWith(shortPrefix, StringComparison.OrdinalIgnoreCase))
        {
            value = arg[shortPrefix.Length..];
            return true;
        }

        return false;
    }

    private static bool TryReadValue(
        string arg,
        string[] args,
        ref int index,
        string longName,
        out string value) =>
        TryReadValue(arg, args, ref index, string.Empty, longName, out value);

    public static string GetUsage()
    {
        return """
            SgnSharp.Cli - SGN encoder for x86/x64 payloads

            Usage: sgnsharp -i <input> [options]

            Flags:
              -h, --help               Show help
              -i, --input=STRING       Input binary path
              -o, --out=STRING         Encoded output binary name
              -a, --arch=64            Binary architecture (32/64)
              -c, --enc=1              Number of times to encode the binary
              -M, --max=50             Maximum number of bytes for decoder obfuscation
                  --plain              Do not encode the decoder stub
                  --ascii              Generate ASCII printable payload (not supported yet)
              -S, --safe               Preserve all register values
                  --badchars=STRING    Disallow specified bytes in hex form (not supported yet)
                  --seed=BYTE          Hex seed value (e.g. 0x2a)
              -v, --verbose            Verbose output
                  --version            Show version
            """;
    }
}
