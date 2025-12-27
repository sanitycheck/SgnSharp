# SgnSharp

SgnSharp is a .NET port of EgeBalci's SGN encoder for x86/x64 payloads. It provides a library API and a console utility.

## CLI Usage

Build and run from the repo root:

```powershell
dotnet build
dotnet run --project SgnSharp.Cli -- -i path\to\payload.bin -a 64 -c 2 -M 50 -S -v
```

### CLI Flags

```
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
```

### Notes

- `--ascii` and `--badchars` are not implemented yet and will return an error.
- The CLI uses Keystone for assembly; the build copies the x64 `keystone.dll` into the output folder. If you need x86, update `SgnSharp.Cli/SgnSharp.Cli.csproj` to copy `installed\x86-windows\bin\keystone.dll` instead.

## Library Usage

```csharp
using SgnSharp;
using SgnSharp.Types;

var payload = File.ReadAllBytes("myfile.bin");
var encoder = new Encoder(
    Arch.x64,
    obfuscationLimit: 50,
    plainDecoder: false,
    encodingCount: 1,
    saveRegisters: false
);

var result = encoder.Encode(payload);
if (result.IsFailure)
{
    Console.WriteLine(result.Error);
    return;
}

File.WriteAllBytes("myfile.bin.sgn", result.Value);
```
