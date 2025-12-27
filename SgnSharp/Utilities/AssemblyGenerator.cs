using System.Text.Json;
using SgnSharp.Types;
using SgnSharp;

namespace SgnSharp.Utilities;

public interface IAssemblyGenerator
{
    Mnemonic GetRandomOperand();
    string GetRandomSafeAssembly();
    Result<AssemblyText> GetRandomUnsafeAssembly(AsmToken destReg);
    Result<Instruction> GetRandomUnsafeMnemonic(RegisterBitWidth opRegSize);
    Result<AsmToken> GetRandomOperandValue(OperandType operandType);
    Result<AsmToken> GetRandomRegister(RegisterBitWidth regSize);
    AsmToken GetRandomStackAddress();
    AsmToken GetStackPointer();
    AsmToken GetBasePointer();
    Result<AsmToken> GetSafeRandomRegister(RegisterBitWidth regSize, params AsmToken[] excludes);
    Result<AssemblyText> GenerateGarbageAssembly();
    Result<AssemblyText> GetRandomFunctionAssembly();
}

public sealed class AssemblyGenerator : IAssemblyGenerator
{
    private static readonly Mnemonic[] OPERANDS =
    [
        Mnemonic.Xor,
        Mnemonic.Sub,
        Mnemonic.Add,
        Mnemonic.Rol,
        Mnemonic.Ror,
        Mnemonic.Not,
    ];

    private static readonly JsonSerializerOptions InstructionJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly Lazy<Result<IReadOnlyList<Instruction>>> UnsafeInstructionCache = new(() =>
    {
        try
        {
            var instructions = JsonSerializer.Deserialize<List<Instruction>>(
                Instructions.InstructionSet,
                InstructionJsonOptions
            );

            if (instructions is null || instructions.Count == 0)
            {
                return Result<IReadOnlyList<Instruction>>.Failure(
                    $"{nameof(AssemblyGenerator)}: Failed to decode instructions"
                );
            }

            return instructions;
        }
        catch (Exception ex)
        {
            return Result<IReadOnlyList<Instruction>>.Failure(
                $"{nameof(AssemblyGenerator)}: Instruction JSON decode failed: {ex.Message}"
            );
        }
    });

    private readonly Arch arch;
    private readonly IReadOnlyList<Register> registers;

    public AssemblyGenerator(Arch arch)
    {
        this.arch = arch;
        registers = InitializeRegisters(arch);
    }

    public Mnemonic GetRandomOperand() => RandomNumberGenerator.RandomElement(OPERANDS);

    public string GetRandomSafeAssembly()
    {
        List<string> newSafeGarbageInstructions = new(Instructions.SafeGarbageInstructions);
        newSafeGarbageInstructions.AddRange(
            Instructions.ConditionalJumpMnemonics.Select(jmp => $"{jmp} {{L}};{{G}};{{L}}:")
        );
        return RandomNumberGenerator.RandomElement(newSafeGarbageInstructions);
    }

    public Result<AssemblyText> GetRandomUnsafeAssembly(AsmToken destReg)
    {
        var is32Bit = arch == Arch.x86;
        var archValue = is32Bit ? 32 : 64;

        var maxExponent = 3 + (archValue / 64);
        var exponent = Random.Shared.Next(maxExponent) + 3;
        var randRegSize = (RegisterBitWidth)(1 << exponent);

        foreach (var register in registers)
        {
            var matches = is32Bit
                ? register.Extended.Equals(destReg)
                : register.Full is { } full && full.Equals(destReg);

            if (!matches) continue;

            var subReg = GetRegisterByWidth(register, randRegSize);
            if (subReg.IsFailure) return Result<AssemblyText>.Failure(subReg.Error);

            var newUnsafeMnemonic = GetRandomUnsafeMnemonic(randRegSize);
            if (newUnsafeMnemonic.IsFailure) return Result<AssemblyText>.Failure(newUnsafeMnemonic.Error);

            var operandType = newUnsafeMnemonic.Value.GetRandomMatchingOperandType(randRegSize);
            if (operandType.IsFailure) return Result<AssemblyText>.Failure(operandType.Error);

            var operand = GetRandomOperandValue(operandType.Value);
            if (operand.IsFailure) return Result<AssemblyText>.Failure(operand.Error);

            return new AssemblyText(
                $"{newUnsafeMnemonic.Value.Mnemonic} {subReg.Value},{operand.Value};"
            );
        }

        return Result<AssemblyText>.Failure(
            $"{nameof(GetRandomUnsafeAssembly)}: Failed to generate unsafe assembly for destination register '{destReg}'"
        );
    }

    public Result<Instruction> GetRandomUnsafeMnemonic(RegisterBitWidth opRegSize)
    {
        var instructionsResult = UnsafeInstructionCache.Value;
        if (instructionsResult.IsFailure)
        {
            return Result<Instruction>.Failure(instructionsResult.Error);
        }

        var instructions = instructionsResult.Value;
        var sizeValue = (int)opRegSize;

        for (var i = 0; i < 1024; i++)
        {
            var instr = RandomNumberGenerator.RandomElement(instructions);
            if (!IsInstructionForArchitecture(instr) || instr.Operands.Length != 2)
            {
                continue;
            }

            if (instr.Operands[0].Types.Any(type =>
                    string.Equals(type, $"r/m{sizeValue}", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(type, $"r{sizeValue}", StringComparison.OrdinalIgnoreCase)))
            {
                return instr;
            }
        }

        return Result<Instruction>.Failure(
            $"{nameof(GetRandomUnsafeMnemonic)}: No matching instruction for register size {sizeValue}"
        );
    }

    public Result<AsmToken> GetRandomOperandValue(OperandType operandType) =>
        operandType switch
        {
            OperandType.Imm8 => new AsmToken($"0x{RandomNumberGenerator.GetRandomByte() % 127:x}"),
            OperandType.Imm16 => new AsmToken($"0x{Random.Shared.Next(0, 32767):x}"),
            OperandType.Imm32 => new AsmToken($"0x{Random.Shared.NextInt64(0, int.MaxValue):x}"),
            OperandType.Imm64 => new AsmToken($"0x{RandomNumberGenerator.GetRandomUInt64():x}"),

            OperandType.R8 => GetRandomRegister(RegisterBitWidth.Low),
            OperandType.R16 => GetRandomRegister(RegisterBitWidth.High),
            OperandType.R32 => GetRandomRegister(RegisterBitWidth.Extended),
            OperandType.R64 => GetRandomRegister(RegisterBitWidth.Full),

            OperandType.RM8 => RandomNumberGenerator.CoinFlip()
                ? GetRandomOperandValue(OperandType.M8)
                : GetRandomRegister(RegisterBitWidth.Low),
            OperandType.RM16 => RandomNumberGenerator.CoinFlip()
                ? GetRandomOperandValue(OperandType.M16)
                : GetRandomRegister(RegisterBitWidth.High),
            OperandType.RM32 => RandomNumberGenerator.CoinFlip()
                ? GetRandomOperandValue(OperandType.M32)
                : GetRandomRegister(RegisterBitWidth.Extended),
            OperandType.RM64 => RandomNumberGenerator.CoinFlip()
                ? GetRandomOperandValue(OperandType.M64)
                : GetRandomRegister(RegisterBitWidth.Full),

            OperandType.M => GetRandomStackAddress(),
            OperandType.M8 => new AsmToken($"BYTE PTR {GetRandomStackAddress()}"),
            OperandType.M16 => new AsmToken($"WORD PTR {GetRandomStackAddress()}"),
            OperandType.M32 => new AsmToken($"DWORD PTR {GetRandomStackAddress()}"),
            OperandType.M64 => new AsmToken($"QWORD PTR {GetRandomStackAddress()}"),

            OperandType.RAX or OperandType.RCX or OperandType.RDX or OperandType.RBX or
            OperandType.RSP or OperandType.RBP or OperandType.RSI or OperandType.RDI or
            OperandType.EAX or OperandType.ECX or OperandType.EDX or OperandType.EBX or
            OperandType.ESP or OperandType.EBP or OperandType.ESI or OperandType.EDI or
            OperandType.AX or OperandType.CX or OperandType.DX or OperandType.BX or
            OperandType.SP or OperandType.BP or OperandType.SI or OperandType.DI or
            OperandType.AH or OperandType.AL or OperandType.CH or OperandType.CL or
            OperandType.DH or OperandType.DL or OperandType.BH or OperandType.BL or
            OperandType.SPL or OperandType.BPL or OperandType.SIL or OperandType.DIL
                => new AsmToken(operandType.ToString()),

            _ => Result<AsmToken>.Failure(
                $"{nameof(GetRandomOperandValue)}: Unsupported instruction operand type: {operandType}"
            )
        };

    public Result<AsmToken> GetRandomRegister(RegisterBitWidth regSize)
    {
        var register = RandomNumberGenerator.RandomElement(registers);
        return GetRegisterByWidth(register, regSize);
    }

    public AsmToken GetRandomStackAddress()
    {
        var stackPointer = GetStackPointer();
        return RandomNumberGenerator.CoinFlip()
            ? new AsmToken($"[{stackPointer}+0x{RandomNumberGenerator.GetRandomByte():x}]")
            : new AsmToken($"[{stackPointer}-0x{RandomNumberGenerator.GetRandomByte():x}]");
    }

    public AsmToken GetStackPointer() => arch switch
    {
        Arch.x86 => new AsmToken("ESP"),
        Arch.x64 => new AsmToken("RSP"),
        _ => new AsmToken("RSP")
    };

    public AsmToken GetBasePointer() => arch switch
    {
        Arch.x86 => new AsmToken("EBP"),
        Arch.x64 => new AsmToken("RBP"),
        _ => new AsmToken("RBP")
    };

    public Result<AsmToken> GetSafeRandomRegister(RegisterBitWidth regSize, params AsmToken[] excludes)
    {
        var eligible = registers
            .Where(reg => !excludes.Any(exclude => MatchesRegister(reg, exclude)))
            .ToList();

        if (eligible.Count == 0)
        {
            return Result<AsmToken>.Failure($"{nameof(GetSafeRandomRegister)}: No registers available after exclusions");
        }

        var selected = RandomNumberGenerator.RandomElement(eligible);
        return GetRegisterByWidth(selected, regSize);
    }

    public Result<AssemblyText> GenerateGarbageAssembly()
    {
        if (!RandomNumberGenerator.CoinFlip())
        {
            return AssemblyText.Empty;
        }

        var randomGarbageAssembly = GetRandomSafeAssembly();
        var register = GetRandomRegister(GetNativeRegisterWidth());
        if (register.IsFailure)
        {
            return Result<AssemblyText>.Failure(register.Error);
        }

        var nested = GenerateGarbageAssembly();
        if (nested.IsFailure)
        {
            return Result<AssemblyText>.Failure(nested.Error);
        }

        randomGarbageAssembly = randomGarbageAssembly.Replace("{R}", register.Value.ToString());
        randomGarbageAssembly = randomGarbageAssembly.Replace("{K}", $"0x{RandomNumberGenerator.GetRandomByte():x}");
        randomGarbageAssembly = randomGarbageAssembly.Replace("{L}", RandomLabel());
        randomGarbageAssembly = randomGarbageAssembly.Replace("{G}", nested.Value.ToString());
        return new AssemblyText(randomGarbageAssembly + ";");
    }

    public static string RandomLabel()
    {
        const string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Span<char> buffer = stackalloc char[5];
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = letters[Random.Shared.Next(letters.Length)];
        }

        return new string(buffer);
    }

    public Result<AssemblyText> GetRandomFunctionAssembly()
    {
        var bp = GetBasePointer();
        var sp = GetStackPointer();

        var prologue = $"PUSH {bp};";
        prologue += $"MOV {bp},{sp};";
        prologue += $"SUB {sp},0x{RandomNumberGenerator.GetRandomByte():x};";

        var garbage = GenerateGarbageAssembly();
        if (garbage.IsFailure)
        {
            return Result<AssemblyText>.Failure(garbage.Error);
        }

        var epilogue = $"MOV {sp},{bp};";
        epilogue += $"POP {bp};";

        return new AssemblyText(prologue + garbage.Value + epilogue);
    }

    private RegisterBitWidth GetNativeRegisterWidth() =>
        arch == Arch.x86 ? RegisterBitWidth.Extended : RegisterBitWidth.Full;

    private bool IsInstructionForArchitecture(Instruction instruction) =>
        (instruction.V32 && arch == Arch.x86) || (instruction.V64 && arch == Arch.x64);

    private static bool MatchesRegister(Register register, AsmToken token) =>
        register.Low.Equals(token) ||
        register.High.Equals(token) ||
        register.Extended.Equals(token) ||
        (register.Full?.Equals(token) ?? false);

    private static Result<AsmToken> GetRegisterByWidth(Register register, RegisterBitWidth regSize) =>
        regSize switch
        {
            RegisterBitWidth.Low => register.Low,
            RegisterBitWidth.High => register.High,
            RegisterBitWidth.Extended => register.Extended,
            RegisterBitWidth.Full => register.Full ??
                                      Result<AsmToken>.Failure(
                                          $"{nameof(GetRandomRegister)}: {nameof(RegisterBitWidth.Full)} is not valid for this architecture"
                                      ),
            _ => Result<AsmToken>.Failure($"{nameof(GetRandomRegister)}: Invalid register bit width supplied"),
        };

    private IReadOnlyList<Register> InitializeRegisters(Arch arch)
    {
        List<Register> registers = [];
        if (arch == Arch.x86)
        {
            registers.AddRange([
                new Register(new AsmToken("AL"), new AsmToken("AX"), new AsmToken("EAX")),
                new Register(new AsmToken("BL"), new AsmToken("BX"), new AsmToken("EBX")),
                new Register(new AsmToken("CL"), new AsmToken("CX"), new AsmToken("ECX")),
                new Register(new AsmToken("DL"), new AsmToken("DX"), new AsmToken("EDX")),
                new Register(new AsmToken("AL"), new AsmToken("SI"), new AsmToken("ESI")),
                new Register(new AsmToken("BL"), new AsmToken("DI"), new AsmToken("EDI")),
            ]);
            return registers;
        }

        registers.AddRange([
            new Register(new AsmToken("AL"), new AsmToken("AX"), new AsmToken("EAX"), new AsmToken("RAX")),
            new Register(new AsmToken("BL"), new AsmToken("BX"), new AsmToken("EBX"), new AsmToken("RBX")),
            new Register(new AsmToken("CL"), new AsmToken("CX"), new AsmToken("ECX"), new AsmToken("RCX")),
            new Register(new AsmToken("DL"), new AsmToken("DX"), new AsmToken("EDX"), new AsmToken("RDX")),
            new Register(new AsmToken("SIL"), new AsmToken("SI"), new AsmToken("ESI"), new AsmToken("RSI")),
            new Register(new AsmToken("DIL"), new AsmToken("DI"), new AsmToken("EDI"), new AsmToken("RDI")),
            new Register(new AsmToken("R8B"), new AsmToken("R8W"), new AsmToken("R8D"), new AsmToken("R8")),
            new Register(new AsmToken("R9B"), new AsmToken("R9W"), new AsmToken("R9D"), new AsmToken("R9")),
            new Register(new AsmToken("R10B"), new AsmToken("R10W"), new AsmToken("R10D"), new AsmToken("R10")),
            new Register(new AsmToken("R11B"), new AsmToken("R11W"), new AsmToken("R11D"), new AsmToken("R11")),
            new Register(new AsmToken("R12B"), new AsmToken("R12W"), new AsmToken("R12D"), new AsmToken("R12")),
            new Register(new AsmToken("R13B"), new AsmToken("R13W"), new AsmToken("R13D"), new AsmToken("R13")),
            new Register(new AsmToken("R14B"), new AsmToken("R14W"), new AsmToken("R14D"), new AsmToken("R14")),
            new Register(new AsmToken("R15B"), new AsmToken("R15W"), new AsmToken("R15D"), new AsmToken("R15")),
        ]);
        return registers;
    }
}
