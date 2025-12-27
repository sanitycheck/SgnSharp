using System.Buffers.Binary;
using System.Numerics;
using System.Text;
using SgnSharp.Types;
using SgnSharp.Utilities;

namespace SgnSharp;

public sealed class Encoder
{
    private readonly IAssembler assembler;
    private readonly IAssemblyGenerator assemblyGenerator;

    public Encoder(
        Arch arch,
        IAssembler? assembler = null,
        IAssemblyGenerator? assemblyGenerator = null,
        byte? seed = null,
        uint obfuscationLimit = 50,
        bool plainDecoder = false,
        uint encodingCount = 1,
        bool saveRegisters = false)
    {
        Arch = arch;
        Seed = seed ?? RandomNumberGenerator.GetRandomByte();
        ObfuscationLimit = obfuscationLimit;
        PlainDecoder = plainDecoder;
        EncodingCount = encodingCount;
        SaveRegisters = saveRegisters;

        this.assembler = assembler ?? new KeystoneAssembler(arch);
        this.assemblyGenerator = assemblyGenerator ?? new AssemblyGenerator(arch);
    }

    public Arch Arch { get; }
    public byte Seed { get; }
    public uint ObfuscationLimit { get; }
    public bool PlainDecoder { get; }
    public uint EncodingCount { get; }
    public bool SaveRegisters { get; }

    public Result<byte[]> Encode(byte[] payload)
    {
        if (payload.Length == 0)
        {
            return Result<byte[]>.Failure($"{nameof(Encode)}: Payload cannot be empty");
        }

        return EncodeInternal(payload, Seed, EncodingCount);
    }

    public static byte[] CipherADFL(byte[] data, byte seed)
    {
        for (var i = 1; i <= data.Length; i++)
        {
            var index = data.Length - i;
            var current = data[index];
            data[index] ^= seed;
            seed = (byte)((current + seed) % 256);
        }

        return data;
    }

    public static string GetSchemaTable(IReadOnlyList<Schema> schema)
    {
        var builder = new StringBuilder();
        builder.AppendLine("OPERAND\tKEY");
        foreach (var cursor in schema)
        {
            var key = cursor.Key is null
                ? "0x00000000"
                : $"0x{Convert.ToHexString(cursor.Key).ToLowerInvariant()}";
            builder.AppendLine($"{cursor.Operand}\t{key}");
        }

        return builder.ToString();
    }

    public Result<double> CalculateAverageGarbageInstructionSize()
    {
        var average = 0.0;
        for (var i = 0; i < 100; i++)
        {
            var randomGarbageAssembly = assemblyGenerator.GenerateGarbageAssembly();
            if (randomGarbageAssembly.IsFailure)
            {
                return Result<double>.Failure(randomGarbageAssembly.Error);
            }

            var garbage = assembler.Assemble(randomGarbageAssembly.Value.ToString());
            if (garbage.IsFailure)
            {
                return Result<double>.Failure(garbage.Error);
            }

            average += garbage.Value.Length;
        }

        return average / 100;
    }

    public Result<byte[]> Assemble(string assembly) => assembler.Assemble(assembly);

    public Result<int> GetAssemblySize(string assembly) => assembler.GetAssemblySize(assembly);

    public string DebugAssembly(string assembly)
    {
        foreach (var instruction in assembly.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var result = assembler.Assemble(instruction);
            if (result.IsFailure)
            {
                return instruction;
            }
        }

        return string.Empty;
    }

    private Result<byte[]> EncodeInternal(byte[] payload, byte seed, uint encodingCount)
    {
        var workingPayload = new List<byte>(payload);
        if (SaveRegisters)
        {
            workingPayload.AddRange(GetRegisterSaveSuffixes());
        }

        var garbage = GenerateGarbageInstructions();
        if (garbage.IsFailure)
        {
            return Result<byte[]>.Failure(garbage.Error);
        }

        workingPayload.InsertRange(0, garbage.Value);
        var cipheredPayload = CipherADFL(workingPayload.ToArray(), seed);

        var encodedPayload = AddADFLDecoder(cipheredPayload, seed);
        if (encodedPayload.IsFailure)
        {
            return Result<byte[]>.Failure(encodedPayload.Error);
        }

        var finalPayload = encodedPayload.Value;
        if (!PlainDecoder)
        {
            var decoderGarbage = GenerateGarbageInstructions();
            if (decoderGarbage.IsFailure)
            {
                return Result<byte[]>.Failure(decoderGarbage.Error);
            }

            finalPayload = decoderGarbage.Value.Concat(finalPayload).ToArray();
            var schemaSize = ((finalPayload.Length - cipheredPayload.Length) / (Arch == Arch.x86 ? 4 : 8)) + 1;
            var randomSchema = NewCipherSchema(schemaSize);
            var obfuscatedPayload = SchemaCipher(finalPayload, 0, randomSchema);

            var schemaDecoderPayload = AddSchemaDecoder(obfuscatedPayload, randomSchema);
            if (schemaDecoderPayload.IsFailure)
            {
                return Result<byte[]>.Failure(schemaDecoderPayload.Error);
            }

            finalPayload = schemaDecoderPayload.Value;
        }

        if (encodingCount > 1)
        {
            var nextSeed = RandomNumberGenerator.GetRandomByte();
            var recursive = EncodeInternal(finalPayload, nextSeed, encodingCount - 1);
            if (recursive.IsFailure)
            {
                return Result<byte[]>.Failure(recursive.Error);
            }

            finalPayload = recursive.Value;
        }

        if (SaveRegisters)
        {
            finalPayload = GetRegisterSavePrefixes().Concat(finalPayload).ToArray();
        }

        return finalPayload;
    }

    internal static byte[] SchemaCipher(byte[] data, int index, IReadOnlyList<Schema> schema)
    {
        foreach (var cursor in schema)
        {
            switch (cursor.Operand)
            {
                case var op when op == Mnemonic.Xor:
                    BinaryPrimitives.WriteUInt32BigEndian(
                        data.AsSpan(index, 4),
                        BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(index, 4)) ^
                        BinaryPrimitives.ReadUInt32LittleEndian(cursor.Key!)
                    );
                    break;
                case var op when op == Mnemonic.Add:
                    BinaryPrimitives.WriteUInt32LittleEndian(
                        data.AsSpan(index, 4),
                        (uint)((BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(index, 4)) -
                                BinaryPrimitives.ReadUInt32BigEndian(cursor.Key!)) % 0xFFFFFFFF)
                    );
                    break;
                case var op when op == Mnemonic.Sub:
                    BinaryPrimitives.WriteUInt32LittleEndian(
                        data.AsSpan(index, 4),
                        (uint)((BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(index, 4)) +
                                BinaryPrimitives.ReadUInt32BigEndian(cursor.Key!)) % 0xFFFFFFFF)
                    );
                    break;
                case var op when op == Mnemonic.Rol:
                    BinaryPrimitives.WriteUInt32LittleEndian(
                        data.AsSpan(index, 4),
                        BitOperations.RotateLeft(
                            BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(index, 4)),
                            -unchecked((int)BinaryPrimitives.ReadUInt32BigEndian(cursor.Key!))
                        )
                    );
                    break;
                case var op when op == Mnemonic.Ror:
                    BinaryPrimitives.WriteUInt32LittleEndian(
                        data.AsSpan(index, 4),
                        BitOperations.RotateLeft(
                            BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(index, 4)),
                            unchecked((int)BinaryPrimitives.ReadUInt32BigEndian(cursor.Key!))
                        )
                    );
                    break;
                case var op when op == Mnemonic.Not:
                    BinaryPrimitives.WriteUInt32BigEndian(
                        data.AsSpan(index, 4),
                        ~BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(index, 4))
                    );
                    break;
            }

            index += 4;
        }

        return data;
    }

    private Result<byte[]> GenerateGarbageInstructions()
    {
        var randomGarbageAssembly = assemblyGenerator.GenerateGarbageAssembly();
        if (randomGarbageAssembly.IsFailure)
        {
            return Result<byte[]>.Failure(randomGarbageAssembly.Error);
        }

        var garbage = assembler.Assemble(randomGarbageAssembly.Value.ToString());
        if (garbage.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(GenerateGarbageInstructions)}: {garbage.Error}");
        }

        var garbageBytes = garbage.Value;
        if (RandomNumberGenerator.CoinFlip())
        {
            var garbageJump = GenerateGarbageJump();
            if (garbageJump.IsFailure)
            {
                return Result<byte[]>.Failure(garbageJump.Error);
            }

            garbageBytes = RandomNumberGenerator.CoinFlip()
                ? garbageJump.Value.Concat(garbageBytes).ToArray()
                : garbageBytes.Concat(garbageJump.Value).ToArray();
        }

        var limit = (int)ObfuscationLimit;
        if (garbageBytes.Length <= limit)
        {
            return garbageBytes;
        }

        return GenerateGarbageInstructions();
    }

    private Result<byte[]> GenerateGarbageJump()
    {
        var padding = RandomNumberGenerator.GetRandomBytes((int)ObfuscationLimit / 10);
        return AddJmpOver(padding);
    }

    private Result<byte[]> AddADFLDecoder(byte[] payload, byte seed)
    {
        var decoderAssembly = NewDecoderAssembly(payload.Length, seed);
        if (decoderAssembly.IsFailure)
        {
            return Result<byte[]>.Failure(decoderAssembly.Error);
        }

        var decoder = assembler.Assemble(decoderAssembly.Value.ToString());
        if (decoder.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddADFLDecoder)}: {decoder.Error}");
        }

        return decoder.Value.Concat(payload).ToArray();
    }

    private Result<AssemblyText> NewDecoderAssembly(int payloadSize, byte seed)
    {
        var decoder = Arch == Arch.x86 ? DecoderStubs.X86 : DecoderStubs.X64;
        var reg = assemblyGenerator.GetSafeRandomRegister(GetNativeRegisterWidth(), new AsmToken("ECX"));
        if (reg.IsFailure)
        {
            return Result<AssemblyText>.Failure(reg.Error);
        }

        var regL = assemblyGenerator.GetSafeRandomRegister(RegisterBitWidth.Low, reg.Value, new AsmToken("CL"));
        if (regL.IsFailure)
        {
            return Result<AssemblyText>.Failure(regL.Error);
        }

        decoder = decoder.Replace("{R}", reg.Value.ToString());
        decoder = decoder.Replace("{RL}", regL.Value.ToString());
        decoder = decoder.Replace("{K}", $"0x{seed:x}");
        decoder = decoder.Replace("{S}", $"0x{payloadSize:x}");
        return new AssemblyText(decoder);
    }

    private Result<byte[]> AddSchemaDecoder(byte[] payload, IReadOnlyList<Schema> schema)
    {
        var index = 0;

        var garbage = GenerateGarbageInstructions();
        if (garbage.IsFailure)
        {
            return Result<byte[]>.Failure(garbage.Error);
        }

        payload = garbage.Value.Concat(payload).ToArray();
        index += garbage.Value.Length;

        var callOver = AddCallOver(payload);
        if (callOver.IsFailure)
        {
            return Result<byte[]>.Failure(callOver.Error);
        }

        payload = callOver.Value;

        garbage = GenerateGarbageInstructions();
        if (garbage.IsFailure)
        {
            return Result<byte[]>.Failure(garbage.Error);
        }

        payload = payload.Concat(garbage.Value).ToArray();

        var reg = assemblyGenerator.GetSafeRandomRegister(
            GetNativeRegisterWidth(),
            assemblyGenerator.GetStackPointer()
        );
        if (reg.IsFailure)
        {
            return Result<byte[]>.Failure(reg.Error);
        }

        var pop = assembler.Assemble($"POP {reg.Value};");
        if (pop.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddSchemaDecoder)}: {pop.Error}");
        }

        payload = payload.Concat(pop.Value).ToArray();

        foreach (var cursor in schema)
        {
            garbage = GenerateGarbageInstructions();
            if (garbage.IsFailure)
            {
                return Result<byte[]>.Failure(garbage.Error);
            }

            payload = payload.Concat(garbage.Value).ToArray();

            var stepAssembly = cursor.Key is null
                ? $"\t{cursor.Operand} DWORD PTR [{reg.Value}+0x{index:x}];\n"
                : $"\t{cursor.Operand} DWORD PTR [{reg.Value}+0x{index:x}],0x{BinaryPrimitives.ReadUInt32BigEndian(cursor.Key):x};\n";

            var decipherStep = assembler.Assemble(stepAssembly);
            if (decipherStep.IsFailure)
            {
                return Result<byte[]>.Failure($"{nameof(AddSchemaDecoder)}: {decipherStep.Error}");
            }

            payload = payload.Concat(decipherStep.Value).ToArray();
            index += 4;
        }

        var returnInstruction = assembler.Assemble($"jmp {reg.Value};");
        if (returnInstruction.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddSchemaDecoder)}: {returnInstruction.Error}");
        }

        return payload.Concat(returnInstruction.Value).ToArray();
    }

    private IReadOnlyList<Schema> NewCipherSchema(int count)
    {
        var schema = new List<Schema>(count);
        for (var i = 0; i < count; i++)
        {
            var op = assemblyGenerator.GetRandomOperand();
            byte[]? key = null;

            if (op == Mnemonic.Not)
            {
                key = null;
            }
            else if (op == Mnemonic.Rol || op == Mnemonic.Ror)
            {
                key = [0, 0, 0, RandomNumberGenerator.GetRandomByte()];
            }
            else
            {
                key = RandomNumberGenerator.GetRandomBytes(4);
            }

            schema.Add(new Schema(op, key));
        }

        return schema;
    }

    private Result<byte[]> AddCallOver(byte[] payload)
    {
        var call = $"call 0x{payload.Length + 5:x}";
        var callBin = assembler.Assemble(call);
        if (callBin.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddCallOver)}: {callBin.Error}");
        }

        return callBin.Value.Concat(payload).ToArray();
    }

    private Result<byte[]> AddJmpOver(byte[] payload)
    {
        var jmp = $"jmp 0x{payload.Length + 2:x}";
        var jmpBin = assembler.Assemble(jmp);
        if (jmpBin.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddJmpOver)}: {jmpBin.Error}");
        }

        return jmpBin.Value.Concat(payload).ToArray();
    }

    private Result<byte[]> AddCondJmpOver(byte[] payload)
    {
        var randomConditional = RandomNumberGenerator.RandomElement(Instructions.ConditionalJumpMnemonics);
        var jmp = $"{randomConditional} 0x{payload.Length + 2:x}";
        var jmpBin = assembler.Assemble(jmp);
        if (jmpBin.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(AddCondJmpOver)}: {jmpBin.Error}");
        }

        return jmpBin.Value.Concat(payload).ToArray();
    }

    private Result<byte[]> GenerateIPToStack()
    {
        var callBin = assembler.Assemble("call 5");
        if (callBin.IsFailure)
        {
            return Result<byte[]>.Failure($"{nameof(GenerateIPToStack)}: {callBin.Error}");
        }

        return callBin.Value;
    }

    private byte[] GetRegisterSavePrefixes() =>
        Arch == Arch.x86 ? Instructions.X86_REG_SAVE_PREFIX : Instructions.X64_REG_SAVE_PREFIX;

    private byte[] GetRegisterSaveSuffixes() =>
        Arch == Arch.x86 ? Instructions.X86_REG_SAVE_SUFFIX : Instructions.X64_REG_SAVE_SUFFIX;

    private RegisterBitWidth GetNativeRegisterWidth() =>
        Arch == Arch.x86 ? RegisterBitWidth.Extended : RegisterBitWidth.Full;
}
