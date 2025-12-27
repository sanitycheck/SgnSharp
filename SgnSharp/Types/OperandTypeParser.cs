namespace SgnSharp.Types;

public static class OperandTypeParser
{
    public static Result<OperandType> Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Result<OperandType>.Failure("Operand type cannot be empty");
        }

        var normalized = value.Trim();
        return normalized.ToLowerInvariant() switch
        {
            "imm8" => OperandType.Imm8,
            "imm16" => OperandType.Imm16,
            "imm32" => OperandType.Imm32,
            "imm64" => OperandType.Imm64,
            "r8" => OperandType.R8,
            "r16" => OperandType.R16,
            "r32" => OperandType.R32,
            "r64" => OperandType.R64,
            "r/m8" => OperandType.RM8,
            "r/m16" => OperandType.RM16,
            "r/m32" => OperandType.RM32,
            "r/m64" => OperandType.RM64,
            "m" => OperandType.M,
            "m8" => OperandType.M8,
            "m16" => OperandType.M16,
            "m32" => OperandType.M32,
            "m64" => OperandType.M64,
            _ => ParseNamedRegister(normalized)
        };
    }

    private static Result<OperandType> ParseNamedRegister(string value)
    {
        return Enum.TryParse<OperandType>(value, true, out var parsed)
            ? Result<OperandType>.Success(parsed)
            : Result<OperandType>.Failure($"Unsupported operand type: {value}");
    }
}
