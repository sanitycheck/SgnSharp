using SgnSharp.Utilities;

namespace SgnSharp.Types;

public sealed class Instruction
{
    public string Mnemonic { get; init; } = string.Empty;
    public bool V64 { get; init; }
    public bool V32 { get; init; }
    public Operands[] Operands { get; init; } = [];

    public Result<OperandType> GetRandomMatchingOperandType(RegisterBitWidth srcRegSize)
    {
        if (Operands.Length != 2)
        {
            return Result<OperandType>.Failure($"{nameof(GetRandomMatchingOperandType)}: instruction operand index out of range");
        }

        var leftTypes = Operands[0].Types ?? [];
        var rightTypes = Operands[1].Types ?? [];

        if (leftTypes.Length == 0 || rightTypes.Length == 0)
        {
            return Result<OperandType>.Failure($"{nameof(GetRandomMatchingOperandType)}: instruction operand has no type");
        }

        if (leftTypes.Length != rightTypes.Length)
        {
            return Result<OperandType>.Failure($"{nameof(GetRandomMatchingOperandType)}: unsupported instruction operand types");
        }

        var indices = new List<int>();
        var sizeValue = (int)srcRegSize;
        for (var i = 0; i < leftTypes.Length; i++)
        {
            var type = leftTypes[i];
            if (string.Equals(type, $"r/m{sizeValue}", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(type, $"r{sizeValue}", StringComparison.OrdinalIgnoreCase))
            {
                indices.Add(i);
            }
        }

        if (indices.Count == 0)
        {
            return Result<OperandType>.Failure($"{nameof(GetRandomMatchingOperandType)}: no matching operand types for size {sizeValue}");
        }

        var candidates = new List<OperandType>();
        foreach (var index in indices)
        {
            var parsed = OperandTypeParser.Parse(rightTypes[index]);
            if (parsed.IsSuccess)
            {
                candidates.Add(parsed.Value);
            }
        }

        if (candidates.Count == 0)
        {
            return Result<OperandType>.Failure($"{nameof(GetRandomMatchingOperandType)}: no supported operand types");
        }

        return RandomNumberGenerator.RandomElement(candidates);
    }
}
