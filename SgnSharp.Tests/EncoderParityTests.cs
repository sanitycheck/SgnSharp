using SgnSharp.Types;

namespace SgnSharp.Tests;

public class EncoderParityTests
{
    [Fact]
    public void CipherADFL_MatchesReferenceOutput()
    {
        var data = new byte[] { 0x00, 0x11, 0x22, 0x33 };
        var result = Encoder.CipherADFL((byte[])data.Clone(), 0x44);

        Assert.Equal(new byte[] { 0xAA, 0x88, 0x55, 0x77 }, result);
    }

    [Fact]
    public void SchemaCipher_MatchesReferenceOutput()
    {
        var data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD };
        var schema = new List<Schema>
        {
            new(Mnemonic.Xor, new byte[] { 0x01, 0x02, 0x03, 0x04 }),
            new(Mnemonic.Not, null)
        };

        var result = Encoder.SchemaCipher((byte[])data.Clone(), 0, schema);

        Assert.Equal(new byte[] { 0x14, 0x23, 0x32, 0x41, 0x55, 0x44, 0x33, 0x22 }, result);
    }
}

public class OperandParsingTests
{
    [Theory]
    [InlineData("r/m32", OperandType.RM32)]
    [InlineData("RAX", OperandType.RAX)]
    [InlineData("m", OperandType.M)]
    public void OperandTypeParser_ParsesExpectedValues(string input, OperandType expected)
    {
        var result = OperandTypeParser.Parse(input);

        if (result.IsFailure)
        {
            throw new Xunit.Sdk.XunitException(result.Error);
        }
        Assert.Equal(expected, result.Value);
    }

    [Fact]
    public void InstructionMatchingOperandType_SelectsExpectedOperand()
    {
        var instruction = new Instruction
        {
            Mnemonic = "ADD",
            V32 = true,
            V64 = true,
            Operands =
            [
                new Operands { Types = ["r/m32"] },
                new Operands { Types = ["imm32"] }
            ]
        };

        var result = instruction.GetRandomMatchingOperandType(RegisterBitWidth.Extended);

        if (result.IsFailure)
        {
            throw new Xunit.Sdk.XunitException(result.Error);
        }
        Assert.Equal(OperandType.Imm32, result.Value);
    }
}
