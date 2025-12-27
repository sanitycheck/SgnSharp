namespace SgnSharp.Types;

public readonly record struct Mnemonic(string Value)
{
    public static readonly Mnemonic Xor = new("XOR");
    public static readonly Mnemonic Sub = new("SUB");
    public static readonly Mnemonic Add = new("ADD");
    public static readonly Mnemonic Rol = new("ROL");
    public static readonly Mnemonic Ror = new("ROR");
    public static readonly Mnemonic Not = new("NOT");

    public override string ToString() => Value;
}
