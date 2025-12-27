namespace SgnSharp.Types;

public readonly record struct AsmToken(string Value)
{
    public override string ToString() => Value;
}
