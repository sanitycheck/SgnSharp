namespace SgnSharp.Types;

public readonly record struct AssemblyText(string Value)
{
    public static readonly AssemblyText Empty = new(";");

    public override string ToString() => Value;
}
