namespace SgnSharp.Types;

public sealed class Register
{
    public AsmToken Low { get; }
    public AsmToken High { get; }
    public AsmToken Extended { get; }
    public AsmToken? Full { get; }
    public Arch Arch { get; }

    public Register(AsmToken low, AsmToken high, AsmToken extended, AsmToken? full = null)
    {
        Low = low;
        High = high;
        Extended = extended;
        Full = full;
        Arch = full is null ? Arch.x86 : Arch.x64;
    }
}
