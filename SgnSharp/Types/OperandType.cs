namespace SgnSharp.Types;

public enum OperandType
{
    // Immediates
    Imm8,
    Imm16,
    Imm32,
    Imm64,

    // Registers (explicit on purpose)
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    AX, CX, DX, BX, SP, BP, SI, DI,
    AH, AL, CH, CL, DH, DL, BH, BL,
    SPL, BPL, SIL, DIL,

    // Registers by size
    R8,
    R16,
    R32,
    R64,

    // Register or memory
    RM8,
    RM16,
    RM32,
    RM64,

    // Memory
    M,
    M8,
    M16,
    M32,
    M64
}
