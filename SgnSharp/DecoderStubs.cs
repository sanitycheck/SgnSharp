namespace SgnSharp;

public static class DecoderStubs
{
    public const string X86 = """
                               CALL getip
                           getip:
                               POP {R}
                               MOV ECX,{S}
                               MOV {RL},{K}
                           decode:
                               XOR BYTE PTR [{R}+ECX+data-6],{RL}
                               ADD {RL},BYTE PTR [{R}+ECX+data-6]
                               LOOP decode
                           data:
                           """;

    public const string X64 = """
                               MOV {RL},{K}
                               MOV RCX,{S}
                               LEA {R},[RIP+data-1]
                           decode:
                               XOR BYTE PTR [{R}+RCX],{RL}
                               ADD {RL},BYTE PTR [{R}+RCX]
                               LOOP decode
                           data:
                           """;
}
