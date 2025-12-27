using SgnSharp.Types;

namespace SgnSharp.Utilities;

public interface IAssembler
{
    Result<byte[]> Assemble(string assembly);
    Result<int> GetAssemblySize(string assembly);
}
