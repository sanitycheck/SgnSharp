namespace SgnSharp.Utilities;
using System.Security.Cryptography;
using  RNG = System.Security.Cryptography.RandomNumberGenerator;
public static class RandomNumberGenerator
{
    public static byte[] GetRandomBytes(int size) => RNG.GetBytes(size);
    public static byte GetRandomByte() => RNG.GetBytes(1)[0];
    public static bool CoinFlip() => Random.Shared.Next(2) == 0;
    public static ulong GetRandomUInt64()
    {
        Span<byte> buffer = stackalloc byte[8];
        RNG.Fill(buffer);
        return BitConverter.ToUInt64(buffer);
    }
    
    public static T RandomElement<T>(IReadOnlyList<T> list)
    {
        if (list.Count == 0)
            throw new InvalidOperationException("List is empty.");

        return list[Random.Shared.Next(list.Count)];
    }

}
