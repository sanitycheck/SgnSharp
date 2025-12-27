using System.Runtime.InteropServices;
using SgnSharp.Types;

namespace SgnSharp.Utilities;

public sealed class KeystoneAssembler : IAssembler
{
    private readonly Arch arch;

    public KeystoneAssembler(Arch arch)
    {
        this.arch = arch;
    }

    public Result<byte[]> Assemble(string assembly)
    {
        if (string.IsNullOrWhiteSpace(assembly))
        {
            return Result<byte[]>.Failure($"{nameof(Assemble)}: Assembly cannot be empty");
        }

        var mode = arch == Arch.x86 ? KsMode.KS_MODE_32 : KsMode.KS_MODE_64;
        var openResult = KeystoneNative.ks_open(KsArch.KS_ARCH_X86, (int)mode, out var handle);
        if (openResult != KsError.KS_ERR_OK)
        {
            return Result<byte[]>.Failure($"{nameof(Assemble)}: {KeystoneNative.GetErrorMessage(openResult)}");
        }

        try
        {
            var optionResult = KeystoneNative.ks_option(
                handle,
                KsOptionType.KS_OPT_SYNTAX,
                (UIntPtr)KsOptionValue.KS_OPT_SYNTAX_INTEL
            );

            if (optionResult != KsError.KS_ERR_OK)
            {
                return Result<byte[]>.Failure($"{nameof(Assemble)}: {KeystoneNative.GetErrorMessage(optionResult)}");
            }

            var result = KeystoneNative.ks_asm(handle, assembly, 0, out var encoding, out var size, out _);
            if (result != 0)
            {
                var error = KeystoneNative.ks_errno(handle);
                if (encoding != IntPtr.Zero)
                {
                    KeystoneNative.ks_free(encoding);
                }
                return Result<byte[]>.Failure($"{nameof(Assemble)}: {KeystoneNative.GetErrorMessage(error)}");
            }

            var sizeValue = checked((int)size.ToUInt64());
            var bytes = new byte[sizeValue];
            if (sizeValue > 0)
            {
                Marshal.Copy(encoding, bytes, 0, sizeValue);
            }

            if (encoding != IntPtr.Zero)
            {
                KeystoneNative.ks_free(encoding);
            }

            return bytes;
        }
        finally
        {
            KeystoneNative.ks_close(handle);
        }
    }

    public Result<int> GetAssemblySize(string assembly)
    {
        var result = Assemble(assembly);
        return result.IsSuccess ? result.Value.Length : Result<int>.Failure(result.Error);
    }

    private static class KeystoneNative
    {
        private const string DllName = "keystone.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern KsError ks_open(KsArch arch, int mode, out IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern KsError ks_close(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern KsError ks_errno(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ks_strerror(KsError code);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern KsError ks_option(IntPtr handle, KsOptionType type, UIntPtr value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ks_asm(
            IntPtr handle,
            string assembly,
            ulong address,
            out IntPtr encoding,
            out UIntPtr size,
            out UIntPtr statCount
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void ks_free(IntPtr pointer);

        public static string GetErrorMessage(KsError error)
        {
            var message = Marshal.PtrToStringAnsi(ks_strerror(error));
            return string.IsNullOrWhiteSpace(message) ? $"Keystone error {error}" : message;
        }
    }

    private enum KsArch
    {
        KS_ARCH_X86 = 4
    }

    [Flags]
    private enum KsMode
    {
        KS_MODE_32 = 1 << 2,
        KS_MODE_64 = 1 << 3
    }

    private enum KsOptionType
    {
        KS_OPT_SYNTAX = 1
    }

    [Flags]
    private enum KsOptionValue
    {
        KS_OPT_SYNTAX_INTEL = 1 << 0
    }

    private enum KsError
    {
        KS_ERR_OK = 0
    }
}
