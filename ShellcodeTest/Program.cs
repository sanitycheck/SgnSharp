using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ShellcodeTest
{
    class Program
    {
        // Windows API imports
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        // Constants
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint INFINITE = 0xFFFFFFFF;

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ShellcodeHarness.exe <shellcode_file_path>");
                Console.WriteLine("Example: ShellcodeHarness.exe shellcode.bin");
                return;
            }

            string filePath = args[0];

            try
            {
                Console.WriteLine($"[*] Reading shellcode from: {filePath}");
                
                // Read shellcode bytes from file
                byte[] shellcode = File.ReadAllBytes(filePath);
                Console.WriteLine($"[*] Shellcode size: {shellcode.Length} bytes");

                // Allocate memory with RWX protection
                Console.WriteLine("[*] Allocating RWX memory...");
                IntPtr address = VirtualAlloc(
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE);

                if (address == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] Failed to allocate memory. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                Console.WriteLine($"[+] Memory allocated at: 0x{address.ToInt64():X}");

                // Copy shellcode to allocated memory
                Console.WriteLine("[*] Copying shellcode to allocated memory...");
                Marshal.Copy(shellcode, 0, address, shellcode.Length);

                // Optional: Change protection (though we already allocated with PAGE_EXECUTE_READWRITE)
                uint oldProtect;
                bool protectSuccess = VirtualProtect(
                    address,
                    (uint)shellcode.Length,
                    PAGE_EXECUTE_READWRITE,
                    out oldProtect);

                if (!protectSuccess)
                {
                    Console.WriteLine($"[-] Failed to set memory protection. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                Console.WriteLine("[+] Memory protection set to PAGE_EXECUTE_READWRITE");

                // Execute shellcode in a new thread
                Console.WriteLine("[*] Executing shellcode...");
                uint threadId;
                IntPtr threadHandle = CreateThread(
                    IntPtr.Zero,
                    0,
                    address,
                    IntPtr.Zero,
                    0,
                    out threadId);

                if (threadHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] Failed to create thread. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                Console.WriteLine($"[+] Thread created (ID: {threadId})");

                // Wait for thread to complete
                Console.WriteLine("[*] Waiting for shellcode execution to complete...");
                WaitForSingleObject(threadHandle, INFINITE);

                Console.WriteLine("[+] Shellcode execution completed!");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine($"[-] File not found: {filePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
    }
}