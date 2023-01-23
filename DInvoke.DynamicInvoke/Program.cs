using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Drawing.Printing;

namespace DInvoke.DynamicInvoke
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
        [Flags]
        public enum PROCESSINFOCLASS : uint
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueryInformationProcess(
            IntPtr processHandle,
            PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            uint processInformationLength,
            IntPtr returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int MessageBoxA(
            IntPtr hWnd, 
            [MarshalAs(UnmanagedType.AnsiBStr)]string lpText, 
            [MarshalAs(UnmanagedType.AnsiBStr)] string lpCaption, 
            uint uType);
        public static void Main()
        {
            
            object[] mArgs = new object[] { IntPtr.Zero, "message", "title", (uint)0x00000000L };
            Generic.DynamicApiInvoke("user32.dll", "MessageboxA", typeof(MessageBoxA), ref mArgs);

            Console.ReadKey();

            IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));
            object[] qArgs = new object[] { 
                (IntPtr)(-1), 
                PROCESSINFOCLASS.ProcessBasicInformation, 
                pInfo, 
                (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), 
                IntPtr.Zero };
            uint ntstatus = (uint)Generic.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(NtQueryInformationProcess), ref qArgs);
            Console.WriteLine("ntstatus was 0x{0:X}", ntstatus);
            PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure((IntPtr)(qArgs[2]), typeof(PROCESS_BASIC_INFORMATION));
            Console.WriteLine("pbi.PebBaseAddress is 0x{0:X}", (long)pbi.PebBaseAddress);
            
            Console.ReadKey();
            
            TestHook();

            Console.ReadKey();
        }
        public static void TestHook()
        {
            int MessageBoxA( 
                IntPtr hWnd,
                [MarshalAs(UnmanagedType.AnsiBStr)] string lpText,
                [MarshalAs(UnmanagedType.AnsiBStr)] string lpCaption,
                uint uType
                )
                { 
                    Console.WriteLine("You called hooked message box!");
                    return (int)0;
                }
            FxHook hook;
            IntPtr user32 = default;
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.ToLower() == "user32.dll")
                    user32 = mod.BaseAddress;
            }
            IntPtr pMessageBox = Generic.GetExportAddress(user32, "MessageBoxA");
            using (hook = new FxHook(pMessageBox, (MessageBoxA)MessageBoxA))
            {
                hook.Install();
                object[] mArgs = new object[] { IntPtr.Zero, "message", "title", (uint)0x00000000L };
                Generic.DynamicApiInvoke("user32.dll", "MessageboxA", typeof(MessageBoxA), ref mArgs);
            }
        }
    }
    public class FxHook : IDisposable
    {

        const int nBytes = 13;
        // movabs r11, address
        // jmp r11

        IntPtr addr;
        Protection old;
        byte[] src = new byte[13];
        byte[] dst = new byte[13];

        public FxHook(IntPtr source, IntPtr destination)
        {
            Console.WriteLine("Source should be 0x{0:X}", (long)source);
            Console.WriteLine("Destination should be 0x{0:X}", (long)destination);
            VirtualProtect(source, nBytes, Protection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(source, src, 0, nBytes);
            dst[0] = 0x49;
            dst[1] = 0XBB;
            var dx = BitConverter.GetBytes((long)destination);
            Array.Copy(dx, 0, dst, 2, 8);
            dst[10] = 0x41;
            dst[11] = 0xFF;
            dst[12] = 0xE3;
            addr = source;
            ;
        }
        public FxHook(IntPtr source, Delegate destination) :
            this(source, Marshal.GetFunctionPointerForDelegate(destination))
        {
        }

        public void Install()
        {
            Marshal.Copy(dst, 0, addr, nBytes);
        }

        public void Uninstall()
        {
            Marshal.Copy(src, 0, addr, nBytes);
        }

        public void Dispose()
        {
            Uninstall();
            Protection x;
            VirtualProtect(addr, nBytes, old, out x);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
            Protection flNewProtect, out Protection lpflOldProtect);

        public enum Protection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

    }

}
