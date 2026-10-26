// ============================================================================
//  LoadSim.cs - Warden benign test target ("full simulator")
//  ------------------------------------------------------------------
//  THIS PROGRAM IS 100% BENIGN. It performs NO network activity, writes
//  NO files outside its own console output, and never touches AMSI, ETW
//  or any security product. It exists so malware analysts can verify
//  that every Warden detection layer fires correctly inside a lab VM.
//
//  What it simulates (all local, all harmless):
//    Step 1  Assembly.Load(byte[])      -> in-memory .NET assembly load
//    Step 2  Reflection.Emit            -> dynamic module creation
//    Step 3  VirtualAlloc RWX + fake MZ -> private executable PE region
//    Step 4  VirtualProtect -> RX       -> executable protection change
//    Step 5  cmd.exe child spawn        -> child process telemetry
//
//  Expected Warden findings: inmemory_module, dynamic_module,
//  exec_region + dump, valloc_exec, vprotect_exec, childproc
//  (NOT amsi_tamper / etw_tamper - those must stay silent).
// ============================================================================
using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Threading;

namespace WardenSim
{
    internal static class LoadSim
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize,
            uint dwFreeType);

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_READ = 0x20;

        private static void Banner(string step, string why)
        {
            Console.WriteLine();
            Console.WriteLine("[LoadSim] {0}", step);
            Console.WriteLine("[LoadSim]   -> {0}", why);
            Thread.Sleep(600);
        }

        private static int Main(string[] args)
        {
            Console.WriteLine("==========================================================");
            Console.WriteLine(" LoadSim - Warden benign detection-verification target");
            Console.WriteLine(" 100% BENIGN: no network, no AV tampering, no persistence");
            Console.WriteLine("==========================================================");

            // ---- Step 1: in-memory assembly load (Assembly.Load(byte[])) ----
            Banner("Step 1/5  Assembly.Load(byte[])",
                   "in-memory managed assembly load (no image base)");
            try
            {
                string self = Assembly.GetExecutingAssembly().Location;
                byte[] raw = File.ReadAllBytes(self);
                Assembly loaded = Assembly.Load(raw);
                Console.WriteLine("[LoadSim]   loaded assembly: {0} (modules: {1})",
                    loaded.GetName().Name, loaded.GetModules().Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LoadSim]   step skipped: {0}", ex.Message);
            }

            // ---- Step 2: dynamic module via Reflection.Emit ------------------
            Banner("Step 2/5  Reflection.Emit dynamic module",
                   "COR_PRF_MODULE_DYNAMIC event should fire");
            try
            {
                AssemblyName an = new AssemblyName("LoadSimDynamic");
                AssemblyBuilder ab = AppDomain.CurrentDomain.DefineDynamicAssembly(
                    an, AssemblyBuilderAccess.Run);
                ModuleBuilder mb = ab.DefineDynamicModule("SimModule");
                TypeBuilder tb = mb.DefineType("SimType", TypeAttributes.Public);
                MethodBuilder meth = tb.DefineMethod("Ping",
                    MethodAttributes.Public | MethodAttributes.Static,
                    typeof(void), Type.EmptyTypes);
                ILGenerator il = meth.GetILGenerator();
                il.EmitWriteLine("[LoadSim]   hello from a dynamic module");
                il.Emit(OpCodes.Ret);
                Type t = tb.CreateType();
                t.GetMethod("Ping").Invoke(null, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LoadSim]   step skipped: {0}", ex.Message);
            }

            // ---- Step 3: private executable MZ region ------------------------
            Banner("Step 3/5  VirtualAlloc RWX + fake PE header",
                   "memory scanner should find a private executable MZ region");
            IntPtr region = VirtualAlloc(IntPtr.Zero, (UIntPtr)0x4000,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (region != IntPtr.Zero)
            {
                byte[] fake = new byte[0x4000];
                fake[0] = (byte)'M'; fake[1] = (byte)'Z';
                // e_lfanew -> "PE\0\0" at 0x80, AMD64 magic
                fake[0x3C] = 0x80;
                fake[0x80] = (byte)'P'; fake[0x81] = (byte)'E';
                fake[0x84] = 0x64;                    // machine = AMD64
                fake[0x88] = 0x0B; fake[0x89] = 0x01; // optional hdr magic 0x20B
                // fill the rest with pseudo-random high-entropy bytes
                Random rnd = new Random(1337);
                for (int i = 0x100; i < fake.Length; i++) fake[i] = (byte)rnd.Next(256);
                Marshal.Copy(fake, 0, region, fake.Length);
                Console.WriteLine("[LoadSim]   RWX region at 0x{0:X} filled (8 KB)",
                    region.ToInt64());

                // ---- Step 4: protection hardening (VirtualProtect -> RX) -----
                Banner("Step 4/5  VirtualProtect to PAGE_EXECUTE_READ",
                       "executable protection change telemetry");
                uint oldProt;
                VirtualProtect(region, (UIntPtr)0x1000,
                    PAGE_EXECUTE_READ, out oldProt);
                Console.WriteLine("[LoadSim]   first page: RWX -> RX");

                // give the Warden scanner a window to observe and dump
                Console.WriteLine("[LoadSim]   holding region for 5 s so the"
                                   + " scanner can catch it ...");
                Thread.Sleep(5000);
                VirtualFree(region, UIntPtr.Zero, MEM_RELEASE);
                Console.WriteLine("[LoadSim]   region released");
            }
            else
            {
                Console.WriteLine("[LoadSim]   VirtualAlloc failed: {0}",
                    Marshal.GetLastWin32Error());
            }

            // ---- Step 5: child process spawn ---------------------------------
            Banner("Step 5/5  cmd.exe child spawn",
                   "child process telemetry (CreateProcessW hook)");
            try
            {
                System.Diagnostics.Process p =
                    System.Diagnostics.Process.Start("cmd.exe", "/c echo loadsim-child-ok");
                if (p != null)
                {
                    p.WaitForExit(5000);
                    Console.WriteLine("[LoadSim]   child exited with {0}", p.ExitCode);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[LoadSim]   step skipped: {0}", ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("==========================================================");
            Console.WriteLine(" LoadSim complete - check the Warden session report.");
            Console.WriteLine(" Expected: inmemory_module, dynamic_module, exec_region,");
            Console.WriteLine("           dump_saved, valloc_exec, vprotect_exec,");
            Console.WriteLine("           childproc | NOT amsi_tamper / etw_tamper");
            Console.WriteLine("==========================================================");
            return 0;
        }
    }
}
