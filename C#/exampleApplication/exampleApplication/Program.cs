using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace exampleApplication
{
    internal class DeviceIo
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(
         String lpFileName,
         UInt32 dwDesiredAccess,
         UInt32 dwShareMode,
         IntPtr lpSecurityAttributes,
         UInt32 dwCreationDisposition,
         UInt32 dwFlagsAndAttributes,
         IntPtr hTemplateFile);

        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            int IoControlCode,
            byte[] InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            ref int pBytesReturned,
            IntPtr Overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);
    }
    class Program
    {
        public class Win32fileOp
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr CreateFile(
              [MarshalAs(UnmanagedType.LPTStr)] string filename,
              uint access,
              uint share,
              IntPtr securityAttributes,
              uint creationDisposition,
              uint flagsAndAttributes,
              IntPtr templateFile);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr hObject);

        }

        public static class DeviceDriver
        {
            public static bool CloseDeviceDriverHandle(IntPtr nHandle)
            {
                if (nHandle != (IntPtr.Zero - 1))
                    return Win32fileOp.CloseHandle(nHandle);
                return false;
            }
        }

        public static IntPtr GetDeviceDriverHandle()
        {
            //In this eample we call the ASrock driver (Asrock101.sys)
            return Win32fileOp.CreateFile("\\\\.\\AsrDrv101", 0xC0000000U, 3U, IntPtr.Zero, 3U, 0x4000000u, IntPtr.Zero);
        }

        static void Main(string[] args)
        {
            readMSRExample();
        }


        private static void readMSRExample()
        {
            byte[] Inbuffer = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x0c };
            IntPtr OutBuffer = DeviceIo.VirtualAlloc(IntPtr.Zero, 1024, 0x3000, 0x40);
            int pBytesReturned = 0;
            IntPtr _deviceHandle = GetDeviceDriverHandle();
            bool result = DeviceIo.DeviceIoControl(_deviceHandle, 0x222848, Inbuffer, Inbuffer.Length, OutBuffer, 1024, ref pBytesReturned, IntPtr.Zero);
            long result2 = System.Runtime.InteropServices.Marshal.ReadInt32(OutBuffer);
            Console.WriteLine(result2);
        }
    }
}

