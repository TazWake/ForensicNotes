# =============================================================================
# Modern Windows Evidence Collection Script
# Version: 0.1
# Description: Incident response evidence collection script for Windows hosts
#              Uses built-in Windows tools and optional Sysinternals tools when available
# Requirements: Administrator privileges, PowerShell 5.1+ (Windows 10/Server 2016+)
# Usage: .\windows_data_collection.ps1 -EvidencePath "D:\evidence" [-SkipMemory] [-SkipDisk]
# Notes: This is an initial version of the script. It has not been tested.
#
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$EvidencePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipMemory,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDisk,
    
    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# Script configuration
$ScriptVersion = "1.0"
$ScriptName = "windows_data_collection.ps1"
$RequiredPSVersion = "5.1"

# Global variables
$Global:LogFile = ""
$Global:HashLog = ""
$Global:CollectionStartTime = ""
$Global:ComputerName = ""
$Global:OSVersion = ""
$Global:AvailableTools = @{}

# Function to write colored output and log
function Write-StatusMessage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "PROGRESS")]
        [string]$Level,
        
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$Level] $timestamp - $Message"
    
    switch ($Level) {
        "INFO" { 
            Write-Host "[INFO] $Message" -ForegroundColor Cyan
            Add-Content -Path $Global:LogFile -Value $logMessage
        }
        "SUCCESS" { 
            Write-Host "[SUCCESS] $Message" -ForegroundColor Green
            Add-Content -Path $Global:LogFile -Value $logMessage
        }
        "WARNING" { 
            Write-Host "[WARNING] $Message" -ForegroundColor Yellow
            Add-Content -Path $Global:LogFile -Value $logMessage
        }
        "ERROR" { 
            Write-Host "[ERROR] $Message" -ForegroundColor Red
            Add-Content -Path $Global:LogFile -Value $logMessage
        }
        "PROGRESS" { 
            Write-Host "[PROGRESS] $Message" -ForegroundColor Blue
            Add-Content -Path $Global:LogFile -Value $logMessage
        }
    }
}

# Function to calculate file hash
function Get-FileHashValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("MD5", "SHA1", "SHA256")]
        [string]$Algorithm = "SHA256"
    )
    
    if (Test-Path $FilePath) {
        try {
            $fileHash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
            $hashString = "$($fileHash.Hash) - $($fileHash.Algorithm)"
            
            # Log hash to hash log
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $hashLogEntry = "$timestamp - $Algorithm`:$($fileHash.Hash) - $FilePath"
            Add-Content -Path $Global:HashLog -Value $hashLogEntry
            
            Write-StatusMessage -Level "INFO" -Message "Hash ($Algorithm): $($fileHash.Hash) - $FilePath"
            return $hashString
        }
        catch {
            Write-StatusMessage -Level "WARNING" -Message "Failed to hash file: $FilePath - $($_.Exception.Message)"
            return "HASH_FAILED"
        }
    }
    else {
        Write-StatusMessage -Level "WARNING" -Message "File not found for hashing: $FilePath"
        return "FILE_NOT_FOUND"
    }
}

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check PowerShell version
function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion -lt [Version]$RequiredPSVersion) {
        Write-StatusMessage -Level "ERROR" -Message "PowerShell $RequiredPSVersion or higher is required. Current version: $psVersion"
        return $false
    }
    return $true
}

# Function to check and detect available tools
function Test-AvailableTools {
    Write-StatusMessage -Level "PROGRESS" -Message "Checking available tools..."
    
    # Built-in Windows tools
    $Global:AvailableTools["Get-Process"] = $true
    $Global:AvailableTools["Get-NetTCPConnection"] = $true
    $Global:AvailableTools["Get-NetAdapter"] = $true
    $Global:AvailableTools["Get-WmiObject"] = $true
    $Global:AvailableTools["Get-EventLog"] = $true
    $Global:AvailableTools["Get-WinEvent"] = $true
    
    # Optional Sysinternals tools
    $sysinternalsTools = @(
        "procexp.exe", "handle.exe", "tcpview.exe", "autoruns.exe", 
        "pslist.exe", "psloggedon.exe", "netstat.exe", "strings.exe"
    )
    
    foreach ($tool in $sysinternalsTools) {
        $toolPath = Get-Command $tool -ErrorAction SilentlyContinue
        if ($toolPath) {
            $Global:AvailableTools[$tool] = $true
            Write-StatusMessage -Level "INFO" -Message "Found Sysinternals tool: $tool"
        }
        else {
            $Global:AvailableTools[$tool] = $false
        }
    }
    
    # Check for memory capture tools
    if (Get-Command "DumpIt.exe" -ErrorAction SilentlyContinue) {
        $Global:AvailableTools["DumpIt"] = $true
        Write-StatusMessage -Level "INFO" -Message "Found memory capture tool: DumpIt"
    }
    elseif (Get-Command "winpmem.exe" -ErrorAction SilentlyContinue) {
        $Global:AvailableTools["winpmem"] = $true
        Write-StatusMessage -Level "INFO" -Message "Found memory capture tool: winpmem"
    }
    else {
        Write-StatusMessage -Level "WARNING" -Message "No memory capture tools found. Memory capture will be skipped."
    }
    
    # Check for disk imaging tools

    # ------------------------------------------------------------------------------------------
    # Future expansion plans:
    #
    # Add support for various disk imaging tools.
    # Consider: Belkasoft, Axiom Acquire, OSFClone, Guymager, etc.
    # ------------------------------------------------------------------------------------------

    if (Get-Command "ftkimager.exe" -ErrorAction SilentlyContinue) {
        $Global:AvailableTools["ftkimager"] = $true
        Write-StatusMessage -Level "INFO" -Message "Found disk imaging tool: FTK Imager"
    }
    elseif (Get-Command "dd.exe" -ErrorAction SilentlyContinue) {
        $Global:AvailableTools["dd"] = $true
        Write-StatusMessage -Level "INFO" -Message "Found disk imaging tool: dd"
    }
    else {
        Write-StatusMessage -Level "WARNING" -Message "No disk imaging tools found. Disk imaging will be skipped."
    }
    
    Write-StatusMessage -Level "SUCCESS" -Message "Tool availability check completed"
}

# Function to collect system information
function Get-SystemInformation {
    Write-StatusMessage -Level "PROGRESS" -Message "Collecting system information..."
    
    $sysInfoFile = Join-Path $EvidencePath "system_information.txt"
    
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
        $processor = Get-WmiObject -Class Win32_Processor
        $bios = Get-WmiObject -Class Win32_BIOS
        
        $sysInfo = @"
=== SYSTEM INFORMATION ===
Collection Time: $(Get-Date)
Computer Name: $($computerSystem.Name)
Domain: $($computerSystem.Domain)
Manufacturer: $($computerSystem.Manufacturer)
Model: $($computerSystem.Model)
Total Physical Memory: $([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB

=== OPERATING SYSTEM ===
OS Name: $($operatingSystem.Caption)
Version: $($operatingSystem.Version)
Build: $($operatingSystem.BuildNumber)
Install Date: $($operatingSystem.InstallDate)
Last Boot: $($operatingSystem.LastBootUpTime)
Serial Number: $($operatingSystem.SerialNumber)

=== PROCESSOR ===
Name: $($processor.Name)
Cores: $($processor.NumberOfCores)
Logical Processors: $($processor.NumberOfLogicalProcessors)
Architecture: $($processor.Architecture)

=== BIOS ===
Manufacturer: $($bios.Manufacturer)
Version: $($bios.Version)
Serial Number: $($bios.SerialNumber)

=== ENVIRONMENT VARIABLES ===
$((Get-ChildItem Env: | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "`n")

=== NETWORK ADAPTERS ===
$((Get-NetAdapter | ForEach-Object { "Name: $($_.Name), Status: $($_.Status), MAC: $($_.MacAddress)" }) -join "`n")

=== DISK DRIVES ===
$((Get-WmiObject -Class Win32_LogicalDisk | ForEach-Object { "Drive: $($_.DeviceID), Size: $([math]::Round($_.Size / 1GB, 2)) GB, Free: $([math]::Round($_.FreeSpace / 1GB, 2)) GB" }) -join "`n")

=== SERVICES ===
$((Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -First 20 | ForEach-Object { "Name: $($_.Name), DisplayName: $($_.DisplayName), Status: $($_.Status)" }) -join "`n")

=== REGISTRY STARTUP LOCATIONS ===
Current User Run:
$((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSProvider" -and $_.Name -ne "PSDrive" } | ForEach-Object { "$($_.Name) = $((Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).$($_.Name))" }) -join "`n")

Machine Run:
$((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSProvider" -and $_.Name -ne "PSDrive" } | ForEach-Object { "$($_.Name) = $((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).$($_.Name))" }) -join "`n")
"@
        
        Set-Content -Path $sysInfoFile -Value $sysInfo
        Get-FileHashValue -FilePath $sysInfoFile
        Write-StatusMessage -Level "SUCCESS" -Message "System information collected: $sysInfoFile"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect system information: $($_.Exception.Message)"
    }
}

# Function to collect process information
function Get-ProcessInformation {
    Write-StatusMessage -Level "PROGRESS" -Message "Collecting process information..."
    
    $procDir = Join-Path $EvidencePath "process_information"
    New-Item -ItemType Directory -Path $procDir -Force | Out-Null
    
    try {
        # Basic process list
        $psFile = Join-Path $procDir "running_processes.txt"
        Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, Path, StartTime | Export-Csv -Path $psFile -NoTypeInformation
        Get-FileHashValue -FilePath $psFile
        
        # Detailed process information
        $detailedFile = Join-Path $procDir "detailed_processes.txt"
        $processes = Get-Process | Select-Object -First 100
        $detailedInfo = @()
        
        foreach ($proc in $processes) {
            try {
                $procInfo = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                if ($procInfo) {
                    $detailedInfo += "PID: $($proc.Id), Name: $($proc.ProcessName), Path: $($procInfo.ExecutablePath), CommandLine: $($procInfo.CommandLine), ParentPID: $($procInfo.ParentProcessId)"
                }
            }
            catch {
                $detailedInfo += "PID: $($proc.Id), Name: $($proc.ProcessName), Error: Could not get detailed info"
            }
        }
        
        Set-Content -Path $detailedFile -Value ($detailedInfo -join "`n")
        Get-FileHashValue -FilePath $detailedFile
        
        # Use Sysinternals tools if available
        if ($Global:AvailableTools["procexp.exe"]) {
            $procexpFile = Join-Path $procDir "procexp_output.txt"
            try {
                Start-Process -FilePath "procexp.exe" -ArgumentList "/accepteula", "/s", $procexpFile -Wait -NoNewWindow
                if (Test-Path $procexpFile) {
                    Get-FileHashValue -FilePath $procexpFile
                }
            }
            catch {
                Write-StatusMessage -Level "WARNING" -Message "Failed to run procexp.exe: $($_.Exception.Message)"
            }
        }
        
        Write-StatusMessage -Level "SUCCESS" -Message "Process information collected in: $procDir"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect process information: $($_.Exception.Message)"
    }
}

# Function to collect network information
function Get-NetworkInformation {
    Write-StatusMessage -Level "PROGRESS" -Message "Collecting network information..."
    
    $netDir = Join-Path $EvidencePath "network_information"
    New-Item -ItemType Directory -Path $netDir -Force | Out-Null
    
    try {
        # TCP connections
        $tcpFile = Join-Path $netDir "tcp_connections.txt"
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Export-Csv -Path $tcpFile -NoTypeInformation
        Get-FileHashValue -FilePath $tcpFile
        
        # UDP connections
        $udpFile = Join-Path $netDir "udp_connections.txt"
        Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Export-Csv -Path $udpFile -NoTypeInformation
        Get-FileHashValue -FilePath $udpFile
        
        # Network adapters
        $adapterFile = Join-Path $netDir "network_adapters.txt"
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Export-Csv -Path $adapterFile -NoTypeInformation
        Get-FileHashValue -FilePath $adapterFile
        
        # ARP cache
        $arpFile = Join-Path $netDir "arp_cache.txt"
        Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Export-Csv -Path $arpFile -NoTypeInformation
        Get-FileHashValue -FilePath $arpFile
        
        # DNS cache
        $dnsFile = Join-Path $netDir "dns_cache.txt"
        Get-DnsClientCache | Select-Object Name, Type, Data, TTL | Export-Csv -Path $dnsFile -NoTypeInformation
        Get-FileHashValue -FilePath $dnsFile
        
        # Use Sysinternals tools if available
        if ($Global:AvailableTools["tcpview.exe"]) {
            $tcpviewFile = Join-Path $netDir "tcpview_output.txt"
            try {
                Start-Process -FilePath "tcpview.exe" -ArgumentList "/accepteula", "/s", $tcpviewFile -Wait -NoNewWindow
                if (Test-Path $tcpviewFile) {
                    Get-FileHashValue -FilePath $tcpviewFile
                }
            }
            catch {
                Write-StatusMessage -Level "WARNING" -Message "Failed to run tcpview.exe: $($_.Exception.Message)"
            }
        }
        
        Write-StatusMessage -Level "SUCCESS" -Message "Network information collected in: $netDir"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect network information: $($_.Exception.Message)"
    }
}

# Function to collect user history and artifacts
function Get-UserArtifacts {
    Write-StatusMessage -Level "PROGRESS" -Message "Collecting user artifacts..."
    
    $userDir = Join-Path $EvidencePath "user_artifacts"
    New-Item -ItemType Directory -Path $userDir -Force | Out-Null
    
    try {
        # Get all user profiles
        $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }
        
        foreach ($userProfile in $userProfiles) {
            $username = $userProfile.LocalPath.Split('\')[-1]
            $userArtifactDir = Join-Path $userDir $username
            New-Item -ItemType Directory -Path $userArtifactDir -Force | Out-Null
            
            # PowerShell history
            $psHistoryPath = Join-Path $userProfile.LocalPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path $psHistoryPath) {
                $targetPath = Join-Path $userArtifactDir "powershell_history.txt"
                Copy-Item -Path $psHistoryPath -Destination $targetPath -Force
                Get-FileHashValue -FilePath $targetPath
            }
            
            # Command prompt history
            $cmdHistoryPath = Join-Path $userProfile.LocalPath "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
            if (Test-Path $cmdHistoryPath) {
                $targetPath = Join-Path $userArtifactDir "cmd_history"
                Copy-Item -Path $cmdHistoryPath -Destination $targetPath -Recurse -Force
                Get-FileHashValue -FilePath $targetPath
            }
            
            # Recent files
            $recentPath = Join-Path $userProfile.LocalPath "AppData\Roaming\Microsoft\Windows\Recent"
            if (Test-Path $recentPath) {
                $targetPath = Join-Path $userArtifactDir "recent_files"
                Copy-Item -Path $recentPath -Destination $targetPath -Recurse -Force
                Get-FileHashValue -FilePath $targetPath
            }
            
            # Desktop items
            $desktopPath = Join-Path $userProfile.LocalPath "Desktop"
            if (Test-Path $desktopPath) {
                $targetPath = Join-Path $userArtifactDir "desktop_items"
                Copy-Item -Path $desktopPath -Destination $targetPath -Recurse -Force
                Get-FileHashValue -FilePath $targetPath
            }
            
            # Downloads folder
            $downloadsPath = Join-Path $userProfile.LocalPath "Downloads"
            if (Test-Path $downloadsPath) {
                $targetPath = Join-Path $userArtifactDir "downloads"
                Copy-Item -Path $downloadsPath -Destination $targetPath -Recurse -Force
                Get-FileHashValue -FilePath $targetPath
            }
        }
        
        Write-StatusMessage -Level "SUCCESS" -Message "User artifacts collected in: $userDir"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect user artifacts: $($_.Exception.Message)"
    }
}

# Function to collect system logs
function Get-SystemLogs {
    Write-StatusMessage -Level "PROGRESS" -Message "Collecting system logs..."
    
    $logsDir = Join-Path $EvidencePath "system_logs"
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    
    try {
        # Windows Event Logs
        $eventLogs = @("System", "Application", "Security")
        
        foreach ($logName in $eventLogs) {
            try {
                $logFile = Join-Path $logsDir "$logName`_events.evtx"
                wevtutil export-log $logName $logFile
                if (Test-Path $logFile) {
                    Get-FileHashValue -FilePath $logFile
                }
            }
            catch {
                Write-StatusMessage -Level "WARNING" -Message "Failed to export $logName log: $($_.Exception.Message)"
            }
        }
        
        # Recent Security events (last 24 hours)
        try {
            $securityFile = Join-Path $logsDir "security_recent.txt"
            $startTime = (Get-Date).AddDays(-1)
            Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -MaxEvents 1000 | 
                Select-Object TimeCreated, Id, LevelDisplayName, Message | 
                Export-Csv -Path $securityFile -NoTypeInformation
            Get-FileHashValue -FilePath $securityFile
        }
        catch {
            Write-StatusMessage -Level "WARNING" -Message "Failed to collect recent security events: $($_.Exception.Message)"
        }
        
        # Prefetch files (useful for process execution history)
        $prefetchDir = Join-Path $logsDir "prefetch"
        New-Item -ItemType Directory -Path $prefetchDir -Force | Out-Null
        
        try {
            $prefetchFiles = Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object -First 100
            foreach ($file in $prefetchFiles) {
                $targetPath = Join-Path $prefetchDir $file.Name
                Copy-Item -Path $file.FullName -Destination $targetPath -Force
                Get-FileHashValue -FilePath $targetPath
            }
        }
        catch {
            Write-StatusMessage -Level "WARNING" -Message "Failed to collect prefetch files: $($_.Exception.Message)"
        }
        
        Write-StatusMessage -Level "SUCCESS" -Message "System logs collected in: $logsDir"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect system logs: $($_.Exception.Message)"
    }
}

# Function to identify recently modified executables
function Get-RecentExecutables {
    Write-StatusMessage -Level "PROGRESS" -Message "Identifying recently modified executables..."
    
    $execFile = Join-Path $EvidencePath "recent_executables.txt"
    $fiveDaysAgo = (Get-Date).AddDays(-5)
    
    try {
        $recentExecs = @()
        $recentExecs += "=== RECENTLY MODIFIED EXECUTABLES (Last 5 Days) ==="
        $recentExecs += "Collection Time: $(Get-Date)"
        $recentExecs += "Search Time: 5 days ago from collection"
        $recentExecs += "Format: MD5_HASH | FILE_PATH | MODIFICATION_TIME"
        $recentExecs += ""
        
        # Search common executable locations
        $searchPaths = @(
            "C:\Windows\System32",
            "C:\Windows\SysWOW64", 
            "C:\Program Files",
            "C:\Program Files (x86)",
            "C:\Users"
        )
        
        $count = 0
        foreach ($searchPath in $searchPaths) {
            if (Test-Path $searchPath) {
                try {
                    $files = Get-ChildItem -Path $searchPath -Recurse -Include "*.exe", "*.dll", "*.sys" -ErrorAction SilentlyContinue | 
                             Where-Object { $_.LastWriteTime -gt $fiveDaysAgo } | 
                             Select-Object -First 200
                    
                    foreach ($file in $files) {
                        try {
                            $hash = Get-FileHashValue -Path $file.FullName -Algorithm MD5
                            $recentExecs += "$($hash.Hash) | $($file.FullName) | $($file.LastWriteTime)"
                            $count++
                            
                            if ($count -ge 1000) { break }
                        }
                        catch {
                            $recentExecs += "HASH_FAILED | $($file.FullName) | $($file.LastWriteTime)"
                        }
                    }
                }
                catch {
                    Write-StatusMessage -Level "WARNING" -Message "Failed to search path: $searchPath"
                }
            }
        }
        
        Set-Content -Path $execFile -Value ($recentExecs -join "`n")
        Get-FileHashValue -FilePath $execFile
        Write-StatusMessage -Level "SUCCESS" -Message "Recent executables list created: $execFile"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to collect recent executables: $($_.Exception.Message)"
    }
}

# Function to capture memory
function Get-MemoryDump {
    if ($SkipMemory) {
        Write-StatusMessage -Level "INFO" -Message "Memory capture skipped by user request"
        return
    }
    
    if ($Global:AvailableTools["DumpIt"]) {
        Write-StatusMessage -Level "PROGRESS" -Message "Starting memory capture with DumpIt..."
        $memoryFile = Join-Path $EvidencePath "memory_dump.raw"
        
        Write-StatusMessage -Level "WARNING" -Message "Memory capture will take several minutes depending on RAM size"
        Write-StatusMessage -Level "WARNING" -Message "Press Ctrl+C within 3 seconds to skip memory capture..."
        Start-Sleep -Seconds 3
        
        try {
            Start-Process -FilePath "DumpIt.exe" -ArgumentList "/accepteula", "/output", $memoryFile -Wait -NoNewWindow
            if (Test-Path $memoryFile) {
                Get-FileHashValue -FilePath $memoryFile
                Write-StatusMessage -Level "SUCCESS" -Message "Memory capture completed: $memoryFile"
            }
        }
        catch {
            Write-StatusMessage -Level "ERROR" -Message "Memory capture failed: $($_.Exception.Message)"
        }
    }
    elseif ($Global:AvailableTools["winpmem"]) {
        Write-StatusMessage -Level "PROGRESS" -Message "Starting memory capture with winpmem..."
        $memoryFile = Join-Path $EvidencePath "memory_dump.raw"
        
        Write-StatusMessage -Level "WARNING" -Message "Memory capture will take several minutes depending on RAM size"
        Write-StatusMessage -Level "WARNING" -Message "Press Ctrl+C within 3 seconds to skip memory capture..."
        Start-Sleep -Seconds 3
        
        try {
            Start-Process -FilePath "winpmem.exe" -ArgumentList $memoryFile -Wait -NoNewWindow
            if (Test-Path $memoryFile) {
                Get-FileHashValue -FilePath $memoryFile
                Write-StatusMessage -Level "SUCCESS" -Message "Memory capture completed: $memoryFile"
            }
        }
        catch {
            Write-StatusMessage -Level "ERROR" -Message "Memory capture failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-StatusMessage -Level "WARNING" -Message "No memory capture tools available, skipping memory capture"
    }
}

# Function to capture disk image
function Get-DiskImage {
    if ($SkipDisk) {
        Write-StatusMessage -Level "INFO" -Message "Disk imaging skipped by user request"
        return
    }
    
    Write-StatusMessage -Level "PROGRESS" -Message "Preparing disk image capture..."
    
    try {
        $systemDrive = (Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).DeviceID
        
        if ($Global:AvailableTools["ftkimager"]) {
            $imageFile = Join-Path $EvidencePath "$($env:COMPUTERNAME)_disk_image"
            Write-StatusMessage -Level "INFO" -Message "Using FTK Imager for disk imaging: $imageFile"
            
            Write-StatusMessage -Level "WARNING" -Message "Disk imaging will take a very long time depending on disk size"
            Write-StatusMessage -Level "WARNING" -Message "Press Ctrl+C within 3 seconds to skip disk imaging..."
            Start-Sleep -Seconds 3
            
            try {
                Start-Process -FilePath "ftkimager.exe" -ArgumentList $systemDrive, $imageFile, "--format", "raw" -Wait -NoNewWindow
                if (Test-Path "$imageFile.raw") {
                    Get-FileHashValue -FilePath "$imageFile.raw"
                    Write-StatusMessage -Level "SUCCESS" -Message "Disk image created: $imageFile.raw"
                }
            }
            catch {
                Write-StatusMessage -Level "ERROR" -Message "Disk imaging failed: $($_.Exception.Message)"
            }
        }
        elseif ($Global:AvailableTools["dd"]) {
            $imageFile = Join-Path $EvidencePath "$($env:COMPUTERNAME)_disk_image.raw"
            Write-StatusMessage -Level "INFO" -Message "Using dd for disk imaging: $imageFile"
            Write-StatusMessage -Level "WARNING" -Message "Raw format will be much larger than compressed formats"
            
            Write-StatusMessage -Level "WARNING" -Message "Disk imaging will take a very long time depending on disk size"
            Write-StatusMessage -Level "WARNING" -Message "Press Ctrl+C within 3 seconds to skip disk imaging..."
            Start-Sleep -Seconds 3
            
            try {
                Start-Process -FilePath "dd.exe" -ArgumentList "if=$systemDrive", "of=$imageFile", "bs=16k", "status=progress" -Wait -NoNewWindow
                if (Test-Path $imageFile) {
                    Get-FileHashValue -FilePath $imageFile
                    Write-StatusMessage -Level "SUCCESS" -Message "Raw disk image created: $imageFile"
                }
            }
            catch {
                Write-StatusMessage -Level "ERROR" -Message "Disk imaging failed: $($_.Exception.Message)"
            }
        }
        else {
            Write-StatusMessage -Level "WARNING" -Message "No disk imaging tools available, skipping disk imaging"
        }
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to prepare disk imaging: $($_.Exception.Message)"
    }
}

# Function to create evidence summary
function New-EvidenceSummary {
    Write-StatusMessage -Level "PROGRESS" -Message "Creating evidence collection summary..."
    
    $summaryFile = Join-Path $EvidencePath "evidence_summary.txt"
    
    try {
        $summary = @"
==========================================
        EVIDENCE COLLECTION SUMMARY
==========================================

Collection Details:
  Start Time: $Global:CollectionStartTime
  End Time: $(Get-Date)
  Computer Name: $Global:ComputerName
  OS Version: $Global:OSVersion
  Evidence Location: $EvidencePath

Evidence Collected:
  - System Information
  - Process Information
  - Network Information
  - User Artifacts
  - System Logs
  - Recently Modified Executables
  - Memory Dump (if tools available)
  - Disk Image (if tools available)

File Integrity:
  All evidence files have been hashed with SHA256
  Hash log: $Global:HashLog

Collection Script:
  Script: $ScriptName
  Version: $ScriptVersion
  Hash: $(Get-FileHashValue -FilePath $PSCommandPath -Algorithm SHA256)

==========================================
Collection Complete
==========================================
"@
        
        Set-Content -Path $summaryFile -Value $summary
        Get-FileHashValue -FilePath $summaryFile
        Write-StatusMessage -Level "SUCCESS" -Message "Evidence summary created: $summaryFile"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to create evidence summary: $($_.Exception.Message)"
    }
}

# Function to display help
function Show-Help {
    $helpText = @"
$ScriptName - Modern Windows Evidence Collection Script

USAGE:
    .\$ScriptName -EvidencePath <evidence_storage_path> [-SkipMemory] [-SkipDisk] [-Help]

DESCRIPTION:
    This script performs comprehensive evidence collection from a potentially
    compromised Windows host using built-in tools and optional Sysinternals tools.

PARAMETERS:
    -EvidencePath    Path where evidence will be stored (required)
    -SkipMemory     Skip memory capture (optional)
    -SkipDisk       Skip disk imaging (optional)
    -Help           Display this help message

REQUIREMENTS:
    - Administrator privileges
    - PowerShell $RequiredPSVersion or higher
    - Windows 10/Server 2016 or higher

OPTIONAL TOOLS (enhance collection):
    - Sysinternals Suite (procexp.exe, handle.exe, tcpview.exe, etc.)
    - DumpIt.exe or winpmem.exe for memory capture
    - FTK Imager or dd.exe for disk imaging

FEATURES:
    - System information collection
    - Process enumeration and analysis
    - Network connection capture
    - User artifact collection
    - Log file collection
    - Recent executable identification
    - Memory capture (if tools available)
    - Disk imaging (if tools available)
    - Comprehensive hashing and logging

EXAMPLES:
    .\$ScriptName -EvidencePath "D:\evidence"
    .\$ScriptName -EvidencePath "E:\incident_001" -SkipMemory
    .\$ScriptName -EvidencePath "F:\forensics" -SkipDisk

VERSION: $ScriptVersion
"@
    
    Write-Host $helpText
}

# Main function
function Main {
    # Check for help request
    if ($Help) {
        Show-Help
        return
    }
    
    # Check if running as Administrator
    if (-not (Test-Administrator)) {
        Write-StatusMessage -Level "ERROR" -Message "This script must be run with Administrator privileges!"
        Write-StatusMessage -Level "ERROR" -Message "Please run PowerShell as Administrator and try again."
        return
    }
    
    # Check PowerShell version
    if (-not (Test-PowerShellVersion)) {
        return
    }
    
    # Check if target path exists and is writable
    if (-not (Test-Path $EvidencePath)) {
        Write-StatusMessage -Level "ERROR" -Message "Target directory does not exist: $EvidencePath"
        return
    }
    
    if (-not (Test-Path $EvidencePath -PathType Container)) {
        Write-StatusMessage -Level "ERROR" -Message "Target path is not a directory: $EvidencePath"
        return
    }
    
    # Initialize collection
    $Global:CollectionStartTime = Get-Date
    $Global:ComputerName = $env:COMPUTERNAME
    $Global:OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    
    # Set up logging
    $Global:LogFile = Join-Path $EvidencePath "evidence_collection.log"
    $Global:HashLog = Join-Path $EvidencePath "file_hashes.txt"
    
    # Create log header
    $logHeader = @"
==========================================
    EVIDENCE COLLECTION LOG
==========================================
Script: $ScriptName
Version: $ScriptVersion
Start Time: $Global:CollectionStartTime
Computer Name: $Global:ComputerName
OS Version: $Global:OSVersion
Evidence Path: $EvidencePath
==========================================

"@
    
    Set-Content -Path $Global:LogFile -Value $logHeader
    
    # Create hash log header
    $hashHeader = @"
==========================================
        FILE INTEGRITY LOG
==========================================
Script: $ScriptName
Version: $ScriptVersion
Collection: $Global:CollectionStartTime
Format: TIMESTAMP - HASH_TYPE:HASH - FILE_PATH
==========================================

"@
    
    Set-Content -Path $Global:HashLog -Value $hashHeader
    
    Write-StatusMessage -Level "INFO" -Message "Evidence collection started"
    Write-StatusMessage -Level "INFO" -Message "Evidence will be stored in: $EvidencePath"
    Write-StatusMessage -Level "INFO" -Message "Log file: $Global:LogFile"
    Write-StatusMessage -Level "INFO" -Message "Hash log: $Global:HashLog"
    
    # Check available tools
    Test-AvailableTools
    
    # Create evidence directory structure
    New-Item -ItemType Directory -Path $EvidencePath -Force | Out-Null
    
    # Collect evidence
    Get-SystemInformation
    Get-ProcessInformation
    Get-NetworkInformation
    Get-UserArtifacts
    Get-SystemLogs
    Get-RecentExecutables
    
    # Capture memory (if tools available)
    Get-MemoryDump
    
    # Capture disk image (if tools available)
    Get-DiskImage
    
    # Create summary
    New-EvidenceSummary
    
    # Final status
    Write-StatusMessage -Level "SUCCESS" -Message "Evidence collection completed successfully!"
    Write-StatusMessage -Level "INFO" -Message "All evidence has been collected and hashed"
    Write-StatusMessage -Level "INFO" -Message "Check the log file for detailed information: $Global:LogFile"
    Write-StatusMessage -Level "INFO" -Message "Check the hash log for file integrity: $Global:HashLog"
    
    # Log final hash of log files
    Get-FileHashValue -FilePath $Global:LogFile
    Get-FileHashValue -FilePath $Global:HashLog
    
    # Set read-only permissions on evidence (Windows equivalent)
    try {
        $acl = Get-Acl $EvidencePath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $EvidencePath -AclObject $acl
    }
    catch {
        Write-StatusMessage -Level "WARNING" -Message "Could not set read-only permissions on evidence directory"
    }
}

# Run main function
Main
