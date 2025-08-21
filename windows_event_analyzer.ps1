# =============================================================================
# Windows Event Log Security Analyzer
# Version: 0.1Beta
# Description: Analyzes Windows security.evtx files to identify process creation
#              events (Event ID 4688) that lack corresponding logon events (Event ID 4624)
#              for the same Logon ID. This helps identify potential security anomalies.
# Requirements: PowerShell 5.1+, Windows Event Log access
# Usage: .\windows_event_analyzer.ps1 -EventLogPath "C:\path\to\security.evtx" [-OutputPath "C:\output\path"]
# Notes: This is a BETA version and has not been thoroughly tested in production.
#        Use with caution and validate results in your environment.
#
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the security.evtx file to analyze")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$EventLogPath,
    
    [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Output directory for analysis results")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Get-Location),
    
    [Parameter(Mandatory = $false, HelpMessage = "Show detailed verbose output")]
    [switch]$ShowVerbose,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show this help message")]
    [switch]$Help
)

# Script Configuration
$ScriptVersion = "0.1Beta"
$ScriptName = "windows_event_analyzer.ps1"
$Author = "Taz Wake"

# Global variables
$Global:AnalysisResults = @{
    ProcessCreationEvents = @()
    LogonEvents = @()
    Anomalies = @()
    Summary = @{}
}

# Function to display help information
function Show-Help {
    param()
    
    $helpText = @"
$ScriptName - Windows Security Event Log Analyzer v$ScriptVersion

DESCRIPTION:
    This script analyzes Windows security.evtx files to identify process creation
    events that lack corresponding logon events, which may indicate security anomalies.

USAGE:
    .\$ScriptName -EventLogPath <path_to_security.evtx> [-OutputPath <output_directory>] [-Verbose] [-Help]

PARAMETERS:
    -EventLogPath    Path to the security.evtx file to analyze (REQUIRED)
    -OutputPath      Output directory for analysis results (OPTIONAL, defaults to current directory)
    -Verbose         Show detailed verbose output (OPTIONAL)
    -Help            Show this help message (OPTIONAL)

EXAMPLES:
    .\$ScriptName -EventLogPath "C:\logs\security.evtx"
    .\$ScriptName -EventLogPath "C:\logs\security.evtx" -OutputPath "C:\analysis_results" -Verbose
    .\$ScriptName -Help

REQUIREMENTS:
    - PowerShell 5.1 or later
    - Access to the security.evtx file
    - Sufficient permissions to read event log files

OUTPUT:
    - Analysis report in HTML format
    - CSV export of anomalies
    - Detailed log file
    - Summary statistics

BETA VERSION NOTES:
    - This is a BETA version and may contain bugs
    - Test thoroughly in your environment before production use
    - Some event parsing may not work with all Windows versions
    - Performance may vary with large event log files

"@
    
    Write-Host $helpText
    exit 0
}

# Function to write status messages with timestamps
function Write-StatusMessage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoNewline
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        "DEBUG" { "Cyan" }
        default { "White" }
    }
    
    $statusMessage = "[$timestamp] $Level`: $Message"
    
    if ($ShowVerbose -or $Level -in @("ERROR", "WARNING", "SUCCESS")) {
        Write-Host $statusMessage -ForegroundColor $color -NoNewline:$NoNewline
    }
    
    # Always log to file
    Add-Content -Path $logFile -Value $statusMessage
}

# Function to validate input parameters and environment
function Test-Environment {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Validating environment and parameters..."
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-StatusMessage -Level "ERROR" -Message "PowerShell 5.1 or later is required. Current version: $psVersion"
        exit 1
    }
    Write-StatusMessage -Level "INFO" -Message "PowerShell version: $psVersion"
    
    # Validate event log file
    if (-not (Test-Path $EventLogPath -PathType Leaf)) {
        Write-StatusMessage -Level "ERROR" -Message "Event log file not found: $EventLogPath"
        exit 1
    }
    
    $fileInfo = Get-Item $EventLogPath
    if ($fileInfo.Extension -ne ".evtx") {
        Write-StatusMessage -Level "WARNING" -Message "File extension is not .evtx: $($fileInfo.Extension)"
    }
    
    Write-StatusMessage -Level "INFO" -Message "Event log file validated: $EventLogPath"
    Write-StatusMessage -Level "INFO" -Message "File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB"
    
    # Validate output path
    if (-not (Test-Path $OutputPath -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-StatusMessage -Level "INFO" -Message "Created output directory: $OutputPath"
        }
        catch {
            Write-StatusMessage -Level "ERROR" -Message "Failed to create output directory: $OutputPath"
            exit 1
        }
    }
    
    Write-StatusMessage -Level "SUCCESS" -Message "Environment validation completed successfully"
}

# Function to initialize logging and output files
function Initialize-OutputFiles {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Initializing output files..."
    
    $script:logFile = Join-Path $OutputPath "event_analysis.log"
    $script:htmlReport = Join-Path $OutputPath "security_analysis_report.html"
    $script:csvReport = Join-Path $OutputPath "security_anomalies.csv"
    $script:summaryFile = Join-Path $OutputPath "analysis_summary.txt"
    
    # Create log file header
    $logHeader = @"
=============================================================================
                    WINDOWS SECURITY EVENT LOG ANALYSIS
=============================================================================
Script: $ScriptName
Version: $ScriptVersion
Author: $Author
Analysis Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Event Log: $EventLogPath
Output Directory: $OutputPath
=============================================================================

"@
    
    Set-Content -Path $logFile -Value $logHeader
    
    # Create CSV header
    $csvHeader = "Timestamp,EventID,LogonID,ProcessName,CommandLine,ComputerName,AnomalyType,Details"
    Set-Content -Path $csvReport -Value $csvHeader
    
    Write-StatusMessage -Level "SUCCESS" -Message "Output files initialized successfully"
}

# Function to extract Event ID 4688 (Process Creation) events
function Get-ProcessCreationEvents {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Extracting Process Creation events (Event ID 4688)..."
    
    try {
        # Load the event log file
        $events = Get-WinEvent -Path $EventLogPath -FilterXPath "*[System[EventID=4688]]" -ErrorAction Stop
        
        Write-StatusMessage -Level "INFO" -Message "Found $($events.Count) Process Creation events"
        
        $processEvents = @()
        $eventCount = 0
        
        foreach ($eventRecord in $events) {
            $eventCount++
            if ($eventCount % 100 -eq 0) {
                Write-StatusMessage -Level "INFO" -Message "Processing event $eventCount of $($events.Count)..."
            }
            
            try {
                # Extract relevant information from the event
                $eventData = @{
                    TimeCreated = $eventRecord.TimeCreated
                    EventID = $eventRecord.Id
                    LogonID = $eventRecord.Properties[7].Value  # Logon ID field
                    ProcessName = $eventRecord.Properties[5].Value  # New Process Name
                    CommandLine = $eventRecord.Properties[8].Value  # Command Line
                    ComputerName = $eventRecord.MachineName
                    EventRecordID = $eventRecord.RecordId
                }
                
                # Validate Logon ID
                if ($eventData.LogonID -and $eventData.LogonID -ne "0x0") {
                    $processEvents += $eventData
                }
                else {
                    Write-StatusMessage -Level "WARNING" -Message "Event $($eventRecord.RecordId) has invalid Logon ID: $($eventData.LogonID)"
                }
            }
            catch {
                Write-StatusMessage -Level "WARNING" -Message "Failed to parse event $($eventRecord.RecordId): $($_.Exception.Message)"
                continue
            }
        }
        
        $Global:AnalysisResults.ProcessCreationEvents = $processEvents
        $Global:AnalysisResults.Summary.ProcessCreationCount = $processEvents.Count
        
        Write-StatusMessage -Level "SUCCESS" -Message "Successfully extracted $($processEvents.Count) valid Process Creation events"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to extract Process Creation events: $($_.Exception.Message)"
        exit 1
    }
}

# Function to extract Event ID 4624 (Logon) events
function Get-LogonEvents {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Extracting Logon events (Event ID 4624)..."
    
    try {
        # Load the event log file
        $events = Get-WinEvent -Path $EventLogPath -FilterXPath "*[System[EventID=4624]]" -ErrorAction Stop
        
        Write-StatusMessage -Level "INFO" -Message "Found $($events.Count) Logon events"
        
        $logonEvents = @()
        $eventCount = 0
        
        foreach ($eventRecord in $events) {
            $eventCount++
            if ($eventCount % 100 -eq 0) {
                Write-StatusMessage -Level "INFO" -Message "Processing event $eventCount of $($events.Count)..."
            }
            
            try {
                # Extract relevant information from the event
                $eventData = @{
                    TimeCreated = $eventRecord.TimeCreated
                    EventID = $eventRecord.Id
                    LogonID = $eventRecord.Properties[7].Value  # Logon ID field
                    LogonType = $eventRecord.Properties[8].Value  # Logon Type
                    UserName = $eventRecord.Properties[5].Value  # Account Name
                    Domain = $eventRecord.Properties[6].Value  # Account Domain
                    ComputerName = $eventRecord.MachineName
                    EventRecordID = $eventRecord.RecordId
                }
                
                # Validate Logon ID
                if ($eventData.LogonID -and $eventData.LogonID -ne "0x0") {
                    $logonEvents += $eventData
                }
                else {
                    Write-StatusMessage -Level "WARNING" -Message "Event $($eventRecord.RecordId) has invalid Logon ID: $($eventData.LogonID)"
                }
            }
            catch {
                Write-StatusMessage -Level "WARNING" -Message "Failed to parse event $($eventRecord.RecordId): $($_.Exception.Message)"
                continue
            }
        }
        
        $Global:AnalysisResults.LogonEvents = $logonEvents
        $Global:AnalysisResults.Summary.LogonCount = $logonEvents.Count
        
        Write-StatusMessage -Level "SUCCESS" -Message "Successfully extracted $($logonEvents.Count) valid Logon events"
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Failed to extract Logon events: $($_.Exception.Message)"
        exit 1
    }
}

# Function to identify anomalies (process creation without corresponding logon)
function Find-Anomalies {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Analyzing events for anomalies..."
    
    $anomalies = @()
    $processCount = 0
    
    foreach ($processEvent in $Global:AnalysisResults.ProcessCreationEvents) {
        $processCount++
        if ($processCount % 100 -eq 0) {
            Write-StatusMessage -Level "INFO" -Message "Analyzing process $processCount of $($Global:AnalysisResults.ProcessCreationEvents.Count)..."
        }
        
        $logonID = $processEvent.LogonID
        $correspondingLogon = $Global:AnalysisResults.LogonEvents | Where-Object { $_.LogonID -eq $logonID }
        
        if (-not $correspondingLogon) {
            $anomaly = @{
                Timestamp = $processEvent.TimeCreated
                EventID = $processEvent.EventID
                LogonID = $logonID
                ProcessName = $processEvent.ProcessName
                CommandLine = $processEvent.CommandLine
                ComputerName = $processEvent.ComputerName
                AnomalyType = "Missing Logon Event"
                Details = "Process creation event found without corresponding logon event for Logon ID: $logonID"
            }
            
            $anomalies += $anomaly
            
            # Add to CSV report
            $csvLine = "$($anomaly.Timestamp),$($anomaly.EventID),$($anomaly.LogonID),$($anomaly.ProcessName),`"$($anomaly.CommandLine)`",$($anomaly.ComputerName),$($anomaly.AnomalyType),$($anomaly.Details)"
            Add-Content -Path $csvReport -Value $csvLine
        }
    }
    
    $Global:AnalysisResults.Anomalies = $anomalies
    $Global:AnalysisResults.Summary.AnomalyCount = $anomalies.Count
    
    Write-StatusMessage -Level "SUCCESS" -Message "Analysis completed. Found $($anomalies.Count) anomalies"
}

# Function to export HTML report
function Export-HTMLReport {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Generating HTML report..."
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Event Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .summary-item { margin: 10px 0; }
        .anomaly { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .anomaly-highlight { background-color: #f8d7da; border-color: #f5c6cb; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { color: #e74c3c; font-weight: bold; }
        .info { color: #3498db; }
        .success { color: #27ae60; }
        .beta-notice { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Windows Security Event Analysis Report</h1>
        
        <div class="beta-notice">
            <strong>⚠️ BETA VERSION NOTICE:</strong> This report was generated by a beta version of the Windows Event Log Analyzer. 
            Please validate all findings in your environment before taking action.
        </div>
        
        <div class="summary">
            <h2>📊 Analysis Summary</h2>
            <div class="summary-item"><strong>Analysis Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</strong></div>
            <div class="summary-item"><strong>Event Log File:</strong> $EventLogPath</div>
            <div class="summary-item"><strong>Total Process Creation Events:</strong> $($Global:AnalysisResults.Summary.ProcessCreationCount)</div>
            <div class="summary-item"><strong>Total Logon Events:</strong> $($Global:AnalysisResults.Summary.LogonCount)</div>
            <div class="summary-item"><strong>Anomalies Detected:</strong> <span class="warning">$($Global:AnalysisResults.Summary.AnomalyCount)</span></div>
        </div>
        
        <h2>🚨 Security Anomalies Detected</h2>
"@
    
    if ($Global:AnalysisResults.Anomalies.Count -eq 0) {
        $htmlContent += @"
        <div class="success">
            <strong>✅ No anomalies detected!</strong> All process creation events have corresponding logon events.
        </div>
"@
    }
    else {
        $htmlContent += @"
        <p class="warning">The following $($Global:AnalysisResults.Anomalies.Count) anomalies were detected:</p>
        
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Logon ID</th>
                    <th>Process Name</th>
                    <th>Command Line</th>
                    <th>Computer</th>
                    <th>Anomaly Type</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($anomaly in $Global:AnalysisResults.Anomalies) {
            $htmlContent += @"
                <tr class="anomaly">
                    <td>$($anomaly.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))</td>
                    <td>$($anomaly.LogonID)</td>
                    <td>$($anomaly.ProcessName)</td>
                    <td>$($anomaly.CommandLine)</td>
                    <td>$($anomaly.ComputerName)</td>
                    <td class="warning">$($anomaly.AnomalyType)</td>
                </tr>
"@
        }
        
        $htmlContent += @"
            </tbody>
        </table>
"@
    }
    
    $htmlContent += @"
        
        <h2>📋 Analysis Details</h2>
        <div class="info">
            <p><strong>What this analysis means:</strong></p>
            <ul>
                <li>Process Creation events (Event ID 4688) show when new processes are started</li>
                <li>Logon events (Event ID 4624) show successful user authentication</li>
                <li>Each process should have a corresponding logon event with the same Logon ID</li>
                <li>Missing logon events may indicate security issues or incomplete logging</li>
            </ul>
        </div>
        
        <div class="warning">
            <p><strong>Important Notes:</strong></p>
            <ul>
                <li>This is a BETA version analysis tool</li>
                <li>Some legitimate processes may not have corresponding logon events</li>
                <li>Always investigate anomalies in context with other security events</li>
                <li>Consider system-specific configurations and logging policies</li>
            </ul>
        </div>
        
        <hr>
        <p><em>Report generated by $ScriptName v$ScriptVersion on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</em></p>
    </div>
</body>
</html>
"@
    
    Set-Content -Path $htmlReport -Value $htmlContent -Encoding UTF8
    Write-StatusMessage -Level "SUCCESS" -Message "HTML report generated: $htmlReport"
}

# Function to export summary report
function Export-SummaryReport {
    param()
    
    Write-StatusMessage -Level "INFO" -Message "Generating summary report..."
    
    $summaryContent = @"
=============================================================================
                    WINDOWS SECURITY EVENT ANALYSIS SUMMARY
=============================================================================
Analysis Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Script: $ScriptName
Version: $ScriptVersion
Event Log: $EventLogPath
Output Directory: $OutputPath

ANALYSIS RESULTS:
- Total Process Creation Events (4688): $($Global:AnalysisResults.Summary.ProcessCreationCount)
- Total Logon Events (4624): $($Global:AnalysisResults.Summary.LogonCount)
- Anomalies Detected: $($Global:AnalysisResults.Summary.AnomalyCount)

ANOMALY DETAILS:
"@
    
    if ($Global:AnalysisResults.Anomalies.Count -eq 0) {
        $summaryContent += "No anomalies detected. All process creation events have corresponding logon events.`n"
    }
    else {
        foreach ($anomaly in $Global:AnalysisResults.Anomalies) {
            $summaryContent += @"
- Timestamp: $($anomaly.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))
  Logon ID: $($anomaly.LogonID)
  Process: $($anomaly.ProcessName)
  Command: $($anomaly.CommandLine)
  Computer: $($anomaly.ComputerName)
  Anomaly: $($anomaly.AnomalyType)

"@
        }
    }
    
    $summaryContent += @"
FILES GENERATED:
- Log File: $logFile
- HTML Report: $htmlReport
- CSV Report: $csvReport
- Summary: $summaryFile

BETA VERSION NOTES:
- This analysis was performed by a beta version tool
- Validate all findings in your environment
- Some legitimate processes may not have corresponding logon events
- Consider system-specific configurations and logging policies

=============================================================================
"@
    
    Set-Content -Path $summaryFile -Value $summaryContent -Encoding UTF8
    Write-StatusMessage -Level "SUCCESS" -Message "Summary report generated: $summaryFile"
}

# Function to display final results
function Show-FinalResults {
    param()
    
    Write-StatusMessage -Level "SUCCESS" -Message "Analysis completed successfully!"
    Write-StatusMessage -Level "INFO" -Message "Results Summary:"
    Write-StatusMessage -Level "INFO" -Message "  - Process Creation Events: $($Global:AnalysisResults.Summary.ProcessCreationCount)"
    Write-StatusMessage -Level "INFO" -Message "  - Logon Events: $($Global:AnalysisResults.Summary.LogonCount)"
    Write-StatusMessage -Level "INFO" -Message "  - Anomalies Detected: $($Global:AnalysisResults.Summary.AnomalyCount)"
    
    if ($Global:AnalysisResults.Anomalies.Count -gt 0) {
        Write-StatusMessage -Level "WARNING" -Message "  ⚠️  $($Global:AnalysisResults.AnomalyCount) anomalies found - review the reports for details"
    }
    else {
        Write-StatusMessage -Level "SUCCESS" -Message "  ✅ No anomalies detected"
    }
    
    Write-StatusMessage -Level "INFO" -Message "Output files generated:"
    Write-StatusMessage -Level "INFO" -Message "  - HTML Report: $htmlReport"
    Write-StatusMessage -Level "INFO" -Message "  - CSV Report: $csvReport"
    Write-StatusMessage -Level "INFO" -Message "  - Summary: $summaryFile"
    Write-StatusMessage -Level "INFO" -Message "  - Log: $logFile"
}

# Main function
function Main {
    param()
    
    # Show help if requested
    if ($Help) {
        Show-Help
        return
    }
    
    Write-StatusMessage -Level "INFO" -Message "=== Windows Security Event Log Analyzer Started ==="
    Write-StatusMessage -Level "INFO" -Message "Script Version: $ScriptVersion"
    Write-StatusMessage -Level "INFO" -Message "Event Log: $EventLogPath"
    Write-StatusMessage -Level "INFO" -Message "Output Directory: $OutputPath"
    
    try {
        # Initialize environment
        Test-Environment
        Initialize-OutputFiles
        
        # Perform analysis
        Get-ProcessCreationEvents
        Get-LogonEvents
        Find-Anomalies
        
        # Generate reports
        Export-HTMLReport
        Export-SummaryReport
        
        # Show results
        Show-FinalResults
        
        Write-StatusMessage -Level "SUCCESS" -Message "=== Analysis completed successfully ==="
    }
    catch {
        Write-StatusMessage -Level "ERROR" -Message "Analysis failed: $($_.Exception.Message)"
        Write-StatusMessage -Level "ERROR" -Message "Check the log file for details: $logFile"
        exit 1
    }
}

# Script entry point
if ($MyInvocation.InvocationName -eq $ScriptName) {
    Main
}
