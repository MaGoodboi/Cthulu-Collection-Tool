# Cthulu Collection Tool
# Please ignore the message displaying to console - the program works fine!

# Load the PresentationFramework, System.Windows.Forms, and System.Drawing assemblies. Necessary classes for GUI in PS
Add-Type -AssemblyName PresentationFramework, System.Windows.Forms

$iM =[System.Windows.MessageBox]::Show("Welcome to the Cthulu Collection Tool. You must run this tool with administrator privileges!")

$sM = [System.Windows.MessageBox]::Show("Save location is $env:HOMEPATH\Desktop\Cthulu")

#Ensure running as Administrator
<#if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
   [System.Windows.MessageBox]::Show("Please run this script as an Administrator.", "Insufficient Privileges", "Ok", "Error")
    exit
}#>

if (Test-Path $env:HOMEPATH\Desktop\Cthulu)
{
    # Do nothing; directory already exist
}
else
{
    New-Item -Path $env:HOMEPATH\Desktop\Cthulu -ItemType Directory | Out-Null
}

# Initalize directory to reference Winpmem
$psDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Ask user if they want to collect memory
$yMemoryCollection = [System.Windows.MessageBox]::Show("Do you want to collect a memory image?", "Optional Memory Collection", "YesNo", "Question")
    
if ($yMemoryCollection -eq "Yes") {
    try {
        # Execute Winpmem to collect memory
        $dumpItPath = Join-Path -Path $psDirectory -ChildPath "Comae-Toolkit-v20230117\x64\DumpIt.exe"
        $memoryOutput = "$env:HOMEPATH\Desktop\Cthulu\HOST_Memory_Image.raw"

        # Begin memory collection
        Start-Process -FilePath $dumpItPath -ArgumentList "/O `"$memoryOutput`"" -Wait
    }
    catch {
        # Generate informational message box in case user does not want to continue with memory collection
        $errorMessage = $_.Exception.Message

        $messageBoxResult = [System.Windows.MessageBox]::Show("Memory Collection Process Failed: $errorMessage.`nDo you want to continue?", "Information", "YesNo", "Error Collecting Memory")

        if ($messageBoxResult -eq "No") {
            # Exit the program
            exit
        }
    }
}

function Get-PSHistory 
{   
    
    [CmdletBinding()]
    param (
        [switch]$SuppressErrors,
        [string]$OutputDirectory
    )

    $users = Get-ChildItem -Path "C:\Users" -Directory

    foreach ($user in $users) {
        Write-Output "    $user"

        $historyFile = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

        if (-not (Test-Path $historyFile)) {
            $errorActionPreference = "Continue"
            if ($SuppressErrors) {
                $errorActionPreference = "SilentlyContinue"
            }

            $psReadlineOptions = Get-PSReadlineOption -Scope "CurrentUser" -ErrorAction $errorActionPreference

            if ($psReadlineOptions -and $psReadlineOptions.HistorySavePath) {
                $historyFile = $psReadlineOptions.HistorySavePath
            }
        }

        if (Test-Path $historyFile) {
            $output += "User: $($user.Name)`n"
            $output += "Command History:`n"
            $output += Get-Content -Path $historyFile | Out-String
            $output += "`n"
        }
        else {
            $output += "User: $($user.Name)`n"
            $output += "No history found.`n`n"
        }
    }

    if ($OutputDirectory) {
        $hostname = $env:COMPUTERNAME
        $date = Get-Date -Format "ddMMMyyyy"
        $time = Get-Date -Format "HHmm"
        $filename = "${hostname}_${date}_${time}_PSHistory.txt"
        $filePath = Join-Path -Path $OutputDirectory -ChildPath $filename

        $output | Out-File -FilePath $filePath
    }
    else {
        Write-Host $output
    }
}

Get-PSHistory -SuppressErrors -OutputDirectory "$env:HOMEPATH\Desktop\Cthulu"


# Collect information about the target device
Get-ComputerInfo | Out-File $env:HOMEPATH\Desktop\Cthulu\ComputerInformation.txt

# Collect Prefetch information
Get-ChildItem -Path C:\Windows\Prefetch\* | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\Prefetch.csv

# Set path for Appplication, Security, and System Logs
$path = "$env:HOMEPATH\Desktop\Cthulu\"

# Export ApplicationlLog as .evt file
$applicationLog = "Application"
$exportFileName = $applicationLog + (get-date -f yyyyMMdd) + ".evt"
$aLogFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $applicationLog}
$aLogFile.backupeventlog($path + $exportFileName)

# Export Security log as .evt file
$securityLog = "Security"
$exportFileName = $securityLog + (get-date -f yyyyMMdd) + ".evt"
$seLogFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $securityLog}
$seLogFile.backupeventlog($path + $exportFileName)

# Export System log as .evt file
$systemLog = "System"
$exportFileName = $systemLog + (get-date -f yyyyMMdd) + ".evt"
$syLogFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $systemLog}
$syLogFile.backupeventlog($path + $exportFileName)

# Collect WinRM logs
Get-EventLog -LogName Microsoft-Windows-WinRM/Operational | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\WindowsRM_Logs.csv

# Collect WMI logs
Get-EventLog -LogName Microsoft-Windows-WMI-Activity/Operational | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\Windows_WMI_Logs.csv

# Collect Defender Logs
Get-EventLog "Microsoft-Windows-Windows Defender/Operational"  | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\Defender_Logs.csv

# Collect PowerShell Logs
Get-EventLog -LogName Microsoft-Windows-PowerShell/Operational | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\PowerShell_Operational.csv
Get-EventLog -LogName Microsoft-Windows-PowerShell/Admin | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\PowerShell_Admin.csv
Get-EventLog -LogName "Windows PowerShell" | Export-Csv  -Path $env:HOMEPATH\Desktop\Cthulu\Windows_PowerShell.csv

# Collect Running Processes
Get-Process | Select-Object -Property * | Export-Csv $env:HOMEPATH\Desktop\Cthulu\Running_Processes.csv

# Collect Process with their PID and PPID
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\PID_PPID.csv

# Collect PowerShell NetTCPConnection information
Get-NetTCPConnection | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process"; Expression={ (Get-Process   -Id $_.OwningProcess).ProcessName}}| Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\NetTCPConnection.csv

# Collect Fileshare information
Get-FileShare | Select-Object -Property Name, Description, UniqueId, FileSharingProtocol, ShareState, OperationalStatus | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\FileShares.csv

# Collect Most Recently Used
Get-ChildItem -Path "$env:HOMEPATH\AppData\Roaming\Microsoft\Windows\Recent\*.*" | Select-Object -Property Name, CreationTime, LastWriteTime |
    Export-Csv $env:HOMEPATH\Desktop\Cthulu\MRU.csv

# Collect Scheduled Tasks
Get-ScheduledTask | Export-Csv $env:HOMEPATH\Desktop\Cthulu\Scheduled_Tasks.csv

# Collect Services
Get-Service | Select-Object -Property Name | Export-Csv $env:HOMEPATH\Desktop\Cthulu\Services.csv

# Collect Registry information for Run and RunOnce
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\HKCU_Run.csv
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\" | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\HKCU_RunOnce.csv
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\HKLM_Run.csv
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\HKLM_RunOnce.csv

# Get list of external devices
$externalDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.PNPClass -eq "USB" -or $_.PNPClass -eq "USBHub" }

# Output the list of external devices
$externalDevices | Select-Object Name, Description, DeviceID | Export-Csv -Path $env:HOMEPATH\Desktop\Cthulu\ExternalDevices.csv

# Closing Message
$cM = [System.Windows.MessageBox]::Show("Collection is complete. As a reminder, output was saved to $env:HOMEPATH\Desktop\Cthulu")