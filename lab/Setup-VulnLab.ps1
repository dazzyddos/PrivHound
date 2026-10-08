<#
.SYNOPSIS
    Setup-VulnLab.ps1 - Creates intentional misconfigurations for testing PrivHound
.DESCRIPTION
    Run as Administrator to introduce privilege escalation vectors that PrivHound
    should detect. Run Teardown-VulnLab.ps1 to revert all changes. Setup will
    refuse to run over an existing or partially cleaned lab.

    WARNING: This script weakens system security. Only run in an isolated VM or lab.
.EXAMPLE
    # As Administrator:
    .\lab\Setup-VulnLab.ps1

    # Then as a low-priv user:
    .\PrivHound.ps1

    # Cleanup as Administrator:
    .\lab\Teardown-VulnLab.ps1
#>
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host @"

  +--------------------------------------------------+
  |  PrivHound Vulnerable Lab Setup                  |
  +--------------------------------------------------+
"@ -ForegroundColor Red
Write-Host "  WARNING: Only run in an isolated test VM!`n" -ForegroundColor Yellow

$labRoot = "C:\PrivHoundLab"
$stateRoot = Join-Path $env:ProgramData 'PrivHoundLabState'
$programFilesLabDir = Join-Path $env:ProgramFiles 'PHLabApp'
$gppHistoryRoot = 'C:\ProgramData\Microsoft\Group Policy\History\{PHLAB-TEST}'
$gppHistoryDir = Join-Path $gppHistoryRoot 'Machine\Preferences\Groups'
# A second run would overwrite the original-setting log and could change
# existing lab services. Check before prompting or modifying the machine.
$labBlockers = [System.Collections.ArrayList]::new()
if (Test-Path -LiteralPath $labRoot) { [void]$labBlockers.Add($labRoot) }
if (Test-Path -LiteralPath $stateRoot) { [void]$labBlockers.Add($stateRoot) }
if (Test-Path -LiteralPath $programFilesLabDir) { [void]$labBlockers.Add($programFilesLabDir) }
if (Test-Path -LiteralPath $gppHistoryRoot) { [void]$labBlockers.Add($gppHistoryRoot) }
foreach ($name in @('PHLabVulnSvc','PHLabUnquotedSvc','PHLabRegSvc','PHLabUserSvc',
                   'PHLabProgSvc','MakeMeAdminService','PHLabXPrivSvc',
                   'PHLabXPrivSvc2','PHLabRecoverySvc')) {
    if (Get-Service -Name $name -EA SilentlyContinue) { [void]$labBlockers.Add("service $name") }
}
foreach ($name in @('PHLabVulnTask','PHLabXPrivTask')) {
    if (Get-ScheduledTask -TaskName $name -EA SilentlyContinue) { [void]$labBlockers.Add("scheduled task $name") }
}
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
foreach ($name in @('PHLabAutorun','PHLabXPrivAutorun')) {
    $key = Get-Item -LiteralPath $runKey -EA SilentlyContinue
    if ($key -and $key.GetValueNames() -contains $name) { [void]$labBlockers.Add("autorun $name") }
}
if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Sinclair Community College\Make Me Admin') {
    [void]$labBlockers.Add('MakeMeAdmin registry key')
}
if (Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -EA SilentlyContinue |
    Where-Object { $_.Name -eq 'PHLabWMIFilter' }) {
    [void]$labBlockers.Add('WMI filter PHLabWMIFilter')
}
if (Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -EA SilentlyContinue |
    Where-Object { $_.Name -eq 'PHLabWMIConsumer' }) {
    [void]$labBlockers.Add('WMI consumer PHLabWMIConsumer')
}
$profileRoot = Join-Path $env:SystemDrive 'Users'
foreach ($name in @('PHLabUser','PHLabSvcUser','PHLabCrossUser','PHLabXPrivUser')) {
    if (Get-LocalUser -Name $name -EA SilentlyContinue) { [void]$labBlockers.Add("local user $name") }
    $escapedName = [regex]::Escape($name)
    if (Get-ChildItem -LiteralPath $profileRoot -Directory -EA SilentlyContinue |
        Where-Object { $_.Name -match "^$escapedName(\.[A-Za-z0-9_.-]+)?$" }) {
        [void]$labBlockers.Add("stale profile for $name")
    }
}
if ($labBlockers.Count -gt 0) {
    Write-Host "  [i] Lab setup already exists; no changes made." -ForegroundColor Yellow
    Write-Host "  [i] Found: $($labBlockers -join ', ')" -ForegroundColor Yellow
    Write-Host "  [i] Run lab\Teardown-VulnLab.ps1 before setting up a new lab." -ForegroundColor Yellow
    return
}

$confirm = Read-Host "  This will weaken system security. Type 'YES' to continue"
if ($confirm -ne "YES") { Write-Host "  Aborted." -ForegroundColor Yellow; exit }

$logFile = Join-Path $stateRoot 'setup_log.json'
$log = @{
    timestamp = (Get-Date -Format o)
    administrator_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    actions = [System.Collections.ArrayList]::new()
}

function Log-Action([string]$Check, [string]$Action, [string]$Detail) {
    [void]$log.actions.Add(@{ check=$Check; action=$Action; detail=$Detail })
    Save-LabLog
    Write-Verbose "($Check) $Action - $Detail"
}

function Save-LabLog {
    $temporaryLog = Join-Path $stateRoot 'setup_log.tmp'
    try {
        $log | ConvertTo-Json -Depth 5 | Out-File $temporaryLog -Encoding UTF8 -EA Stop
        $logAcl = Get-Acl -LiteralPath $temporaryLog -EA Stop
        $logAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        Set-Acl -LiteralPath $temporaryLog -AclObject $logAcl -EA Stop
        if (Test-Path -LiteralPath $logFile) {
            $backupLog = Join-Path $stateRoot ("setup_log.$([guid]::NewGuid().ToString('N')).bak")
            [IO.File]::Replace($temporaryLog, $logFile, $backupLog)
            Remove-Item -LiteralPath $backupLog -Force -EA SilentlyContinue
        } else { [IO.File]::Move($temporaryLog, $logFile) }
    } catch {
        Remove-Item -LiteralPath $temporaryLog -Force -EA SilentlyContinue
        throw "Could not write protected recovery log: $_"
    }
}

function Ensure-LabUser([string]$Username, [string]$Password, [string]$Description) {
    if (-not (Get-LocalUser -Name $Username -EA SilentlyContinue)) {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $securePassword -EA Stop | Out-Null
    }
    if (-not (Get-LocalUser -Name $Username -EA SilentlyContinue)) {
        throw "Local account $Username was not created"
    }
    $users = Get-LocalGroup -SID 'S-1-5-32-545' -EA Stop
    $user = Get-LocalUser -Name $Username -EA Stop
    $member = Get-LocalGroupMember -Group $users.Name -EA Stop |
        Where-Object { $_.SID.Value -eq $user.SID.Value }
    if (-not $member) { Add-LocalGroupMember -Group $users.Name -Member $user -EA Stop }
    $member = Get-LocalGroupMember -Group $users.Name -EA Stop |
        Where-Object { $_.SID.Value -eq $user.SID.Value }
    if (-not $member) { throw "Failed to add $Username to the local Users group" }
    Log-Action "User" $Description $Username
}

function Add-LabUserToAdministrators([string]$Username) {
    $admins = Get-LocalGroup -SID 'S-1-5-32-544' -EA Stop
    $member = Get-LocalGroupMember -Group $admins.Name -EA SilentlyContinue |
        Where-Object { $_.Name -match "\\$([regex]::Escape($Username))$" }
    if (-not $member) { Add-LocalGroupMember -Group $admins.Name -Member $Username -EA Stop }
    $member = Get-LocalGroupMember -Group $admins.Name -EA SilentlyContinue |
        Where-Object { $_.Name -match "\\$([regex]::Escape($Username))$" }
    if (-not $member) { throw "Failed to add $Username to the local Administrators group" }
}

# Recovery data includes original credentials used by elevated teardown.
# Store it outside the user-writable lab tree and disable ACL inheritance.
New-Item -Path $stateRoot -ItemType Directory -EA Stop | Out-Null
$stateAcl = [Security.AccessControl.DirectorySecurity]::new()
$stateAcl.SetAccessRuleProtection($true, $false)
$stateAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $stateAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $stateRoot -AclObject $stateAcl -EA Stop
Save-LabLog

# ── Create lab directory ──────────────────────────
New-Item -Path $labRoot -ItemType Directory -Force | Out-Null
Log-Action "Setup" "Created lab root" $labRoot

# ── Create test users early (needed by later checks) ──
Write-Host "`n  --- Pre-creating Test Users ---" -ForegroundColor Cyan
$testUser = "PHLabUser"
$testPass = "PHLab_P@ssw0rd_TEST"
try { Ensure-LabUser $testUser $testPass "Pre-created test user" }
catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; throw }

$svcUser = "PHLabSvcUser"
$svcUserPass = "PHLabSvcUser_P@ss!"
try { Ensure-LabUser $svcUser $svcUserPass "Pre-created service user" }
catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; throw }

$crossUser = "PHLabCrossUser"
$crossPass = "PHLabCross_P@ss!"
try { Ensure-LabUser $crossUser $crossPass "Pre-created cross user" }
catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; throw }

$crossPrivUser = "PHLabXPrivUser"
$crossPrivPass = "PHLabXPriv_S3cret!"
try { Ensure-LabUser $crossPrivUser $crossPrivPass "Pre-created cross-priv user" }
catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; throw }

# Helper: resolve actual profile path for a user (handles .DOMAIN.NNN suffixes)
function Get-UserProfilePath([string]$Username) {
    # Method 1: Check ProfileList in registry (most reliable)
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        $profileDir = (Get-ItemProperty $regPath -EA Stop).ProfileImagePath
        if ($profileDir -and (Test-Path $profileDir -EA SilentlyContinue)) { return $profileDir }
    } catch {}
    # Method 2: Glob for matching profile dirs
    $candidates = Get-ChildItem "C:\Users" -Directory -Filter "$Username*" -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($candidates) { return $candidates[0].FullName }
    # Method 3: Default path (may not exist yet)
    return "C:\Users\$Username"
}

# Force profile creation by running a quick process as each user
Write-Verbose 'Ensuring user profiles exist...'
foreach ($u in @(@{n=$testUser;p=$testPass},@{n=$crossUser;p=$crossPass})) {
    try {
        $secPw = ConvertTo-SecureString $u.p -AsPlainText -Force
        $cred = New-Object PSCredential(".\$($u.n)", $secPw)
        Start-Process cmd.exe -ArgumentList "/c whoami" -Credential $cred -NoNewWindow -Wait -EA Stop 2>$null
    } catch { <# Profile may already exist #> }
}

$labUserProfile = Get-UserProfilePath $testUser
$crossUserProfile = Get-UserProfilePath $crossUser
Write-Verbose "PHLabUser profile: $labUserProfile"
Write-Verbose "PHLabCrossUser profile: $crossUserProfile"
Log-Action "Profiles" "Resolved profile paths" "PHLabUser=$labUserProfile, Cross=$crossUserProfile"

# ══════════════════════════════════════════════════
# CHECK 1 & 2: Weak Service Permissions + Writable Binary
# ══════════════════════════════════════════════════
Write-Host "`n  --- Check 1/2: Vulnerable Service ---" -ForegroundColor Cyan

$svcDir = Join-Path $labRoot "VulnService"
New-Item -Path $svcDir -ItemType Directory -Force | Out-Null

# Use cmd.exe as a valid PE stand-in for the test service binary.
$svcExe = Join-Path $svcDir "phlab_svc.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $svcExe -Force

# Make the binary writable by BUILTIN\Users
$acl = Get-Acl $svcExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $svcExe $acl
Log-Action "SvcBin" "Made binary writable by Users" $svcExe

# Create service running as SYSTEM
sc.exe create "PHLabVulnSvc" binPath= $svcExe start= demand obj= "LocalSystem" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not create PHLabVulnSvc (sc.exe exit $LASTEXITCODE)" }
# Grant BUILTIN\Users SERVICE_CHANGE_CONFIG (DC). WP only grants SERVICE_STOP.
# Keep DELETE/WRITE_DAC for Administrators so teardown can remove the service.
sc.exe sdset "PHLabVulnSvc" "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCDC;;;BU)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set PHLabVulnSvc permissions (sc.exe exit $LASTEXITCODE)" }
Log-Action "SvcPerms" "Created modifiable service 'PHLabVulnSvc' as SYSTEM" "SDDL grants DC to BU"

# ══════════════════════════════════════════════════
# CHECK 3: Unquoted Service Path
# ══════════════════════════════════════════════════
Write-Host "  --- Check 3: Unquoted Service Path ---" -ForegroundColor Cyan

$unqDir = Join-Path $labRoot "Program With Spaces"
$unqSubDir = Join-Path $unqDir "Service"
New-Item -Path $unqSubDir -ItemType Directory -Force | Out-Null
$unqExe = Join-Path $unqSubDir "binary.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $unqExe -Force

# Make parent directory writable so hijack is possible
$acl = Get-Acl $labRoot
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $labRoot $acl

# Create service with unquoted path (no quotes around space-containing path)
$unqPath = "$labRoot\Program With Spaces\Service\binary.exe"
sc.exe create "PHLabUnquotedSvc" binPath= $unqPath start= demand obj= "LocalSystem" | Out-Null
Log-Action "Unquoted" "Created unquoted path service" $unqPath

# ══════════════════════════════════════════════════
# CHECK 4: Writable PATH Directory (DLL Hijacking)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 4: Writable PATH Directory ---" -ForegroundColor Cyan

$pathDir = Join-Path $labRoot "FakePath"
New-Item -Path $pathDir -ItemType Directory -Force | Out-Null

# Make it writable by Everyone
$acl = Get-Acl $pathDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Everyone", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $pathDir $acl

# Add to system PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$pathDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$pathDir", "Machine")
    Log-Action "DLLHijack" "Added writable dir to system PATH" $pathDir
}

# ══════════════════════════════════════════════════
# CHECK 5: AlwaysInstallElevated
# ══════════════════════════════════════════════════
Write-Host "  --- Check 5: AlwaysInstallElevated ---" -ForegroundColor Cyan

$aieBaseline = @{}
foreach ($hive in @('HKLM','HKCU')) {
    $key = Get-Item -LiteralPath "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -EA SilentlyContinue
    $valueExisted = $key -and $key.GetValueNames() -contains 'AlwaysInstallElevated'
    $aieBaseline[$hive] = @{
        key_existed = [bool]$key
        value_existed = [bool]$valueExisted
        value = if ($valueExisted) { $key.GetValue('AlwaysInstallElevated') } else { $null }
    }
}
Log-Action 'AIE' 'Original policies' ($aieBaseline | ConvertTo-Json -Compress)
Save-LabLog
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -Type DWord
# Set HKCU for the current admin user
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -Type DWord
# Also set it for PHLabUser by loading their registry hive
$labUserNtuser = Join-Path $labUserProfile "NTUSER.DAT"
$Script:NeedsAieUserSetup = $false
if (Test-Path $labUserNtuser -EA SilentlyContinue) {
    reg load "HKU\PHLabUser" $labUserNtuser 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        try {
            reg add "HKU\PHLabUser\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 1 /f 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "reg add failed with exit $LASTEXITCODE" }
            Log-Action "AIE" "Enabled AlwaysInstallElevated in HKLM + HKCU (admin + PHLabUser)" "Profile: $labUserProfile"
        } catch {
            $Script:NeedsAieUserSetup = $true
            Write-Host "  [!] PHLabUser installer policy needs manual setup: $_" -ForegroundColor Yellow
        } finally {
            reg unload "HKU\PHLabUser" 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not unload HKU\PHLabUser; reboot before teardown.' }
        }
    } else { $Script:NeedsAieUserSetup = $true }
} else {
    $Script:NeedsAieUserSetup = $true
    Log-Action "AIE" "Enabled AlwaysInstallElevated in HKLM + admin HKCU" "PHLabUser profile not ready; manual HKCU setup needed after first login"
    Write-Host "  [!] PHLabUser profile is missing; HKCU installer policy requires a manual follow-up." -ForegroundColor Yellow
}

# ══════════════════════════════════════════════════
# CHECK 6: Token Privileges (informational - can't easily grant)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 6: Token Privileges ---" -ForegroundColor Cyan
Write-Verbose "Token privileges depend on the account; use a service account or ntrights for manual testing."
Log-Action "TokenPriv" "Skipped - requires ntrights.exe or secpol.msc" "Manual step"

# ══════════════════════════════════════════════════
# CHECK 7: Scheduled Task with Writable Binary
# ══════════════════════════════════════════════════
Write-Host "  --- Check 7: Scheduled Task ---" -ForegroundColor Cyan

$taskExe = Join-Path $labRoot "phlab_task.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $taskExe -Force
$acl = Get-Acl $taskExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $taskExe $acl

$action = New-ScheduledTaskAction -Execute $taskExe -Argument "/c echo test"
$trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "PHLabVulnTask" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
# Verify the task was created correctly
$verifyTask = Get-ScheduledTask -TaskName "PHLabVulnTask" -EA SilentlyContinue
if ($verifyTask) {
    Write-Verbose "Task verified: UserId='$($verifyTask.Principal.UserId)' State='$($verifyTask.State)' Execute='$($verifyTask.Actions[0].Execute)'"
    Log-Action "Task" "Created scheduled task with writable binary" $taskExe
} else {
    Write-Host "  [!] Task registration may have failed!" -ForegroundColor Red
    Log-Action "Task" "Failed to verify scheduled task registration" $taskExe
}

# ══════════════════════════════════════════════════
# CHECK 8: Autorun with Writable Binary
# ══════════════════════════════════════════════════
Write-Host "  --- Check 8: Autorun ---" -ForegroundColor Cyan

$autoExe = Join-Path $labRoot "phlab_autorun.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $autoExe -Force
$acl = Get-Acl $autoExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $autoExe $acl

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PHLabAutorun" -Value $autoExe
Log-Action "Autorun" "Created HKLM Run entry with writable binary" $autoExe

# ══════════════════════════════════════════════════
# CHECK 9: Writable Service Registry Key
# ══════════════════════════════════════════════════
Write-Host "  --- Check 9: Writable Registry Key ---" -ForegroundColor Cyan

$regSvcExe = Join-Path $labRoot "phlab_regsvc.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $regSvcExe -Force
sc.exe create "PHLabRegSvc" binPath= $regSvcExe start= demand obj= "LocalSystem" | Out-Null

# Grant BUILTIN\Users write access to the service's registry key
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\PHLabRegSvc"
$acl = Get-Acl $regPath
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "BUILTIN\Users", "SetValue,WriteKey", "ContainerInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $regPath $acl
Log-Action "RegKey" "Created service with writable registry key" $regPath

# ══════════════════════════════════════════════════
# CHECK 10: Stored Credentials (AutoLogon)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 10: AutoLogon Credentials ---" -ForegroundColor Cyan

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$winlogonKey = Get-Item -LiteralPath $winlogonPath -EA Stop
$autoLogonBaseline = @{}
foreach ($name in @('DefaultUserName','DefaultPassword','DefaultDomainName')) {
    $autoLogonBaseline[$name] = if ($winlogonKey.GetValueNames() -contains $name) {
        $winlogonKey.GetValue($name)
    } else { $null }
}
Log-Action 'AutoLogon' 'Original values' ($autoLogonBaseline | ConvertTo-Json -Compress)
Save-LabLog
Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -Value "PHLabUser"
Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -Value "PHLab_P@ssw0rd_TEST"
Set-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -Value "PHLABDOMAIN"
Log-Action "AutoLogon" "Set fake AutoLogon credentials" "PHLabUser / PHLab_P@ssw0rd_TEST"

# ══════════════════════════════════════════════════
# CHECK 11: GPP Password XML (simulated)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 11: GPP Cached Password ---" -ForegroundColor Cyan

$gppDir = Join-Path $labRoot "GPP\Machine\Preferences\Groups"
New-Item -Path $gppDir -ItemType Directory -Force | Out-Null
$gppXml = Join-Path $gppDir "Groups.xml"
# GPP's AES-256 key is public (MS14-025); this cpassword is test data.
@'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="PHLabAdmin" changed="2026-01-01 00:00:00" uid="{test}">
    <Properties action="U" newName="" fullName="" description="" cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="PHLabAdmin"/>
  </User>
</Groups>
'@ | Out-File $gppXml -Encoding UTF8

# Also place it in the actual GPP History path if possible.
Log-Action 'GPP' 'Creating lab GPP history directory' $gppHistoryDir
New-Item -Path $gppHistoryDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null
if (Test-Path (Split-Path $gppHistoryDir)) {
    Copy-Item $gppXml $gppHistoryDir -Force -EA SilentlyContinue
    Log-Action "GPP" "Placed Groups.xml with cpassword in GPP History" $gppHistoryDir
} else {
    Log-Action "GPP" "Placed Groups.xml with cpassword in lab dir" $gppXml
}

# ══════════════════════════════════════════════════
# CHECK 12: Unattended Install File
# ══════════════════════════════════════════════════
Write-Host "  --- Check 12: Unattend File ---" -ForegroundColor Cyan

$pantherDir = "$env:SystemRoot\Panther"
if (-not (Test-Path -LiteralPath $pantherDir)) {
    Log-Action 'Unattend' 'Creating Panther directory' $pantherDir
    New-Item -Path $pantherDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    if (Test-Path -LiteralPath $pantherDir) {
        Log-Action 'Unattend' 'Created Panther directory' $pantherDir
    }
}
$unattendFile = Join-Path $pantherDir "unattend.xml"
if (-not (Test-Path -LiteralPath $unattendFile)) {
@'
<?xml version="1.0" encoding="utf-8"?>
<!-- PrivHoundLab fixture -->
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password>
          <Value>UEhMYWJUZXN0UGFzcw==</Value>
          <PlainText>false</PlainText>
        </Password>
        <Username>Administrator</Username>
        <Enabled>true</Enabled>
      </AutoLogon>
    </component>
  </settings>
</unattend>
'@ | Out-File $unattendFile -Encoding UTF8
    Log-Action "Unattend" "Created unattend.xml with password element" $unattendFile
} else {
    Log-Action "Unattend" "Preserved pre-existing unattend.xml" $unattendFile
}

# ══════════════════════════════════════════════════
# CHECK 13: PowerShell History (always exists naturally)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 13: PowerShell History ---" -ForegroundColor Cyan
Write-Verbose "PSReadLine history exists naturally; use the test user to enrich it."
Log-Action "PSHistory" "Skipped - exists naturally" "ConsoleHost_history.txt"

# ══════════════════════════════════════════════════
# CHECK 14: Sensitive Files
# ══════════════════════════════════════════════════
Write-Host "  --- Check 14: Sensitive Files ---" -ForegroundColor Cyan

# Create files in PHLabUser's resolved profile (handles .DOMAIN.NNN suffix)
if (-not (Test-Path $labUserProfile)) {
    New-Item -Path $labUserProfile -ItemType Directory -Force -EA SilentlyContinue | Out-Null
}

# Fake .git-credentials in PHLabUser's profile
$gitCreds = Join-Path $labUserProfile ".git-credentials"
"https://phlab-user:FakeToken123@github.com" | Out-File $gitCreds -Encoding UTF8 -Force
Log-Action "SensFile" "Created fake .git-credentials" $gitCreds

# Fake .kdbx in PHLabUser's profile
$labUserDocs = Join-Path $labUserProfile "Documents"
New-Item -Path $labUserDocs -ItemType Directory -Force -EA SilentlyContinue | Out-Null
$kdbxFile = Join-Path $labUserDocs "PHLab_passwords.kdbx"
[byte[]]$fakeKdbx = @(0x03, 0xD9, 0xA2, 0x9A) # KeePass magic bytes (first 4)
[System.IO.File]::WriteAllBytes($kdbxFile, $fakeKdbx)
Log-Action "SensFile" "Created fake .kdbx file" $kdbxFile

# Fake .rdg file in PHLabUser's profile
$rdgFile = Join-Path $labUserDocs "PHLab_servers.rdg"
@'
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.90">
  <file><credentialsProfiles><credentialsProfile><profileName>test</profileName>
  <userName>admin</userName><password>ZmFrZXBhc3N3b3Jk</password>
  </credentialsProfile></credentialsProfiles></file>
</RDCMan>
'@ | Out-File $rdgFile -Encoding UTF8
Log-Action "SensFile" "Created fake .rdg file" $rdgFile

# Grant PHLabUser access to their own profile files
icacls $labUserProfile /grant "PHLabUser:(OI)(CI)F" /T /Q 2>$null | Out-Null

# Place test files in the current admin's profile; the collector scans $env:USERPROFILE.
$adminProfile = $env:USERPROFILE
$adminGitCreds = Join-Path $adminProfile ".git-credentials"
if (-not (Test-Path $adminGitCreds)) {
    Log-Action "SensFile" "Creating .git-credentials in admin profile" $adminGitCreds
    "https://phlab-admin:AdminFakeToken789@github.com" | Out-File $adminGitCreds -Encoding UTF8 -Force
    Log-Action "SensFile" "Created .git-credentials in admin profile for detection" $adminGitCreds
} else {
    Write-Host "  [i] Admin .git-credentials already exists - not overwriting" -ForegroundColor Yellow
}
$adminDocs = Join-Path $adminProfile "Documents"
if (-not (Test-Path -LiteralPath $adminDocs)) {
    Log-Action 'SensFile' 'Creating admin Documents directory' $adminDocs
    New-Item -Path $adminDocs -ItemType Directory -Force -EA SilentlyContinue | Out-Null
    if (Test-Path -LiteralPath $adminDocs) {
        Log-Action 'SensFile' 'Created admin Documents directory' $adminDocs
    }
}
$adminKdbx = Join-Path $adminDocs "PHLab_passwords.kdbx"
if (-not (Test-Path -LiteralPath $adminKdbx)) {
    Log-Action "SensFile" "Creating .kdbx in admin profile" $adminKdbx
    [System.IO.File]::WriteAllBytes($adminKdbx, $fakeKdbx)
    Log-Action "SensFile" "Created .kdbx in admin profile for detection" $adminKdbx
}
$adminRdg = Join-Path $adminDocs "PHLab_servers.rdg"
if (-not (Test-Path -LiteralPath $adminRdg)) {
    Log-Action "SensFile" "Creating .rdg in admin profile" $adminRdg
@'
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.90">
  <file><credentialsProfiles><credentialsProfile><profileName>test</profileName>
  <userName>admin</userName><password>ZmFrZXBhc3N3b3Jk</password>
  </credentialsProfile></credentialsProfiles></file>
</RDCMan>
'@ | Out-File $adminRdg -Encoding UTF8
    Log-Action "SensFile" "Created .rdg in admin profile for detection" $adminRdg
}

# ══════════════════════════════════════════════════
# CHECK 15: UAC Weakening
# ══════════════════════════════════════════════════
Write-Host "  --- Check 15: UAC Configuration ---" -ForegroundColor Cyan

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# Set ConsentPromptBehaviorAdmin to 0 (never prompt)
$origConsent = $null
$origLocalFilter = $null
$uacKey = Get-Item -LiteralPath $uacPath -EA SilentlyContinue
if ($uacKey -and $uacKey.GetValueNames() -contains 'ConsentPromptBehaviorAdmin') {
    $origConsent = $uacKey.GetValue('ConsentPromptBehaviorAdmin')
}
if ($uacKey -and $uacKey.GetValueNames() -contains 'LocalAccountTokenFilterPolicy') {
    $origLocalFilter = $uacKey.GetValue('LocalAccountTokenFilterPolicy')
}
Log-Action 'UAC' 'Original policies' "Original consent=$origConsent; localFilter=$origLocalFilter"
Save-LabLog
Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord
# Enable LocalAccountTokenFilterPolicy (allows remote pass-the-hash)
Set-ItemProperty -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
# Add PHLabUser to Administrators to exercise the filtered-token UAC check.
Add-LabUserToAdministrators $testUser
Log-Action "UAC" "Set ConsentPromptBehaviorAdmin=0, LocalAccountTokenFilterPolicy=1, added PHLabUser to Admins" "Original consent=$origConsent; localFilter=$origLocalFilter"

# ══════════════════════════════════════════════════
# CHECK 16: Writable Program Files Directory
# ══════════════════════════════════════════════════
Write-Host "  --- Check 16: Writable Program Dir ---" -ForegroundColor Cyan

$progDir = $programFilesLabDir
Log-Action "ProgDir" "Creating lab directory" $progDir
New-Item -Path $progDir -ItemType Directory -Force | Out-Null
$acl = Get-Acl $progDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $progDir $acl
Log-Action "ProgDir" "Created writable dir in Program Files" $progDir

# ══════════════════════════════════════════════════
# CHECK 17: Cross-User Profile Access
# ══════════════════════════════════════════════════
Write-Host "  --- Check 17: Cross-User Profile ---" -ForegroundColor Cyan

# Use the pre-created cross-user's resolved profile path (handles .DOMAIN.NNN suffix).
$crossProfile = $crossUserProfile
if (-not (Test-Path $crossProfile)) {
    New-Item -Path $crossProfile -ItemType Directory -Force -EA SilentlyContinue | Out-Null
}
$crossPSHistDir = Join-Path $crossProfile "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
New-Item -Path $crossPSHistDir -ItemType Directory -Force -EA SilentlyContinue | Out-Null

# Plant PS history with embedded credentials
$crossHistFile = Join-Path $crossPSHistDir "ConsoleHost_history.txt"
@"
Get-Service
`$secPw = ConvertTo-SecureString "CrossUserSecret123!" -AsPlainText -Force
`$cred = New-Object PSCredential("admin", `$secPw)
Invoke-Command -Credential `$cred -ScriptBlock { whoami }
net use \\server\share /user:svcaccount SvcP@ssw0rd2024
"@ | Out-File $crossHistFile -Encoding UTF8 -Force

# Plant .git-credentials
$crossGitCreds = Join-Path $crossProfile ".git-credentials"
"https://crossuser:CrossGitToken456@github.com" | Out-File $crossGitCreds -Encoding UTF8 -Force

# Make profile readable by BUILTIN\Users
icacls $crossProfile /grant "BUILTIN\Users:(OI)(CI)RX" /T /Q 2>$null | Out-Null
Log-Action "CrossProfile" "Created readable cross-user profile with PS history & git-credentials" $crossProfile

# ══════════════════════════════════════════════════
# CHECK 18: Non-SYSTEM Service Account
# ══════════════════════════════════════════════════
Write-Host "  --- Check 18: Non-SYSTEM Service ---" -ForegroundColor Cyan

$svcUser = "PHLabSvcUser"
$svcUserPass = "PHLabSvcUser_P@ss!"
# User pre-created above; just ensure admin group membership
Add-LabUserToAdministrators $svcUser
Log-Action "UserSvc" "Added service account to Administrators" "$svcUser / $svcUserPass"

$userSvcExe = Join-Path $labRoot "phlab_usersvc.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $userSvcExe -Force
# Grant BUILTIN\Users modify so the service check picks it up
$acl = Get-Acl $userSvcExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $userSvcExe $acl

sc.exe create "PHLabUserSvc" binPath= $userSvcExe start= demand obj= ".\$svcUser" password= $svcUserPass | Out-Null
# Grant BUILTIN\Users modify permission on the service
sc.exe sdset "PHLabUserSvc" "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCDC;;;BU)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set PHLabUserSvc permissions (sc.exe exit $LASTEXITCODE)" }
Log-Action "UserSvc" "Created modifiable service 'PHLabUserSvc' running as $svcUser (admin)" "Binary: $userSvcExe"

# ══════════════════════════════════════════════════
# CHECK 19: ProgDir → Service Link
# ══════════════════════════════════════════════════
Write-Host "  --- Check 19: ProgDir -> Service Link ---" -ForegroundColor Cyan

$progSvcDir = Join-Path $env:ProgramFiles "PHLabApp"
# PHLabApp dir was already created in Check 16 with writable perms
$progSvcExe = Join-Path $progSvcDir "phlab_progsvc.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $progSvcExe -Force

sc.exe create "PHLabProgSvc" binPath= $progSvcExe start= demand obj= "LocalSystem" | Out-Null
Log-Action "ProgSvc" "Created service 'PHLabProgSvc' with binary in writable PHLabApp dir" $progSvcExe

# ══════════════════════════════════════════════════
# CHECK 20: cmdkey stored credential (manual step)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 20: cmdkey Stored Credential ---" -ForegroundColor Cyan
Log-Action "CmdKey" "Manual step - add cmdkey entry as PHLabUser" "cmdkey /add:PHLabTarget /user:PHLabUser /pass:PHLab_P@ssw0rd_TEST"

# ══════════════════════════════════════════════════
# CHECK 21: MakeMeAdmin JIT (fake registry + service)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 21: JIT Admin (MakeMeAdmin) ---" -ForegroundColor Cyan

$mmaRegPath = "HKLM:\SOFTWARE\Sinclair Community College\Make Me Admin"
Log-Action 'JITAdmin' 'Creating fake MakeMeAdmin registry' $mmaRegPath
New-Item -Path $mmaRegPath -Force | Out-Null
Set-ItemProperty -Path $mmaRegPath -Name "AdminDurationMinutes" -Value 15 -Type DWord
Set-ItemProperty -Path $mmaRegPath -Name "AllowedEntities" -Value "BUILTIN\Users" -Type String
# Create a fake service to simulate MakeMeAdmin
$mmaExe = Join-Path $labRoot "MakeMeAdminService.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $mmaExe -Force
sc.exe create "MakeMeAdminService" binPath= $mmaExe start= demand obj= "LocalSystem" | Out-Null
Log-Action "JITAdmin" "Created fake MakeMeAdmin registry + service" $mmaRegPath

# ══════════════════════════════════════════════════
# CHECK 22: WSUS HTTP Config
# ══════════════════════════════════════════════════
Write-Host "  --- Check 22: WSUS HTTP Config ---" -ForegroundColor Cyan

$wsusRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wsusKey = Get-Item -LiteralPath $wsusRegPath -EA SilentlyContinue
$wsusBaseline = @{ key_existed = [bool]$wsusKey; values = @{} }
foreach ($name in @('WUServer','WUStatusServer','UseWUServer')) {
    $valueExisted = $wsusKey -and $wsusKey.GetValueNames() -contains $name
    $wsusBaseline.values[$name] = @{
        existed = [bool]$valueExisted
        value = if ($valueExisted) { $wsusKey.GetValue($name) } else { $null }
    }
}
Log-Action 'WSUS' 'Original policies' ($wsusBaseline | ConvertTo-Json -Compress)
Save-LabLog
New-Item -Path $wsusRegPath -Force | Out-Null
Set-ItemProperty -Path $wsusRegPath -Name "WUServer" -Value "http://wsus.phlab.local:8530" -Type String
Set-ItemProperty -Path $wsusRegPath -Name "WUStatusServer" -Value "http://wsus.phlab.local:8530" -Type String
Set-ItemProperty -Path $wsusRegPath -Name "UseWUServer" -Value 1 -Type DWord
Log-Action "WSUS" "Configured WSUS with HTTP URL" "http://wsus.phlab.local:8530"

# ══════════════════════════════════════════════════
# CHECK 23: WMI Permanent Subscription with writable consumer
# ══════════════════════════════════════════════════
Write-Host "  --- Check 23: WMI Subscription ---" -ForegroundColor Cyan

$wmiConsumerExe = Join-Path $labRoot "phlab_wmi_consumer.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $wmiConsumerExe -Force
$acl = Get-Acl $wmiConsumerExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $wmiConsumerExe $acl

try {
    $filterArgs = @{
        EventNamespace = "root\cimv2"
        Name = "PHLabWMIFilter"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    }
    $filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments $filterArgs -EA Stop

    $consumerArgs = @{
        Name = "PHLabWMIConsumer"
        ExecutablePath = $wmiConsumerExe
        CommandLineTemplate = "$wmiConsumerExe /c echo test"
    }
    $consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments $consumerArgs -EA Stop

    $bindingArgs = @{
        Filter = $filter
        Consumer = $consumer
    }
    Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments $bindingArgs -EA Stop | Out-Null

    Log-Action "WMISub" "Created WMI subscription with writable consumer" $wmiConsumerExe
} catch {
    Write-Host "  [!] Could not create WMI subscription: $_" -ForegroundColor Yellow
    Log-Action "WMISub" "Failed to create WMI subscription" "$_"
}

# ══════════════════════════════════════════════════
# CHECK 24: Hijackable COM CLSID
# ══════════════════════════════════════════════════
Write-Host "  --- Check 24: COM Hijack Registry ---" -ForegroundColor Cyan

# Create a test CLSID: HKCR exists while the per-user HKCU override is absent.
# We use a test CLSID in HKLM\SOFTWARE\Classes (which feeds into HKCR)
$testCLSID = "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"
$hklmClsidRoot = "HKLM:\SOFTWARE\Classes\CLSID\$testCLSID"
$hklmClsidPath = "$hklmClsidRoot\InprocServer32"
if (-not (Test-Path $hklmClsidRoot -EA SilentlyContinue)) {
    # Record ownership first so teardown can recover from interrupted setup.
    Log-Action "COMHijack" "Creating HKCR CLSID for COM hijack test" $testCLSID
    Save-LabLog
    New-Item -Path $hklmClsidPath -Force | Out-Null
    Set-ItemProperty -Path $hklmClsidPath -Name "(default)" -Value "C:\Windows\System32\taskschd.dll"
    Log-Action "COMHijack" "Created HKCR CLSID for COM hijack test" $testCLSID
} else {
    Log-Action "COMHijack" "Preserved pre-existing COM registration" $testCLSID
    Write-Host "  [i] COM registration already existed; no lab key created." -ForegroundColor Cyan
}

Write-Host "  --- Check 25: Named Pipes (informational) ---" -ForegroundColor Cyan
Log-Action "NamedPipes" "Skipped - uses existing Windows named pipes" "No lab artifact"

# ══════════════════════════════════════════════════
# CHECK 26: WebClient Relay (WebClient service + LDAP signing)
# ══════════════════════════════════════════════════
Write-Host "  --- Check 26: WebClient Relay ---" -ForegroundColor Cyan

# Save original WebClient start type for teardown
$origWebClient = (Get-Service "WebClient" -EA SilentlyContinue)
if ($origWebClient) {
    $origStartType = (Get-CimInstance Win32_Service -Filter "Name='WebClient'" -EA SilentlyContinue).StartMode
    if ($origStartType -notin @('Auto','Manual','Disabled')) { throw 'Cannot record original WebClient start mode' }
    Log-Action "WebClientRelay" "Set WebClient to Manual (was: $origStartType)" "Manual = triggerable without admin"
    Save-LabLog
    Set-Service WebClient -StartupType Manual -EA SilentlyContinue
} else {
    Write-Host "  [!] WebClient service not installed - skipping" -ForegroundColor Yellow
    Log-Action "WebClientRelay" "WebClient not installed" "Skipped"
}

# Set LDAP signing to negotiate, simulating the default weak configuration.
$ldapPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LDAP"
$ldapKey = Get-Item -LiteralPath $ldapPolicyPath -EA SilentlyContinue
$origLdapSigning = $null
if ($ldapKey -and $ldapKey.GetValueNames() -contains 'LDAPClientIntegrity') {
    $origLdapSigning = $ldapKey.GetValue('LDAPClientIntegrity')
}
$ldapBaseline = @{
    key_existed = [bool]$ldapKey
    value_existed = ($null -ne $origLdapSigning)
    value = $origLdapSigning
}
Log-Action 'WebClientRelay' 'Set LDAP signing to negotiate (1)' ($ldapBaseline | ConvertTo-Json -Compress)
Save-LabLog
New-Item -Path $ldapPolicyPath -Force -EA SilentlyContinue | Out-Null
Set-ItemProperty -Path $ldapPolicyPath -Name "LDAPClientIntegrity" -Value 1 -Type DWord

# ══════════════════════════════════════════════════
# CHECK 27: Cross-User Privilege Escalation
# ══════════════════════════════════════════════════
Write-Host "`n  --- Check 27: Cross-User Privilege Escalation ---" -ForegroundColor Cyan

# The current user discovers PHLabXPrivUser credentials in AutoLogon or history.
# That account can write a SYSTEM service binary, modify another service via SDDL,
# and write a SYSTEM scheduled-task binary. The graph should link it to each target.

# -- Create a service whose binary is writable ONLY by PHLabXPrivUser --
$xprivSvcDir = Join-Path $labRoot "CrossPrivService"
New-Item -Path $xprivSvcDir -ItemType Directory -Force | Out-Null
$xprivSvcExe = Join-Path $xprivSvcDir "phlab_xpriv_svc.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $xprivSvcExe -Force

# Remove inherited permissions and grant only PHLabXPrivUser write access
$acl = Get-Acl $xprivSvcExe
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$xprivRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$env:COMPUTERNAME\$crossPrivUser", "Modify", "Allow")
$readRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "ReadAndExecute", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($xprivRule)
$acl.AddAccessRule($readRule)
Set-Acl $xprivSvcExe $acl

sc.exe create "PHLabXPrivSvc" binPath= $xprivSvcExe start= demand obj= "LocalSystem" | Out-Null
Log-Action "CrossPriv" "Created SYSTEM service with binary writable only by $crossPrivUser" $xprivSvcExe

# -- Create a service whose SDDL grants modify rights to PHLabXPrivUser's SID --
$xprivSvcExe2 = Join-Path $xprivSvcDir "phlab_xpriv_svc2.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $xprivSvcExe2 -Force
sc.exe create "PHLabXPrivSvc2" binPath= $xprivSvcExe2 start= demand obj= "LocalSystem" | Out-Null

# Resolve PHLabXPrivUser's SID for SDDL
try {
    $xprivSid = (New-Object System.Security.Principal.NTAccount($crossPrivUser)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    # DC changes service configuration; WP grants only SERVICE_STOP on service objects.
    $xprivSDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCDC;;;$xprivSid)"
    sc.exe sdset "PHLabXPrivSvc2" $xprivSDDL | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set PHLabXPrivSvc2 permissions (sc.exe exit $LASTEXITCODE)" }
    Log-Action "CrossPriv" "Created SYSTEM service modifiable by $crossPrivUser via SDDL" "SID=$xprivSid"
} catch {
    Write-Host "  [!] Could not resolve SID for $crossPrivUser - skipping SDDL setup" -ForegroundColor Yellow
}

# -- Create a scheduled task whose binary is writable only by PHLabXPrivUser --
$xprivTaskExe = Join-Path $xprivSvcDir "phlab_xpriv_task.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $xprivTaskExe -Force

$acl = Get-Acl $xprivTaskExe
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$env:COMPUTERNAME\$crossPrivUser", "Modify", "Allow")))
$acl.AddAccessRule($readRule)
Set-Acl $xprivTaskExe $acl

$xprivAction = New-ScheduledTaskAction -Execute $xprivTaskExe -Argument "/c echo xpriv"
$xprivTrigger = New-ScheduledTaskTrigger -Daily -At "04:00"
$xprivPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "PHLabXPrivTask" -Action $xprivAction -Trigger $xprivTrigger -Principal $xprivPrincipal -Force | Out-Null
Log-Action "CrossPriv" "Created SYSTEM task with binary writable only by $crossPrivUser" $xprivTaskExe

# -- Plant PHLabXPrivUser's credentials in a discoverable location --
# Option 1: Add to the cross-user profile PS history (already accessible)
$crossHistFile = Join-Path $crossPSHistDir "ConsoleHost_history.txt"
if (Test-Path $crossHistFile) {
    $existingHistory = Get-Content $crossHistFile -Raw
    $xprivCredLine = "`nnet use \\fileserver\share /user:$crossPrivUser $crossPrivPass"
    if ($existingHistory -notmatch [regex]::Escape($crossPrivUser)) {
        Add-Content $crossHistFile $xprivCredLine -Encoding UTF8
        Log-Action "CrossPriv" "Planted $crossPrivUser credentials in cross-user PS history" $crossHistFile
    }
}

# Option 2: Also create an autorun entry whose binary is writable only by PHLabXPrivUser
$xprivAutoExe = Join-Path $xprivSvcDir "phlab_xpriv_autorun.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $xprivAutoExe -Force
$acl = Get-Acl $xprivAutoExe
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$env:COMPUTERNAME\$crossPrivUser", "Modify", "Allow")))
$acl.AddAccessRule($readRule)
Set-Acl $xprivAutoExe $acl
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PHLabXPrivAutorun" -Value $xprivAutoExe
Log-Action "CrossPriv" "Created HKLM Run entry writable only by $crossPrivUser" $xprivAutoExe

Write-Verbose "Cross-user scenario: CurrentUser reads PS history for PHLabXPrivUser credentials; that account can modify PHlabXPrivSvc, PHlabXPrivSvc2, PHlabXPrivTask, and PHlabXPrivAutorun."

# ══════════════════════════════════════════════════
# CHECK 28: Service Failure Recovery Command
# ══════════════════════════════════════════════════
Write-Host "`n  --- Check 28: Service Recovery Command ---" -ForegroundColor Cyan

$recoveryDir = Join-Path $labRoot "RecoveryService"
New-Item -Path $recoveryDir -ItemType Directory -Force | Out-Null
$recoveryExe = Join-Path $recoveryDir "phlab_recovery.exe"
Copy-Item "$env:SystemRoot\System32\cmd.exe" $recoveryExe -Force

# Make recovery binary writable by BUILTIN\Users
$acl = Get-Acl $recoveryExe
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $recoveryExe $acl

# Create service running as SYSTEM
sc.exe create "PHLabRecoverySvc" binPath= "$labRoot\VulnService\phlab_svc.exe" start= demand obj= "LocalSystem" | Out-Null
# Configure failure recovery to run the writable binary
sc.exe failure "PHLabRecoverySvc" reset= 0 actions= run/5000 command= $recoveryExe | Out-Null
Log-Action "SvcRecovery" "Created service with writable recovery command binary" $recoveryExe

# ══════════════════════════════════════════════════
# CHECK 29: Shadow Copy Sensitive Files
# ══════════════════════════════════════════════════
Write-Host "  --- Check 29: Shadow Copy ---" -ForegroundColor Cyan

$shadowBeforeIds = $null
try {
    $shadowBeforeIds = @(Get-CimInstance Win32_ShadowCopy -EA Stop | ForEach-Object { $_.ID })
} catch { Write-Verbose "Could not capture pre-creation shadow copy IDs: $_" }

try {
    $shadowOutput = @(vssadmin create shadow "/for=$env:SystemDrive" 2>&1)
    $shadowExitCode = $LASTEXITCODE
    $shadowTool = 'vssadmin'
    if ($shadowExitCode -ne 0) {
        $vssError = ($shadowOutput | Out-String).Trim()
        Write-Host "  [!] vssadmin create shadow failed (exit $shadowExitCode): $vssError" -ForegroundColor Yellow
        # vssadmin's create command is not available on all Windows editions.
        # Diskshadow can create a persistent copy without a backup session.
        if (Get-Command diskshadow.exe -EA SilentlyContinue) {
            $shadowTool = 'diskshadow'
            $diskshadowScript = Join-Path $stateRoot 'create_shadow.dsh'
            try {
                @('set context persistent nowriters', "add volume $env:SystemDrive", 'create', 'exit') |
                    Set-Content -LiteralPath $diskshadowScript -Encoding ASCII -EA Stop
                $shadowOutput = @(diskshadow.exe -s $diskshadowScript 2>&1)
                $shadowExitCode = $LASTEXITCODE
            } finally {
                Remove-Item -LiteralPath $diskshadowScript -Force -EA SilentlyContinue
            }
        }
    }
    if ($shadowExitCode -eq 0) {
        $shadowId = $null
        $idMatch = [regex]::Match(($shadowOutput -join "`n"), '(?i)Shadow Copy ID:\s*(\{[0-9A-Fa-f-]{36}\})')
        if ($idMatch.Success) { $shadowId = $idMatch.Groups[1].Value }
        if (-not $shadowId -and $null -ne $shadowBeforeIds) {
            try {
                $newIds = @(Get-CimInstance Win32_ShadowCopy -EA Stop | ForEach-Object { $_.ID } | Where-Object { $_ -notin $shadowBeforeIds })
                if ($newIds.Count -eq 1 -and $newIds[0] -match '^\{[0-9A-Fa-f-]{36}\}$') { $shadowId = $newIds[0] }
            } catch { Write-Verbose "Could not compare shadow copy IDs: $_" }
        }
        if ($shadowId) {
            Log-Action "ShadowCopy" "Created shadow copy for C:" $shadowId
            Write-Host "  [+] Created shadow copy with $shadowTool`: $shadowId" -ForegroundColor Green
            # Persist the ID immediately so an interrupted setup can be torn down safely.
            try { Save-LabLog }
            catch { Write-Host "  [!] Shadow copy created but its ID could not be saved to $logFile : $_" -ForegroundColor Yellow }
        } else {
            Write-Host "  [!] $shadowTool returned success but the shadow copy ID could not be identified; check its output and vssadmin list shadows." -ForegroundColor Yellow
            Write-Host "  [i] $($shadowOutput -join ' ')" -ForegroundColor Yellow
            Log-Action "ShadowCopy" "Failed to record shadow copy ID" "Check vssadmin list shadows"
        }
    } else {
        $failure = ($shadowOutput | Out-String).Trim()
        Write-Host "  [!] $shadowTool shadow copy failed (exit $shadowExitCode): $failure" -ForegroundColor Yellow
        Log-Action "ShadowCopy" "Failed to create shadow copy" "$shadowTool exit $shadowExitCode`: $failure"
    }
} catch {
    Write-Host "  [!] Could not create shadow copy: $_" -ForegroundColor Yellow
    Log-Action "ShadowCopy" "Failed to create shadow copy" "$_"
}

# ══════════════════════════════════════════════════
# Final user verification
# ══════════════════════════════════════════════════
Write-Host "`n  --- Verifying Test Users ---" -ForegroundColor Cyan
# Verify PHLabUser's administrator membership established in Check 15.
$isAdmin = net localgroup Administrators 2>$null | Select-String "PHLabUser"
if ($isAdmin) { Log-Action "User" "PHLabUser confirmed in Administrators group" "Ready" }
else { Write-Host "  [!] PHLabUser not in Administrators - some credential-to-admin queries will fail" -ForegroundColor Yellow }

# ══════════════════════════════════════════════════
# Save setup log for teardown
# ══════════════════════════════════════════════════
Save-LabLog

$setupLines = @(
    ''
    'Test user: PHLabUser / PHLab_P@ssw0rd_TEST'
    ''
    'Next steps:'
    '  1. Open a non-elevated cmd as PHLabUser: runas /user:PHLabUser cmd'
    '  2. Run PrivHound: powershell .\PrivHound.ps1'
    '  3. Review findings and failed/skipped checks.'
    '  4. Cleanup as Administrator: .\lab\Teardown-VulnLab.ps1'
    ''
    'Manual follow-ups (optional):'
    '  Token privileges: use a service account or configure with ntrights/secpol.'
    '  PS history: run commands as the test user.'
    '  Cmdkey (as PHLabUser): cmdkey /add:PHLabTarget /user:PHLabUser /pass:PHLab_P@ssw0rd_TEST'
)
if ($Script:NeedsAieUserSetup) {
    $setupLines += @(
        "  Installer policy: set AlwaysInstallElevated in PHLabUser's HKCU hive after first login."
    )
}
$setupLines += @('', "Full action log ($($log.actions.Count) entries):", "  $logFile", '')
$boxWidth = [Math]::Max(50, [int](($setupLines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum) + 4)
Write-Host ("`n  +" + ('-' * $boxWidth) + '+') -ForegroundColor Green
Write-Host ('  |  ' + 'Lab Setup Complete!'.PadRight($boxWidth - 4) + '  |') -ForegroundColor Green
Write-Host ('  +' + ('-' * $boxWidth) + '+') -ForegroundColor Green
foreach ($line in $setupLines) {
    Write-Host ('  |  ' + $line.PadRight($boxWidth - 4) + '  |') -ForegroundColor Green
}
Write-Host ('  +' + ('-' * $boxWidth) + "+`n") -ForegroundColor Green
