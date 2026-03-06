<#
.SYNOPSIS
    Teardown-VulnLab.ps1 - Reverts all changes made by Setup-VulnLab.ps1
.DESCRIPTION
    Run as Administrator to clean up the PrivHound test lab environment.
.EXAMPLE
    .\tests\Teardown-VulnLab.ps1
#>
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "`n  PrivHound Lab Teardown`n" -ForegroundColor Cyan

function Remove-Quietly([string]$What, [scriptblock]$Action) {
    try { & $Action; Write-Host "  [x] Removed: $What" -ForegroundColor Green }
    catch { Write-Host "  [!] Failed: $What - $_" -ForegroundColor Yellow }
}

# ── Services ──
Remove-Quietly "Service PHLabVulnSvc" { sc.exe stop "PHLabVulnSvc" 2>$null | Out-Null; sc.exe delete "PHLabVulnSvc" 2>$null | Out-Null }
Remove-Quietly "Service PHLabUnquotedSvc" { sc.exe stop "PHLabUnquotedSvc" 2>$null | Out-Null; sc.exe delete "PHLabUnquotedSvc" 2>$null | Out-Null }
Remove-Quietly "Service PHLabRegSvc" { sc.exe stop "PHLabRegSvc" 2>$null | Out-Null; sc.exe delete "PHLabRegSvc" 2>$null | Out-Null }
Remove-Quietly "Service PHLabUserSvc" { sc.exe stop "PHLabUserSvc" 2>$null | Out-Null; sc.exe delete "PHLabUserSvc" 2>$null | Out-Null }
Remove-Quietly "Service PHLabProgSvc" { sc.exe stop "PHLabProgSvc" 2>$null | Out-Null; sc.exe delete "PHLabProgSvc" 2>$null | Out-Null }
Remove-Quietly "Service MakeMeAdminService" { sc.exe stop "MakeMeAdminService" 2>$null | Out-Null; sc.exe delete "MakeMeAdminService" 2>$null | Out-Null }
Remove-Quietly "Service PHLabXPrivSvc" { sc.exe stop "PHLabXPrivSvc" 2>$null | Out-Null; sc.exe delete "PHLabXPrivSvc" 2>$null | Out-Null }
Remove-Quietly "Service PHLabXPrivSvc2" { sc.exe stop "PHLabXPrivSvc2" 2>$null | Out-Null; sc.exe delete "PHLabXPrivSvc2" 2>$null | Out-Null }
Remove-Quietly "Service PHLabRecoverySvc" { sc.exe stop "PHLabRecoverySvc" 2>$null | Out-Null; sc.exe delete "PHLabRecoverySvc" 2>$null | Out-Null }

# ── Scheduled Task ──
Remove-Quietly "Scheduled task PHLabVulnTask" { Unregister-ScheduledTask -TaskName "PHLabVulnTask" -Confirm:$false -EA Stop }
Remove-Quietly "Scheduled task PHLabXPrivTask" { Unregister-ScheduledTask -TaskName "PHLabXPrivTask" -Confirm:$false -EA Stop }

# ── Autorun ──
Remove-Quietly "Autorun PHLabAutorun" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PHLabAutorun" -EA Stop }
Remove-Quietly "Autorun PHLabXPrivAutorun" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "PHLabXPrivAutorun" -EA Stop }

# ── AlwaysInstallElevated ──
Remove-Quietly "AIE HKLM" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -EA Stop }
Remove-Quietly "AIE HKCU" { Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -EA Stop }

# ── MakeMeAdmin registry ──
Remove-Quietly "MakeMeAdmin registry" { Remove-Item "HKLM:\SOFTWARE\Sinclair Community College\Make Me Admin" -Recurse -Force -EA Stop }
Remove-Quietly "MakeMeAdmin parent key" { Remove-Item "HKLM:\SOFTWARE\Sinclair Community College" -Recurse -Force -EA Stop }

# ── WSUS HTTP config ──
Remove-Quietly "WSUS WUServer" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -EA Stop }
Remove-Quietly "WSUS WUStatusServer" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -EA Stop }
Remove-Quietly "WSUS UseWUServer" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UseWUServer" -EA Stop }

# ── WMI Subscriptions ──
Remove-Quietly "WMI binding PHLabWMIConsumer" {
    $binding = Get-WmiObject -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -EA SilentlyContinue | Where-Object { $_.Consumer -match "PHLabWMIConsumer" }
    if ($binding) { $binding | Remove-WmiObject -EA Stop }
}
Remove-Quietly "WMI consumer PHLabWMIConsumer" {
    $consumer = Get-WmiObject -Namespace "root\subscription" -Class "CommandLineEventConsumer" -EA SilentlyContinue | Where-Object { $_.Name -eq "PHLabWMIConsumer" }
    if ($consumer) { $consumer | Remove-WmiObject -EA Stop }
}
Remove-Quietly "WMI filter PHLabWMIFilter" {
    $filter = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" -EA SilentlyContinue | Where-Object { $_.Name -eq "PHLabWMIFilter" }
    if ($filter) { $filter | Remove-WmiObject -EA Stop }
}

# ── COM Hijack test CLSID ──
$testCLSID = "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"
Remove-Quietly "COM test CLSID HKLM" {
    $p = "HKLM:\SOFTWARE\Classes\CLSID\$testCLSID"
    # Only remove if it was created by the lab (check for taskschd.dll)
    $val = (Get-ItemProperty "$p\InprocServer32" -EA SilentlyContinue).'(default)'
    if ($val -eq "C:\Windows\System32\taskschd.dll") { Remove-Item $p -Recurse -Force -EA Stop }
}

# ── WebClient relay ──
Remove-Quietly "WebClient start type (reset to Disabled)" {
    $svc = Get-Service "WebClient" -EA SilentlyContinue
    if ($svc) { Set-Service WebClient -StartupType Disabled -EA Stop }
}
Remove-Quietly "LDAP signing policy" { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LDAP" -Name "LDAPClientIntegrity" -EA Stop }

# ── AutoLogon credentials ──
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Remove-Quietly "AutoLogon DefaultPassword" { Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -EA Stop }
Remove-Quietly "AutoLogon DefaultUserName" {
    $val = (Get-ItemProperty $winlogonPath -EA SilentlyContinue).DefaultUserName
    if ($val -eq "PHLabUser") { Remove-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -EA Stop }
}
Remove-Quietly "AutoLogon DefaultDomainName" {
    $val = (Get-ItemProperty $winlogonPath -EA SilentlyContinue).DefaultDomainName
    if ($val -eq "PHLABDOMAIN") { Remove-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -EA Stop }
}

# ── UAC settings ──
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Remove-Quietly "UAC ConsentPromptBehaviorAdmin (reset to 5)" { Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord }
Remove-Quietly "UAC LocalAccountTokenFilterPolicy" { Remove-ItemProperty -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -EA Stop }

# ── PATH cleanup ──
$labPathDir = "C:\PrivHoundLab\FakePath"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -like "*$labPathDir*") {
    $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $labPathDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    Write-Host "  [x] Removed: $labPathDir from system PATH" -ForegroundColor Green
}

# ── Unattend file ──
$unattendFile = "$env:SystemRoot\Panther\unattend.xml"
if ((Test-Path $unattendFile) -and (Get-Content $unattendFile -Raw -EA SilentlyContinue) -match "PHLab") {
    Remove-Quietly "Unattend file" { Remove-Item $unattendFile -Force }
}

# ── GPP History ──
$gppHistoryDir = "C:\ProgramData\Microsoft\Group Policy\History\{PHLAB-TEST}"
Remove-Quietly "GPP History test dir" { Remove-Item $gppHistoryDir -Recurse -Force -EA Stop }

# ── Sensitive files (in PHLabUser's profile - handle .DOMAIN.NNN suffix) ──
$labUserProfiles = Get-ChildItem "C:\Users" -Directory -Filter "PHLabUser*" -EA SilentlyContinue
foreach ($lup in $labUserProfiles) {
    Remove-Quietly ".git-credentials ($($lup.Name))" { Remove-Item (Join-Path $lup.FullName ".git-credentials") -Force -EA Stop }
    Remove-Quietly "Fake .kdbx ($($lup.Name))" { Remove-Item (Join-Path $lup.FullName "Documents\PHLab_passwords.kdbx") -Force -EA Stop }
    Remove-Quietly "Fake .rdg ($($lup.Name))" { Remove-Item (Join-Path $lup.FullName "Documents\PHLab_servers.rdg") -Force -EA Stop }
}

# ── Sensitive files in admin profile ──
$adminProfile = $env:USERPROFILE
Remove-Quietly "Admin .git-credentials" {
    $f = Join-Path $adminProfile ".git-credentials"
    if ((Test-Path $f) -and (Get-Content $f -Raw -EA SilentlyContinue) -match "phlab") { Remove-Item $f -Force -EA Stop }
}
Remove-Quietly "Admin PHLab .kdbx" { Remove-Item (Join-Path $adminProfile "Documents\PHLab_passwords.kdbx") -Force -EA Stop }
Remove-Quietly "Admin PHLab .rdg" { Remove-Item (Join-Path $adminProfile "Documents\PHLab_servers.rdg") -Force -EA Stop }

# ── Program Files dir ──
Remove-Quietly "PHLabApp in Program Files" { Remove-Item (Join-Path $env:ProgramFiles "PHLabApp") -Recurse -Force -EA Stop }

# ── Cross-user profile (handle .DOMAIN.NNN suffix) ──
$crossProfiles = Get-ChildItem "C:\Users" -Directory -Filter "PHLabCrossUser*" -EA SilentlyContinue
foreach ($cp in $crossProfiles) {
    Remove-Quietly "Cross-user .git-credentials ($($cp.Name))" { Remove-Item (Join-Path $cp.FullName ".git-credentials") -Force -EA Stop }
    Remove-Quietly "Cross-user PS history ($($cp.Name))" { Remove-Item (Join-Path $cp.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt") -Force -EA Stop }
}

# ── Test users ──
Remove-Quietly "PHLabSvcUser from Administrators" { net localgroup Administrators PHLabSvcUser /delete 2>$null | Out-Null }
Remove-Quietly "Test user PHLabSvcUser" { net user PHLabSvcUser /delete 2>$null | Out-Null }
Remove-Quietly "Test user PHLabCrossUser" { net user PHLabCrossUser /delete 2>$null | Out-Null }
Remove-Quietly "Test user PHLabXPrivUser" { net user PHLabXPrivUser /delete 2>$null | Out-Null }
Remove-Quietly "PHLabUser from Administrators" { net localgroup Administrators PHLabUser /delete 2>$null | Out-Null }
Remove-Quietly "Test user PHLabUser" { net user PHLabUser /delete 2>$null | Out-Null }

# ── Shadow copies (lab-created) ──
Remove-Quietly "Lab shadow copies" { vssadmin delete shadows /for=C: /oldest /quiet 2>$null | Out-Null }

# ── Lab root directory ──
Remove-Quietly "Lab root C:\PrivHoundLab" { Remove-Item "C:\PrivHoundLab" -Recurse -Force -EA Stop }

Write-Host @"

  ╔══════════════════════════════════════════════════╗
  ║  Teardown Complete                               ║
  ║  All PrivHound lab artifacts removed.            ║
  ║  Reboot recommended to fully apply changes.     ║
  ╚══════════════════════════════════════════════════╝

"@ -ForegroundColor Green
