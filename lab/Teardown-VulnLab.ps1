<#
.SYNOPSIS
    Teardown-VulnLab.ps1 - Reverts all changes made by Setup-VulnLab.ps1
.DESCRIPTION
    Run as Administrator to clean up the PrivHound test lab environment.
.EXAMPLE
    .\lab\Teardown-VulnLab.ps1
#>
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host "`n  PrivHound Lab Teardown`n" -ForegroundColor Cyan
$Script:AlreadyAbsentCount = 0
$Script:FailureCount = 0
$Script:PendingReboot = $false
$Script:PreservedSettings = [System.Collections.Generic.List[string]]::new()
$stateRoot = Join-Path $env:ProgramData 'PrivHoundLabState'
$setupLog = Join-Path $stateRoot 'setup_log.json'
$actions = @()
if (Test-Path -LiteralPath $setupLog) {
    try {
        # Reject substituted/reparse-point state and any recovery data writable
        # by ordinary users before using it to restore machine-wide policies.
        foreach ($path in @($stateRoot, $setupLog)) {
            $item = Get-Item -LiteralPath $path -Force -EA Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Recovery path is a reparse point: $path" }
            $acl = Get-Acl -LiteralPath $path -EA Stop
            $trusted = @('S-1-5-18', 'S-1-5-32-544')
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
                throw "Untrusted recovery owner: $path"
            }
            foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($ace.AccessControlType -eq 'Allow' -and
                    $ace.IdentityReference.Value -notin $trusted -and
                    ([int]$ace.FileSystemRights -band 0xD0156)) {
                    throw "Recovery data is writable by $($ace.IdentityReference.Value): $path"
                }
            }
        }
        $recovery = Get-Content -LiteralPath $setupLog -Raw -EA Stop | ConvertFrom-Json -EA Stop
        $ownerSid = $recovery.PSObject.Properties['administrator_sid']
        if ($ownerSid -and $ownerSid.Value -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
            throw 'Run teardown as the administrator who ran setup to restore HKCU and profile files.'
        }
        $actions = @($recovery.actions)
    } catch {
        # Stop before destructive cleanup when recovery data cannot be trusted.
        throw "Could not load protected setup log: $_"
    }
} elseif ((Test-Path -LiteralPath 'C:\PrivHoundLab') -or (Test-Path -LiteralPath $stateRoot)) {
    $Script:FailureCount++
    Write-Host '  [!] Protected setup log missing; original policy values cannot be restored.' -ForegroundColor Red
    Write-Host '      Lab working directories will be removed; protected recovery data will be retained.' -ForegroundColor Yellow
}

function Skip-LabItem([string]$What) {
    $Script:AlreadyAbsentCount++
    Write-Verbose "Already absent: $What"
}

function Preserve-LabSetting([string]$What) {
    $Script:PreservedSettings.Add($What)
}

function Remove-Quietly([string]$What, [scriptblock]$Action) {
    try { & $Action; Write-Host "  [x] Removed: $What" -ForegroundColor Green }
    catch { $Script:FailureCount++; Write-Host "  [!] Failed: $What - $_" -ForegroundColor Red }
}

function Remove-LabPath([string]$What, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Skip-LabItem $What; return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -EA Stop
        Write-Host "  [x] Removed: $What" -ForegroundColor Green
    } catch {
        $Script:FailureCount++
        Write-Host "  [!] Failed: $What - $_" -ForegroundColor Red
        if ($What -like 'Orphan lab profile directory*' -and
            "$_" -match '(?i)NTUSER\.DAT|being used by another process|cannot access the file') {
            Write-Host '      The profile hive can be held open even without an interactive login.' -ForegroundColor Yellow
            Write-Host '      Close its processes; use quser and logoff <ID> if a session exists.' -ForegroundColor Yellow
            Write-Host '      Otherwise reboot Windows, then rerun teardown.' -ForegroundColor Yellow
        }
    }
}

function Remove-LabValue([string]$What, [string]$Path, [string]$Name) {
    $key = Get-Item -LiteralPath $Path -EA SilentlyContinue
    if (-not $key -or -not ($key.GetValueNames() -contains $Name)) {
        Skip-LabItem $What
        return
    }
    Remove-Quietly $What { Remove-ItemProperty -LiteralPath $Path -Name $Name -EA Stop }
}

function Remove-LabKeyIfEmpty([string]$What, [string]$Path) {
    $key = Get-Item -LiteralPath $Path -EA SilentlyContinue
    if ($key -and $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0) {
        Remove-LabPath $What $Path
    }
}

function Remove-LabDirectoryIfEmpty([string]$What, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        if (@(Get-ChildItem -LiteralPath $Path -Force -EA Stop).Count -eq 0) {
            [IO.Directory]::Delete($Path, $false)
            Write-Host "  [x] Removed: $What" -ForegroundColor Green
        }
    } catch {
        $Script:FailureCount++
        Write-Host "  [!] Failed: $What - $_" -ForegroundColor Red
    }
}

function Remove-LabService([string]$Name) {
    $svc = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $svc) { Skip-LabItem "Service $Name"; return }
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$Name'" -EA SilentlyContinue
    $programFilesBinary = Join-Path $env:ProgramFiles 'PHLabApp\phlab_progsvc.exe'
    $isLabBinary = $serviceInfo -and (
        $serviceInfo.PathName -match '^"?C:\\PrivHoundLab\\' -or
        ($Name -eq 'PHLabProgSvc' -and $serviceInfo.PathName.Trim('"') -ieq $programFilesBinary)
    )
    if (-not $isLabBinary) {
        $Script:FailureCount++
        Write-Host "  [!] Preserved service with an unrecognized binary path: $Name" -ForegroundColor Yellow
        return
    }
    try {
        if ($svc.Status -ne 'Stopped') { & sc.exe stop $Name 2>$null | Out-Null }
        & sc.exe delete $Name 2>$null | Out-Null
        if ($LASTEXITCODE -eq 5 -and $Name -eq 'PHLabVulnSvc') {
            # Older lab SDDL omitted DELETE for Administrators. Only use the
            # registry fallback when the service points into our lab directory.
            $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
            $key = Get-Item -LiteralPath $serviceKey -EA SilentlyContinue
            $imagePath = if ($key) { $key.GetValue('ImagePath') } else { $null }
            if ($imagePath -and $imagePath -match '^"?C:\\PrivHoundLab\\') {
                & reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\$Name" /f 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe denied deletion and reg.exe failed with exit code $LASTEXITCODE" }
                $Script:PendingReboot = $true
                Write-Host "  [x] Removed legacy lab service registration: $Name (reboot required)" -ForegroundColor Green
                return
            }
        }
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1072) {
            throw "sc.exe delete failed with exit code $LASTEXITCODE"
        }
        if (Get-Service -Name $Name -EA SilentlyContinue) { $Script:PendingReboot = $true }
        Write-Host "  [x] Deletion requested: Service $Name (may remain until handles close or reboot)" -ForegroundColor Green
    } catch {
        $Script:FailureCount++
        $reason = if ($LASTEXITCODE -eq 5) { 'access denied (exit 5); check elevation; older lab service ACLs may require SYSTEM to delete' } else { $_ }
        Write-Host "  [!] Failed: Service $Name - $reason" -ForegroundColor Red
    }
}

function Remove-LabTask([string]$Name) {
    $task = Get-ScheduledTask -TaskName $Name -EA SilentlyContinue
    if (-not $task) {
        Skip-LabItem "Scheduled task $Name"
        return
    }
    $executable = @($task.Actions | ForEach-Object { $_.Execute }) | Select-Object -First 1
    if (-not $executable -or $executable -notmatch '^"?C:\\PrivHoundLab\\') {
        $Script:FailureCount++
        Write-Host "  [!] Preserved task with an unrecognized executable: $Name ($executable)" -ForegroundColor Yellow
        return
    }
    Remove-Quietly "Scheduled task $Name" { Unregister-ScheduledTask -TaskName $Name -Confirm:$false -EA Stop }
}

function Remove-LabUser([string]$Name) {
    if (-not (Get-LocalUser -Name $Name -EA SilentlyContinue)) {
        Skip-LabItem "Test user $Name"
        return
    }
    try {
        & net.exe user $Name /delete 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net user /delete failed with exit code $LASTEXITCODE" }
        Write-Host "  [x] Removed: Test user $Name" -ForegroundColor Green
    } catch { $Script:FailureCount++; Write-Host "  [!] Failed: Test user $Name - $_" -ForegroundColor Red }
}

function Remove-LabShadowCopy([string]$Id) {
    try {
        $shadow = @(Get-CimInstance Win32_ShadowCopy -Filter "ID='$Id'" -EA Stop)
        if ($shadow.Count -eq 0) { Skip-LabItem "Lab shadow copy $Id"; return }
        & vssadmin delete shadows "/shadow=$Id" /quiet 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "vssadmin failed with exit code $LASTEXITCODE" }
        Write-Host "  [x] Removed: Lab shadow copy $Id" -ForegroundColor Green
    } catch { $Script:FailureCount++; Write-Host "  [!] Failed: Lab shadow copy - $_" -ForegroundColor Red }
}

# ── Services ──
@('PHLabVulnSvc','PHLabUnquotedSvc','PHLabRegSvc','PHLabUserSvc','PHLabProgSvc',
  'MakeMeAdminService','PHLabXPrivSvc','PHLabXPrivSvc2','PHLabRecoverySvc') | ForEach-Object { Remove-LabService $_ }

# ── Scheduled Task ──
Remove-LabTask 'PHLabVulnTask'
Remove-LabTask 'PHLabXPrivTask'

# ── Autorun ──
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
foreach ($name in @('PHLabAutorun','PHLabXPrivAutorun')) {
    $key = Get-Item -LiteralPath $runKey -EA SilentlyContinue
    if (-not $key -or $name -notin $key.GetValueNames()) { Skip-LabItem "Autorun $name"; continue }
    $value = [string]$key.GetValue($name)
    if ($value -notmatch '^"?C:\\PrivHoundLab\\') {
        $Script:FailureCount++
        Write-Host "  [!] Preserved autorun with an unrecognized command: $name ($value)" -ForegroundColor Yellow
        continue
    }
    Remove-LabValue "Autorun $name" $runKey $name
}

# ── AlwaysInstallElevated ──
$aieBaseline = $actions | Where-Object { $_.check -eq 'AIE' -and $_.action -eq 'Original policies' } | Select-Object -Last 1
if ($aieBaseline) {
    try {
        $original = $aieBaseline.detail | ConvertFrom-Json -EA Stop
        foreach ($hive in @('HKLM','HKCU')) {
            $path = "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer"
            $baseline = $original.$hive
            $baselineProperties = if ($null -ne $baseline) {
                @($baseline.PSObject.Properties | ForEach-Object { $_.Name })
            } else { @() }
            if ('value_existed' -notin $baselineProperties) {
                $legacyValue = $baseline
                $baseline = [pscustomobject]@{
                    key_existed = $true
                    value_existed = ($null -ne $legacyValue)
                    value = $legacyValue
                }
            }
            if (-not $baseline.value_existed) { Remove-LabValue "AIE $hive" $path 'AlwaysInstallElevated' }
            else {
                $value = [int]$baseline.value
                Remove-Quietly "AIE $hive (restore original)" {
                    Set-ItemProperty -LiteralPath $path -Name 'AlwaysInstallElevated' -Value $value -Type DWord -EA Stop
                }
            }
            if (-not $baseline.key_existed) { Remove-LabKeyIfEmpty "AIE $hive installer key" $path }
        }
    } catch { $Script:FailureCount++; Write-Host "  [!] Invalid AIE baseline: $_" -ForegroundColor Red }
} else { Preserve-LabSetting 'AIE policies (no recorded baseline)' }
$aieUser = Get-LocalUser -Name 'PHLabUser' -EA SilentlyContinue
if ($aieUser) {
    $hivePath = "Registry::HKEY_USERS\$($aieUser.SID.Value)\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (Test-Path -LiteralPath "Registry::HKEY_USERS\$($aieUser.SID.Value)") {
        Remove-LabValue 'AIE PHLabUser' $hivePath 'AlwaysInstallElevated'
    } else {
        $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$($aieUser.SID.Value)'" -EA SilentlyContinue
        $ntuser = if ($profile) { Join-Path $profile.LocalPath 'NTUSER.DAT' } else { $null }
        if ($ntuser -and (Test-Path -LiteralPath $ntuser)) {
            $hiveAliases = @(@('PHLabCleanup','PHLabUser') | Where-Object {
                Test-Path -LiteralPath "Registry::HKEY_USERS\$_"
            })
            if ($hiveAliases.Count -eq 0) {
                & reg.exe load 'HKU\PHLabCleanup' $ntuser 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { $hiveAliases = @('PHLabCleanup') }
                else {
                    $Script:FailureCount++
                    Write-Host '  [!] Failed to load PHLabUser registry hive.' -ForegroundColor Red
                }
            }
            foreach ($hiveAlias in $hiveAliases) {
                try {
                    $userPolicyKey = "HKU\$hiveAlias\SOFTWARE\Policies\Microsoft\Windows\Installer"
                    & reg.exe query $userPolicyKey /v AlwaysInstallElevated 2>$null | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        & reg.exe delete $userPolicyKey /v AlwaysInstallElevated /f 2>$null | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw 'Could not remove AlwaysInstallElevated from PHLabUser hive.' }
                        Write-Host '  [x] Removed: AIE PHLabUser' -ForegroundColor Green
                    } else { Skip-LabItem 'AIE PHLabUser' }
                } finally {
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    & reg.exe unload "HKU\$hiveAlias" 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) { $Script:FailureCount++; Write-Host '  [!] Failed to unload PHLabUser registry hive.' -ForegroundColor Red }
                }
            }
        }
    }
}

# ── MakeMeAdmin registry ──
$mmaPath = 'HKLM:\SOFTWARE\Sinclair Community College\Make Me Admin'
$mmaAction = @($actions | Where-Object {
    $_.check -eq 'JITAdmin' -and $_.action -in @(
        'Creating fake MakeMeAdmin registry', 'Created fake MakeMeAdmin registry + service'
    )
}).Count -gt 0
$mmaService = Get-CimInstance Win32_Service -Filter "Name='MakeMeAdminService'" -EA SilentlyContinue
$mmaOwned = $mmaAction -or ($mmaService -and $mmaService.PathName -match '^"?C:\\PrivHoundLab\\')
if ($mmaOwned) { Remove-LabPath 'MakeMeAdmin registry' $mmaPath }
elseif (Test-Path -LiteralPath $mmaPath) {
    $Script:FailureCount++
    Write-Host '  [!] Preserved unowned MakeMeAdmin registry key.' -ForegroundColor Yellow
}
$mmaParent = 'HKLM:\SOFTWARE\Sinclair Community College'
$mmaKey = Get-Item -LiteralPath $mmaParent -EA SilentlyContinue
if ($mmaOwned -and $mmaKey -and -not $mmaKey.SubKeyCount -and -not $mmaKey.ValueCount) {
    Remove-LabPath 'MakeMeAdmin parent key' $mmaParent
}

# ── WSUS HTTP config ──
$wsusPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wsusBaseline = $actions | Where-Object { $_.check -eq 'WSUS' -and $_.action -eq 'Original policies' } | Select-Object -Last 1
if ($wsusBaseline) {
    try {
        $original = $wsusBaseline.detail | ConvertFrom-Json -EA Stop
        $baselineProperties = @($original.PSObject.Properties | ForEach-Object { $_.Name })
        if ('values' -notin $baselineProperties) {
            $legacyValues = @{}
            foreach ($name in @('WUServer','WUStatusServer','UseWUServer')) {
                $legacyValues[$name] = @{ existed = ($null -ne $original.$name); value = $original.$name }
            }
            $original = [pscustomobject]@{ key_existed = $true; values = [pscustomobject]$legacyValues }
        }
        foreach ($name in @('WUServer','WUStatusServer','UseWUServer')) {
            $baseline = $original.values.$name
            if (-not $baseline.existed) { Remove-LabValue "WSUS $name" $wsusPath $name }
            else {
                $value = $baseline.value
                Remove-Quietly "WSUS $name (restore original)" {
                    Set-ItemProperty -LiteralPath $wsusPath -Name $name -Value $value -EA Stop
                }
            }
        }
        if (-not $original.key_existed) { Remove-LabKeyIfEmpty 'WSUS policy key' $wsusPath }
    } catch { $Script:FailureCount++; Write-Host "  [!] Invalid WSUS baseline: $_" -ForegroundColor Red }
} else { Preserve-LabSetting 'WSUS policies (no recorded baseline)' }

# ── WMI Subscriptions ──
$binding = Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' -EA SilentlyContinue | Where-Object { $_.Consumer -match 'PHLabWMIConsumer' }
if ($binding) { Remove-Quietly 'WMI binding PHLabWMIConsumer' { $binding | Remove-WmiObject -EA Stop } }
else { Skip-LabItem 'WMI binding PHLabWMIConsumer' }
$consumer = Get-WmiObject -Namespace 'root\subscription' -Class 'CommandLineEventConsumer' -EA SilentlyContinue | Where-Object { $_.Name -eq 'PHLabWMIConsumer' }
if ($consumer) { Remove-Quietly 'WMI consumer PHLabWMIConsumer' { $consumer | Remove-WmiObject -EA Stop } }
else { Skip-LabItem 'WMI consumer PHLabWMIConsumer' }
$filter = Get-WmiObject -Namespace 'root\subscription' -Class '__EventFilter' -EA SilentlyContinue | Where-Object { $_.Name -eq 'PHLabWMIFilter' }
if ($filter) { Remove-Quietly 'WMI filter PHLabWMIFilter' { $filter | Remove-WmiObject -EA Stop } }
else { Skip-LabItem 'WMI filter PHLabWMIFilter' }

# ── COM Hijack test CLSID ──
$testCLSID = "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"
$p = "HKLM:\SOFTWARE\Classes\CLSID\$testCLSID"
# The Task Scheduler registration may be real; only remove a lab-owned key.
$createdByLab = @($actions | Where-Object {
    $_.check -eq "COMHijack" -and $_.detail -eq $testCLSID -and
    $_.action -in @("Creating HKCR CLSID for COM hijack test", "Created HKCR CLSID for COM hijack test")
}).Count -gt 0
if ($createdByLab) { Remove-LabPath 'COM test CLSID HKLM' $p }
elseif (Test-Path $p) { Write-Host "  [i] Preserved pre-existing COM registration: $testCLSID" -ForegroundColor Yellow }
else { Skip-LabItem 'COM test CLSID HKLM' }

# ── WebClient relay ──
$webAction = $actions | Where-Object { $_.check -eq 'WebClientRelay' -and $_.action -match '^Set WebClient to Manual \(was: (.+)\)$' } | Select-Object -Last 1
if ($webAction -and $webAction.action -match '\(was: (Auto|Automatic|Manual|Disabled)\)$') {
    $startupType = if ($Matches[1] -eq 'Auto') { 'Automatic' } else { $Matches[1] }
    if (Get-Service WebClient -EA SilentlyContinue) {
        Remove-Quietly "WebClient start type (restore $startupType)" {
            Set-Service WebClient -StartupType $startupType -EA Stop
        }
    } else { Skip-LabItem 'WebClient service' }
} else { Preserve-LabSetting 'WebClient start type' }
$ldapAction = $actions | Where-Object { $_.check -eq 'WebClientRelay' -and $_.action -eq 'Set LDAP signing to negotiate (1)' } | Select-Object -Last 1
$ldapPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LDAP'
if ($ldapAction) {
    try {
        $baseline = $ldapAction.detail | ConvertFrom-Json -EA Stop
        if ($baseline.value_existed) {
            $origLdap = [int]$baseline.value
            Remove-Quietly "LDAP signing policy (restore $origLdap)" {
                Set-ItemProperty -Path $ldapPath -Name 'LDAPClientIntegrity' -Value $origLdap -Type DWord -EA Stop
            }
        } else { Remove-LabValue 'LDAP signing policy' $ldapPath 'LDAPClientIntegrity' }
        if (-not $baseline.key_existed) { Remove-LabKeyIfEmpty 'LDAP policy key' $ldapPath }
    } catch {
        if ($ldapAction.detail -match '^Original: (\d+)$') {
            $origLdap = [int]$Matches[1]
            Remove-Quietly "LDAP signing policy (restore $origLdap)" {
                Set-ItemProperty -Path $ldapPath -Name 'LDAPClientIntegrity' -Value $origLdap -Type DWord -EA Stop
            }
        } elseif ($ldapAction.detail -eq 'Original: ') {
            Remove-LabValue 'LDAP signing policy' $ldapPath 'LDAPClientIntegrity'
        } else {
            $Script:FailureCount++
            Write-Host "  [!] Invalid LDAP signing baseline: $_" -ForegroundColor Red
        }
    }
} else { Preserve-LabSetting 'LDAP policy' }

# ── AutoLogon credentials ──
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoBaseline = $actions | Where-Object { $_.check -eq 'AutoLogon' -and $_.action -eq 'Original values' } | Select-Object -Last 1
if ($autoBaseline) {
    try {
        $original = $autoBaseline.detail | ConvertFrom-Json -EA Stop
        foreach ($name in @('DefaultUserName','DefaultPassword','DefaultDomainName')) {
            if ($null -eq $original.$name) { Remove-LabValue "AutoLogon $name" $winlogonPath $name }
            else {
                $value = $original.$name
                Remove-Quietly "AutoLogon $name (restore original)" {
                    Set-ItemProperty -LiteralPath $winlogonPath -Name $name -Value $value -EA Stop
                }
            }
        }
    } catch { $Script:FailureCount++; Write-Host "  [!] Invalid AutoLogon baseline: $_" -ForegroundColor Red }
} else { Preserve-LabSetting 'AutoLogon values (no recorded baseline)' }

# ── UAC settings ──
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacAction = $actions | Where-Object {
    $_.check -eq 'UAC' -and $_.detail -match '^Original consent=(\d+)?(;|$)'
} | Select-Object -Last 1
if ($uacAction -and $uacAction.detail -match '^Original consent=(\d+)(;|$)') {
    $origConsent = [int]$Matches[1]
    Remove-Quietly "UAC ConsentPromptBehaviorAdmin (restore $origConsent)" {
        Set-ItemProperty -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value $origConsent -Type DWord -EA Stop
    }
} elseif ($uacAction -and $uacAction.detail -match '^Original consent=;') {
    Remove-LabValue 'UAC ConsentPromptBehaviorAdmin' $uacPath 'ConsentPromptBehaviorAdmin'
} else { Preserve-LabSetting 'UAC consent policy' }
if ($uacAction -and $uacAction.detail -match 'localFilter=(\d+)') {
    $origFilter = [int]$Matches[1]
    Remove-Quietly "UAC LocalAccountTokenFilterPolicy (restore $origFilter)" {
        Set-ItemProperty -Path $uacPath -Name 'LocalAccountTokenFilterPolicy' -Value $origFilter -Type DWord -EA Stop
    }
} elseif ($uacAction -and $uacAction.detail -match 'localFilter=$') {
    Remove-LabValue 'UAC LocalAccountTokenFilterPolicy' $uacPath 'LocalAccountTokenFilterPolicy'
} else { Preserve-LabSetting 'LocalAccountTokenFilterPolicy' }

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
$pantherDir = Split-Path -Parent $unattendFile
if (Test-Path -LiteralPath $unattendFile) {
    $unattendText = Get-Content -LiteralPath $unattendFile -Raw -EA SilentlyContinue
    # Older lab fixtures have no marker: match their unique encoded password
    # and account together, never an arbitrary system unattend file.
    $labUnattend = $unattendText -match '<!-- PrivHoundLab fixture -->' -or
        ($unattendText -match '<Value>\s*UEhMYWJUZXN0UGFzcw==\s*</Value>' -and
         $unattendText -match '<Username>\s*Administrator\s*</Username>')
    if ($labUnattend) { Remove-LabPath 'Lab unattend file' $unattendFile }
    else { Write-Host '  [i] Preserved non-lab unattend.xml' }
}
$pantherCreated = @($actions | Where-Object {
    $_.check -eq 'Unattend' -and
    $_.action -in @('Creating Panther directory','Created Panther directory') -and
    $_.detail -ieq $pantherDir
}).Count -gt 0
if ($pantherCreated) {
    Remove-LabDirectoryIfEmpty 'Empty Panther directory created by lab' $pantherDir
}

# ── GPP History ──
$gppHistoryRoot = 'C:\ProgramData\Microsoft\Group Policy\History\{PHLAB-TEST}'
$gppHistoryDir = Join-Path $gppHistoryRoot 'Machine\Preferences\Groups'
$gppHistoryCreated = @($actions | Where-Object {
    $_.check -eq 'GPP' -and (
        ($_.action -eq 'Creating lab GPP history directory' -and $_.detail -ieq $gppHistoryDir) -or
        ($_.action -eq 'Placed Groups.xml with cpassword in GPP History' -and $_.detail -ieq $gppHistoryDir)
    )
}).Count -gt 0
if ($gppHistoryCreated) {
    Remove-LabPath 'GPP History test directory' $gppHistoryRoot
} elseif (Test-Path -LiteralPath $gppHistoryRoot) {
    $Script:FailureCount++
    Write-Host "  [!] Preserved unowned GPP history directory: $gppHistoryRoot" -ForegroundColor Yellow
}

# ── Sensitive files (in PHLabUser's profile - handle .DOMAIN.NNN suffix) ──
$labUserProfiles = Get-ChildItem "C:\Users" -Directory -Filter "PHLabUser*" -EA SilentlyContinue
foreach ($lup in $labUserProfiles) {
    Remove-LabPath ".git-credentials ($($lup.Name))" (Join-Path $lup.FullName ".git-credentials")
    Remove-LabPath "Fake .kdbx ($($lup.Name))" (Join-Path $lup.FullName "Documents\PHLab_passwords.kdbx")
    Remove-LabPath "Fake .rdg ($($lup.Name))" (Join-Path $lup.FullName "Documents\PHLab_servers.rdg")
}

# ── Sensitive files in admin profile ──
$adminProfile = $env:USERPROFILE
$adminGitCreds = Join-Path $adminProfile '.git-credentials'
if (@($actions | Where-Object { $_.check -eq 'SensFile' -and
    $_.action -in @('Creating .git-credentials in admin profile','Created .git-credentials in admin profile for detection') -and
    $_.detail -eq $adminGitCreds }).Count -gt 0) {
    Remove-LabPath 'Admin .git-credentials' $adminGitCreds
} else { Skip-LabItem 'Lab admin .git-credentials' }
foreach ($file in @(
    @{name='PHLab_passwords.kdbx'; action='Created .kdbx in admin profile for detection'; creating='Creating .kdbx in admin profile'},
    @{name='PHLab_servers.rdg'; action='Created .rdg in admin profile for detection'; creating='Creating .rdg in admin profile'}
)) {
    $path = Join-Path $adminProfile "Documents\$($file.name)"
    if (@($actions | Where-Object { $_.check -eq 'SensFile' -and
        $_.action -in @($file.action, $file.creating) -and $_.detail -eq $path }).Count -gt 0) {
        Remove-LabPath "Admin $($file.name)" $path
    }
}
$adminDocs = Join-Path $adminProfile 'Documents'
$adminDocsCreated = @($actions | Where-Object {
    $_.check -eq 'SensFile' -and
    $_.action -in @('Creating admin Documents directory','Created admin Documents directory') -and
    $_.detail -ieq $adminDocs
}).Count -gt 0
if ($adminDocsCreated) {
    Remove-LabDirectoryIfEmpty 'Empty admin Documents directory created by lab' $adminDocs
}

# ── Program Files dir ──
$programFilesLabDir = Join-Path $env:ProgramFiles 'PHLabApp'
$programFilesLabCreated = @($actions | Where-Object {
    $_.check -eq 'ProgDir' -and $_.detail -ieq $programFilesLabDir -and
    $_.action -in @('Creating lab directory','Created writable dir in Program Files')
}).Count -gt 0
if ($programFilesLabCreated) {
    Remove-LabPath 'PHLabApp in Program Files' $programFilesLabDir
} elseif (Test-Path -LiteralPath $programFilesLabDir) {
    $Script:FailureCount++
    Write-Host "  [!] Preserved unowned Program Files directory: $programFilesLabDir" -ForegroundColor Yellow
}

# ── Cross-user profile (handle .DOMAIN.NNN suffix) ──
$crossProfiles = Get-ChildItem "C:\Users" -Directory -Filter "PHLabCrossUser*" -EA SilentlyContinue
foreach ($cp in $crossProfiles) {
    Remove-LabPath "Cross-user .git-credentials ($($cp.Name))" (Join-Path $cp.FullName '.git-credentials')
    Remove-LabPath "Cross-user PS history ($($cp.Name))" (Join-Path $cp.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')
}

# ── Test users ──
$labUsers = @('PHLabSvcUser','PHLabCrossUser','PHLabXPrivUser','PHLabUser')
$labProfiles = @()
foreach ($name in $labUsers) {
    $user = Get-LocalUser -Name $name -EA SilentlyContinue
    if ($user) {
        $labProfiles += @(Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'" -EA SilentlyContinue)
    }
}
$labUsers | ForEach-Object { Remove-LabUser $_ }
# Also locate orphaned profiles from earlier teardowns, when the accounts were
# removed but their Windows profile records were left behind.
$profileRoot = Join-Path $env:SystemDrive 'Users'
$labProfilePattern = '^(PHLabSvcUser|PHLabCrossUser|PHLabXPrivUser|PHLabUser)(\.[A-Za-z0-9_.-]+)?$'
$labProfiles += @(Get-CimInstance Win32_UserProfile -EA SilentlyContinue | Where-Object {
    $_.LocalPath -and
    [IO.Path]::GetDirectoryName($_.LocalPath) -ieq $profileRoot -and
    [IO.Path]::GetFileName($_.LocalPath) -match $labProfilePattern
})
foreach ($profile in @($labProfiles | Where-Object { $_ } | Sort-Object SID -Unique)) {
    if (-not $profile.LocalPath -or
        [IO.Path]::GetDirectoryName($profile.LocalPath) -ine $profileRoot -or
        [IO.Path]::GetFileName($profile.LocalPath) -notmatch $labProfilePattern) { continue }
    $accountName = [regex]::Match([IO.Path]::GetFileName($profile.LocalPath), $labProfilePattern).Groups[1].Value
    if (Get-LocalUser -Name $accountName -EA SilentlyContinue) {
        Write-Host "  [i] Kept profile for account still present: $($profile.LocalPath)"
        continue
    }
    if ($profile.Loaded) {
        $Script:FailureCount++
        Write-Host "  [i] Lab profile still loaded; log off user before removing: $($profile.LocalPath)" -ForegroundColor Yellow
        continue
    }
    Remove-Quietly "Lab user profile $($profile.LocalPath)" { $profile | Remove-CimInstance -EA Stop }
}
# Remove leftover lab-named directories only when neither a local account nor a registered profile remains.
try {
    $registeredProfiles = @(Get-CimInstance Win32_UserProfile -EA Stop)
    foreach ($directory in (Get-ChildItem -LiteralPath $profileRoot -Directory -EA Stop)) {
        $match = [regex]::Match($directory.Name, $labProfilePattern)
        if (-not $match.Success) { continue }
        if (Get-LocalUser -Name $match.Groups[1].Value -EA SilentlyContinue) { continue }
        if (@($registeredProfiles | Where-Object { $_.LocalPath -ieq $directory.FullName }).Count -gt 0) { continue }
        Remove-LabPath "Orphan lab profile directory $($directory.FullName)" $directory.FullName
    }
} catch {
    $Script:FailureCount++
    Write-Host "  [!] Could not inspect orphan lab profiles: $_" -ForegroundColor Red
}

# ── Shadow copies (lab-created) ──
$shadowIds = @($actions | Where-Object {
    $_.check -eq 'ShadowCopy' -and $_.action -eq 'Created shadow copy for C:' -and
    $_.detail -match '^\{[0-9A-Fa-f-]{36}\}$'
} | Select-Object -ExpandProperty detail -Unique)
if ($shadowIds.Count -gt 0) {
    foreach ($shadowId in $shadowIds) {
        Remove-LabShadowCopy $shadowId
    }
} else { Preserve-LabSetting 'existing shadow copies' }
if (@($actions | Where-Object {
    $_.check -eq 'ShadowCopy' -and $_.action -eq 'Failed to record shadow copy ID'
}).Count -gt 0) {
    $Script:FailureCount++
    Write-Host '  [!] Lab created a shadow copy without recording its ID; inspect vssadmin list shadows before removing anything.' -ForegroundColor Red
}

# ── Lab working directories ──
# Remove lab working directories even if another cleanup step failed, so stale files do not block setup.
# Retain protected recovery data until cleanup succeeds and pending service removal is resolved.
Remove-LabPath 'Lab root C:\PrivHoundLab' 'C:\PrivHoundLab'
Remove-LabPath 'Lab run directory C:\PrivHoundRun' 'C:\PrivHoundRun'
if ($Script:FailureCount -eq 0 -and -not $Script:PendingReboot) {
    Remove-LabPath 'Protected lab recovery data' $stateRoot
}

$teardownLines = @("Already absent: $Script:AlreadyAbsentCount  |  Failures: $Script:FailureCount")
if ($Script:PreservedSettings.Count) {
    $teardownLines += 'No baseline; preserved:'
    $teardownLines += @($Script:PreservedSettings | ForEach-Object { "  $_" })
}
if ($Script:FailureCount) {
    $teardownLines += 'Resolve failures before retrying.'
}
if ($Script:PendingReboot) {
    $teardownLines += 'Reboot, then rerun teardown to verify service removal.'
} else {
    $teardownLines += 'Restart Windows to finish cleanup.'
}
$boxWidth = [Math]::Max(40, [int](($teardownLines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum) + 4)
$boxColor = if ($Script:FailureCount -or $Script:PendingReboot) { 'Yellow' } else { 'Green' }
Write-Host ("`n  +" + ('-' * $boxWidth) + '+') -ForegroundColor $boxColor
Write-Host ('  |  ' + 'Teardown Finished'.PadRight($boxWidth - 4) + '  |') -ForegroundColor $boxColor
Write-Host ('  +' + ('-' * $boxWidth) + '+') -ForegroundColor $boxColor
foreach ($line in $teardownLines) {
    $lineColor = if ($Script:FailureCount -and $line -like '*Failures:*') { 'Red' } else { $boxColor }
    Write-Host ('  |  ' + $line.PadRight($boxWidth - 4) + '  |') -ForegroundColor $lineColor
}
Write-Host ('  +' + ('-' * $boxWidth) + "+`n") -ForegroundColor $boxColor

$restart = Read-Host '  Restart Windows now to finish teardown? [y/N]'
if ($restart -match '^(?i:y|yes)$') {
    try {
        Restart-Computer -Force -EA Stop
    } catch {
        Write-Host "  [!] Restart failed: $_" -ForegroundColor Red
    }
} else {
    Write-Host '  [i] Restart skipped. Restart Windows later to finish teardown.' -ForegroundColor Yellow
}
