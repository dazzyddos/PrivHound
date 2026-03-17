<#
.SYNOPSIS
    PrivHound v1.4.0 - Windows Local PrivEsc Collector for BloodHound OpenGraph
.DESCRIPTION
    Enumerates local privilege escalation vectors and outputs BloodHound OpenGraph JSON.
.PARAMETER OutputPath
    Output JSON path. Default: .\privhound_<hostname>_<timestamp>.json
.PARAMETER OutputFormat
    BloodHound | BloodHound-customnodes | All (default: All)
.PARAMETER SkipChecks
    Checks to skip: Services, UnquotedPaths, DLLHijacking, AlwaysInstall, TokenPrivileges, ScheduledTasks, Autoruns, RegistryKeys, StoredCreds, GPPPasswords, UnattendFiles, PSHistory, SensitiveFiles, UACBypass, WritableProgDirs, CrossUserProfiles, CredLoginPaths, CrossUserPriv, JITAdmin, PrintSpooler, WSUSConfig, SCCMCreds, COMHijacking, NamedPipes, CachedCreds, WMISubscriptions, WebClientRelay, SvcRecovery, ShadowCopies
.PARAMETER NoCredTest
    Skip credential validation (Test-LocalCredential). No PHCanLoginAs edges will be created.
.EXAMPLE
    .\PrivHound.ps1
    .\PrivHound.ps1 -OutputFormat BloodHound-customnodes
    .\PrivHound.ps1 -SkipChecks "ScheduledTasks","Autoruns"
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [ValidateSet('BloodHound','BloodHound-customnodes','All')]
    [string]$OutputFormat = "All",
    [string[]]$SkipChecks = @(),
    [switch]$NoCredTest
)

$Script:VERSION = "1.4.0"
$Script:HOSTNAME = $env:COMPUTERNAME.ToUpper()
if (-not $OutputPath) { $OutputPath = ".\privhound_$($Script:HOSTNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).json" }

$Script:DangerousPrivileges = @("SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege","SeBackupPrivilege","SeRestorePrivilege","SeDebugPrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege","SeCreateTokenPrivilege","SeTcbPrivilege","SeManageVolumePrivilege")
$Script:Nodes = [System.Collections.ArrayList]::new()
$Script:Edges = [System.Collections.ArrayList]::new()
$Script:Findings = [System.Collections.ArrayList]::new()
$Script:NodeIds = @{}
$Script:EdgeIds = @{}
$Script:ExtractedCreds = [System.Collections.ArrayList]::new()
$Script:ValidatedCreds = [System.Collections.ArrayList]::new()
$Script:CachedServiceSDDL = @{}
$Script:CachedServiceRecovery = @{}
$Script:NoCredTest = $NoCredTest.IsPresent
$Script:CachedServices = $null
$Script:CachedLocalUsers = $null

function Write-PHBanner { Write-Host "`n  PrivHound v$Script:VERSION - Windows PrivEsc -> BloodHound OpenGraph`n  Target: $Script:HOSTNAME | User: $env:USERDOMAIN\$env:USERNAME`n" -ForegroundColor Red }
function Write-PHStatus($Message, $Type="info") { $c = switch($Type){"info"{"Cyan"}"finding"{"Green"}"warn"{"Yellow"}"error"{"Red"}}; Write-Host "  [$($Type[0])] $Message" -ForegroundColor $c }

function New-PHId([string]$Type,[string]$Name) {
    $h = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Script:HOSTNAME|$Type|$Name"))).Replace("-","").Substring(0,32).ToUpper()
    return $h
}

function Add-PHNode([string]$Id,[string[]]$Kinds,[hashtable]$Properties) {
    if ($Script:NodeIds.ContainsKey($Id)) { return $Id }
    $Script:NodeIds[$Id] = $true
    if ($Properties.ContainsKey("name")) { $Properties["name"] = $Properties["name"].ToUpper() }
    $Properties["objectid"] = $Id
    # Remove null values — OpenGraph schema rejects them
    $nullKeys = @($Properties.Keys | Where-Object { $null -eq $Properties[$_] })
    foreach ($k in $nullKeys) { $Properties.Remove($k) }
    [void]$Script:Nodes.Add(@{ id=$Id; kinds=$Kinds; properties=$Properties })
    return $Id
}

$Script:EdgeAbuseInfo = @{
    PHCanModifyService = @{
        description = "User can reconfigure this service binary path via sc.exe or ChangeServiceConfig API, redirecting it to an attacker-controlled executable that runs as SYSTEM on next service start."
        abuse_info  = "Modify the service binPath to point to an attacker-controlled executable, then restart the service. The new binary will execute under the service account. See MITRE T1543.003 for details."
        opsec       = "Generates Event IDs 7045/4697. Restore original binPath immediately after exploitation."
    }
    PHCanWriteBinary = @{
        description = "User has write access to the service executable on disk. Replacing it gives SYSTEM execution when the service starts."
        abuse_info  = "Back up the original binary, replace it with an attacker-controlled executable, then restart the service. The replacement runs under the service account. See MITRE T1574.010."
        opsec       = "File replacement triggers FIM and EDR file-write alerts. Restore original binary immediately."
    }
    PHCanHijackPath = @{
        description = "Service has an unquoted path with spaces. Windows tries intermediate paths (e.g., C:\Program.exe before C:\Program Files\App\svc.exe). A writable intermediate directory allows placing a hijack binary."
        abuse_info  = "Identify the hijack point from the unquoted path, place an executable at that location, and restart the service. Windows will execute the planted binary instead of the intended one. See MITRE T1574.009."
        opsec       = "Dropping an exe in C:\Program Files is conspicuous. Clean up immediately after exploitation."
    }
    PHCanWriteTo = @{
        description = "User can write to a directory in the system PATH. Privileged processes searching for DLLs will load a planted DLL from this directory."
        abuse_info  = "Identify DLLs that a privileged service fails to load, then place a DLL with that name in the writable PATH directory. The service will load it on next start. See MITRE T1574.001."
        opsec       = "DLL side-loading is a known EDR detection vector. Use a proxy DLL with forwarded exports."
    }
    PHDLLHijackTo = @{
        description = "A writable PATH directory enables DLL hijacking into a SYSTEM-level process."
        abuse_info  = "Plant a DLL in the writable directory matching a name searched by a SYSTEM service. See MITRE T1574.001."
        opsec       = "Monitor which processes load from the directory before planting to avoid detection."
    }
    PHCanExploit = @{
        description = "AlwaysInstallElevated is enabled in both HKLM and HKCU. Any user can install MSI packages that execute as SYSTEM."
        abuse_info  = "Create an MSI package containing an attacker payload and install it silently with msiexec /quiet /qn /i. The MSI runs as SYSTEM due to the policy. See MITRE T1548.002."
        opsec       = "MSI install generates Windows Installer Event IDs 1033/1034 and Sysmon process creation events."
    }
    PHHasPrivilege = @{
        description = "User holds a dangerous Windows token privilege that can be abused for privilege escalation to SYSTEM."
        abuse_info  = "Abuse depends on specific privilege. SeImpersonate: token impersonation via named pipe or COM coercion. SeDebug: inject into or dump SYSTEM processes. SeBackup: read protected registry hives. SeRestore: overwrite protected files. SeTakeOwnership: take ownership of protected objects. SeLoadDriver: load a vulnerable kernel driver. See MITRE T1134.001."
        opsec       = "Token impersonation exploits create named pipes/COM objects triggering ETW events. LSASS access is heavily monitored."
    }
    PHCanEscalateTo = @{
        description = "This privilege enables escalation to the SYSTEM account via token impersonation or direct exploitation."
        abuse_info  = "Exploit the associated token privilege to obtain SYSTEM-level access. The technique varies by privilege type - see the associated PHHasPrivilege edge for specifics. See MITRE T1134.001."
        opsec       = "Choose exploit based on target OS version. Test in lab before deploying."
    }
    PHCanWriteTaskBinary = @{
        description = "User can replace the executable run by a scheduled task configured to run as SYSTEM."
        abuse_info  = "Back up the original task binary, replace it with an attacker-controlled executable, then wait for the task to run or trigger it manually with schtasks /run. See MITRE T1053.005."
        opsec       = "Task execution logged under Event ID 4698/4702 and TaskScheduler operational log."
    }
    PHCanWriteAutorun = @{
        description = "User can replace an executable in an HKLM Run/RunOnce autorun key. It executes as the next user who logs in (often an admin)."
        abuse_info  = "Back up the original autorun binary, replace it with an attacker-controlled executable, then wait for a privileged user to log in. See MITRE T1547.001."
        opsec       = "Requires waiting for a privileged user to log in. Replaced binary visible to autorun enumeration."
    }
    PHCanModifyRegKey = @{
        description = "User has write access to a service registry key (HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>), allowing modification of ImagePath to point to an attacker-controlled binary."
        abuse_info  = "Modify the ImagePath value under the service registry key to point to an attacker-controlled executable, then restart the service. Restore original ImagePath after exploitation. See MITRE T1574.011."
        opsec       = "Registry modification generates Event ID 4657. Restore original ImagePath immediately."
    }
    PHHasStoredCreds = @{
        description = "Windows Credential Manager contains saved credentials. If /savecred was used, commands can be run as that user without a password."
        abuse_info  = "Enumerate stored credentials with cmdkey /list. If /savecred entries exist, use runas /savecred /user:TARGET_USER to execute commands as that user. See MITRE T1555.004."
        opsec       = "runas /savecred creates Event ID 4648 (explicit credential logon) easily correlated to the caller."
    }
    PHCanReadCreds = @{
        description = "Plaintext or encoded credentials are readable from a file or registry key accessible to the current user."
        abuse_info  = "AutoLogon: query Winlogon registry key for DefaultPassword. Unattend files: search for Password elements and decode Base64 values. See MITRE T1552.001."
        opsec       = "Reading registry/files is low-noise. Using recovered credentials will produce logon events (4624/4648)."
    }
    PHCanDecryptGPP = @{
        description = "A GPP XML file contains a cpassword attribute encrypted with Microsoft's publicly known AES key (MS14-025). Any domain user can decrypt it."
        abuse_info  = "Search GPP XML files for cpassword attributes. The AES key is publicly documented by Microsoft (MS14-025), so the password can be decrypted offline. See MITRE T1552.006."
        opsec       = "Accessing SYSVOL is normal domain traffic. Watch for decoy GPP files (honeypots)."
    }
    PHCanReadHistory = @{
        description = "PowerShell command history (ConsoleHost_history.txt) or transcript logs are accessible and may contain credentials, API keys, or sensitive commands."
        abuse_info  = "Read ConsoleHost_history.txt from PSReadLine directory. Search for patterns like password, secret, key, token. Also check transcript log directories if configured. See MITRE T1552.001."
        opsec       = "Reading text files is low-noise. Accessing other users' profiles may trigger access auditing."
    }
    PHCanAccessFile = @{
        description = "Sensitive file accessible to current user: SAM/SYSTEM backups (offline hash extraction), KeePass databases (.kdbx), RDCMan files (.rdg), or Git credential stores."
        abuse_info  = "SAM/SYSTEM: copy hives and extract hashes offline. KeePass: extract master hash and crack offline. RDG: decrypt stored RDP credentials. Git creds: read plaintext tokens/passwords from .git-credentials. See MITRE T1552.001."
        opsec       = "SAM/SYSTEM access is high-fidelity detection. Copy files to staging dir and process offline."
    }
    PHCanBypassUAC = @{
        description = "User is admin but running non-elevated (filtered token), or UAC is misconfigured (ConsentPromptBehaviorAdmin=0). Auto-elevation bypass gives full admin without a prompt."
        abuse_info  = "Use an auto-elevation technique to spawn an elevated process without triggering a UAC prompt. Common methods involve abusing trusted Windows binaries that auto-elevate. See MITRE T1548.002."
        opsec       = "Registry-based UAC bypasses leave well-known IoCs. Clean up immediately after use."
    }
    PHCanWriteProgDir = @{
        description = "User can write to a subdirectory of Program Files. Applications or services running from this directory may load attacker-planted DLLs or executables."
        abuse_info  = "Identify services or applications running from the writable directory, then plant a DLL or replace an executable to gain code execution in their context. See MITRE T1574.010."
        opsec       = "Writing to Program Files triggers real-time AV scanning and EDR file-write monitoring."
    }
    PHCanLoginAs = @{
        description = "Cleartext credentials found on this system are valid for this local user account, enabling direct authentication."
        abuse_info  = "Use runas /user:TARGET_USER or create a PSCredential and invoke Start-Process / Invoke-Command to authenticate as the target user. If the target is an Administrator, this is a direct privilege escalation. See MITRE T1078.003."
        opsec       = "Logon events (Event ID 4624 type 2/10) and runas usage (4648) will be generated."
    }
    PHMemberOf = @{
        description = "This local user is a member of the local Administrators group, granting full administrative control over the system."
        abuse_info  = "Authenticate as this user to obtain administrative access. Use runas, PSCredential, or pass-the-hash techniques. See MITRE T1078.003."
        opsec       = "Administrative logon events will be generated. Group membership is visible via net localgroup."
    }
    PHHostsBinaryFor = @{
        description = "A service or scheduled task runs a binary located within this writable directory."
        abuse_info  = "Identify the binary inside this directory used by the service/task. Replace or trojanize it so the service/task executes attacker code on next start. See MITRE T1574.010."
        opsec       = "File replacement in Program Files triggers AV/EDR file-write alerts. Back up and restore the original."
    }
    PHRunsAsUser = @{
        description = "This service runs under a named local user account (not SYSTEM). Compromising the service yields execution as that user."
        abuse_info  = "Exploit the parent finding (modifiable service config, writable binary) to gain code execution as the service account. If the service account is an admin, this is a direct privilege escalation."
        opsec       = "Service restart may be logged. Check service recovery settings."
    }
    PHCanReadProtected = @{
        description = "SeBackupPrivilege allows reading protected files (SAM/SYSTEM registry hives) that normally require SYSTEM access."
        abuse_info  = "Use reg save HKLM\\SAM sam.hiv and reg save HKLM\\SYSTEM system.hiv to export the hives. Extract local password hashes offline with secretsdump or mimikatz. See MITRE T1003.002."
        opsec       = "Registry export creates Event ID 4656/4663. Copy hives to staging directory and process offline."
    }
    PHCanExtractHashes = @{
        description = "SAM and SYSTEM hive backups can be combined to extract local account password hashes for offline cracking or pass-the-hash attacks."
        abuse_info  = "Use secretsdump.py -sam sam.hiv -system system.hiv LOCAL or mimikatz lsadump::sam to extract NTLM hashes. Crack or pass-the-hash to authenticate as local admin. See MITRE T1003.002."
        opsec       = "Offline extraction is undetectable. Using recovered hashes for PtH generates Event ID 4624 type 3."
    }
    PHCanWriteProtected = @{
        description = "SeRestorePrivilege allows writing to any file on the system, bypassing ACLs. This can be used to replace protected service binaries or DLLs."
        abuse_info  = "Replace a DLL or executable loaded by a SYSTEM service with an attacker-controlled payload. The service will execute the payload on next start. See MITRE T1574.010."
        opsec       = "File replacement generates FIM alerts. Target a service with manual start to control timing."
    }
    PHCanInjectInto = @{
        description = "SeDebugPrivilege allows attaching to and injecting into any process, including those running as SYSTEM."
        abuse_info  = "Use process injection (CreateRemoteThread, NtCreateThreadEx) to inject shellcode into a SYSTEM process like winlogon.exe or lsass.exe. Alternatively, dump LSASS for credential extraction. See MITRE T1055."
        opsec       = "LSASS access is heavily monitored by EDR. Target less-monitored SYSTEM processes for injection."
    }
    PHCanLoginViaRunas = @{
        description = "Stored credentials in Windows Credential Manager allow running commands as the target user via runas /savecred without knowing the password."
        abuse_info  = "Use runas /savecred /user:TARGET_USER cmd.exe to spawn a shell as the target. If the target is admin, this is a direct privilege escalation. See MITRE T1555.004."
        opsec       = "runas /savecred generates Event ID 4648 (explicit credential logon)."
    }
    PHCanAccessProfile = @{
        description = "Current user can read another user's profile directory, potentially accessing sensitive files like credentials, history, and configuration."
        abuse_info  = "Enumerate the target profile for .git-credentials, ConsoleHost_history.txt, .kdbx, .rdg, and other sensitive files. Extract credentials for lateral movement or escalation."
        opsec       = "File access auditing may log reads on other users' profiles. Minimize file access footprint."
    }
    PHProfileContains = @{
        description = "This sensitive file was found inside another user's profile directory."
        abuse_info  = "Read and parse the file for credentials or secrets. .git-credentials contain plaintext tokens, .rdg files contain encrypted RDP passwords, .kdbx files can be cracked offline."
        opsec       = "Reading files from other profiles may trigger access auditing alerts."
    }
    PHContainsCreds = @{
        description = "This file contains embedded credentials (passwords, tokens, or secrets) that were detected by pattern matching."
        abuse_info  = "Extract the credentials from the file content. Test them against local and domain accounts for password reuse. Feed into the credential pipeline for automated validation."
        opsec       = "Credential extraction is file-read only. Using recovered credentials will produce logon events."
    }
    PHCanRequestJIT = @{
        description = "A JIT (Just-In-Time) admin tool is installed and the current user is allowed to request temporary administrator access."
        abuse_info  = "Use the JIT tool's UI or CLI to request temporary admin privileges. During the elevation window, extract credentials, install persistence, or pivot. See MITRE T1548."
        opsec       = "JIT requests are logged by the tool. Act within the time window and clean up before expiry."
    }
    PHGrantsTempAdmin = @{
        description = "This JIT admin tool grants temporary membership in the local Administrators group to approved users."
        abuse_info  = "Once temporary admin is granted, perform privileged actions: dump credentials, install services, modify ACLs. Persistence outlasts the JIT window if planted before expiry."
        opsec       = "JIT tools log elevation events. Some monitor for persistence mechanisms planted during the window."
    }
    PHCanExploitSpooler = @{
        description = "Print Spooler is running with vulnerable Point and Print configuration, enabling driver installation as SYSTEM (PrintNightmare-style)."
        abuse_info  = "Set up a malicious print server, then use Point and Print to install a crafted printer driver that executes as SYSTEM. Tools: CVE-2021-34527 PoCs, Impacket printerbug. See MITRE T1068."
        opsec       = "Print Spooler exploitation generates Event IDs 316/808 and Sysmon driver load events. Patch status is detectable."
    }
    PHCanExploitWSUS = @{
        description = "WSUS is configured to use HTTP (not HTTPS), enabling man-in-the-middle attacks to inject malicious updates that execute as SYSTEM."
        abuse_info  = "Perform ARP spoofing or WPAD hijack to intercept WSUS traffic, then inject a malicious update package using tools like WSUSpendu or SharpWSUS. The update executes as SYSTEM. See MITRE T1557."
        opsec       = "Requires network-level MITM. Injected updates appear in Windows Update history. WSUS server logs show the fake update."
    }
    PHCanReadNAA = @{
        description = "SCCM/MECM Network Access Account (NAA) credentials are stored locally and may be retrievable via WMI or DPAPI."
        abuse_info  = "Query WMI namespace root\\ccm\\policy\\Machine\\ActualConfig for CCM_NetworkAccessAccount. Decrypt the DPAPI-protected blob using SharpSCCM or sccmhunter. NAA creds often have domain-wide access. See MITRE T1552.001."
        opsec       = "WMI queries to CCM namespace may be logged. Using recovered domain creds generates logon events."
    }
    PHCanHijackCOM = @{
        description = "A COM object CLSID used by a SYSTEM-context process can be hijacked by planting a DLL in the per-user HKCU registry hive."
        abuse_info  = "Create HKCU\\Software\\Classes\\CLSID\\{target-CLSID}\\InprocServer32 pointing to an attacker DLL. The SYSTEM process loading this CLSID will execute the DLL. See MITRE T1546.015."
        opsec       = "Registry writes to HKCU\\Classes\\CLSID are a known EDR detection vector. DLL load events from unexpected paths trigger alerts."
    }
    PHCanImpersonatePipe = @{
        description = "A named pipe owned by a SYSTEM service has permissive ACLs allowing the current user to connect and potentially impersonate the server's token."
        abuse_info  = "Connect to the named pipe and use ImpersonateNamedPipeClient to obtain the server's SYSTEM token. Tools: PrintSpoofer, RoguePotato, EfsPotato. See MITRE T1134.001."
        opsec       = "Named pipe impersonation generates ETW pipe events. Some EDR products monitor for suspicious pipe creation/connection patterns."
    }
    PHHasCachedCreds = @{
        description = "Cached or stored credentials exist on this system: domain cached credentials (DCC2), WiFi passwords, WinSCP/FileZilla/PuTTY saved sessions."
        abuse_info  = "DCC2: extract from SECURITY hive and crack offline (hashcat mode 2100). WiFi: netsh wlan show profile key=clear. WinSCP: decrypt from registry. FileZilla: read plaintext XML. See MITRE T1552.001."
        opsec       = "Reading registry/files is low-noise. DCC2 cracking is offline. Using recovered creds generates logon events."
    }
    PHCanModifyWMI = @{
        description = "A WMI permanent event subscription consumer's binary or script path is writable by the current user. WMI subscriptions execute as SYSTEM."
        abuse_info  = "Replace the consumer's binary or script with an attacker payload. The WMI event subscription will execute it as SYSTEM when the associated event fires. See MITRE T1546.003."
        opsec       = "WMI subscription execution generates Event ID 5861. Modified consumer binaries trigger FIM/EDR alerts."
    }
    PHCanRelayWebClient = @{
        description = "WebClient service is installed and can be triggered on this domain-joined machine. Combined with default LDAP signing settings, this enables NTLM relay to the domain controller for local privilege escalation to SYSTEM."
        abuse_info  = "Trigger WebClient via SearchConnector file or ETW, coerce machine account auth to localhost HTTP relay, relay to DC LDAP, inject Shadow Credentials (msDS-KeyCredentialLink) or configure RBCD, obtain admin service ticket via S4U2Self, create SYSTEM service. Tools: WebClientRelayUp, DavRelayUp, KrbRelayUp. See MITRE T1187."
        opsec       = "Creates AD object modifications (Event ID 5136 for msDS-KeyCredentialLink). Service creation generates Event IDs 7045/4697. WebClient activation may be logged."
    }
    PHRunsAs = @{
        description = "This service or task runs under a privileged account (typically SYSTEM). Compromising it yields execution as that account."
        abuse_info  = "Exploit the parent finding (modifiable service, writable binary, unquoted path, etc.) to inject a payload into this service's execution context."
        opsec       = "Service restarts may be logged and noticed. Check if the service is set to auto-start."
    }
    PHEscalatesTo = @{
        description = "Exploiting this misconfiguration provides a direct escalation path to the target privilege level."
        abuse_info  = "Follow the abuse steps from the inbound edge. The result is code execution or credential access at the target privilege level (SYSTEM or Local Admin)."
        opsec       = "Escalation is the noisiest phase. Have your post-exploitation ready before triggering."
    }
    PHExecutesAs = @{
        description = "This autorun entry executes in a privileged context (HKLM = all users including admins)."
        abuse_info  = "Replace the autorun binary (see PHCanWriteAutorun). It will run with the privileges of the next user who logs in."
        opsec       = "HKLM autoruns execute for ALL users. An admin logon triggers the payload as admin."
    }
    PHHosts = @{
        description = "This computer hosts the indicated privilege target (SYSTEM account or Local Administrators group)."
        abuse_info  = "Informational edge. The computer is the assessment target. Follow attack paths from the user node to reach this target."
        opsec       = "N/A"
    }
    PHHasSessionOn = @{
        description = "The assessed user has an active session on this endpoint."
        abuse_info  = "Informational edge. This links the PrivHound user to the computer being assessed. Overlay with AD collection data to find AD attack paths."
        opsec       = "N/A"
    }
    PHCanWriteRecoveryBin = @{
        description = "Service failure recovery action executes a command whose binary is writable. Replacing it gives code execution as the service account on next crash."
        abuse_info  = "Replace the recovery command binary, crash the service (sc stop / taskkill). Windows executes the recovery command as the service account (usually SYSTEM). See MITRE T1574.010."
        opsec       = "Service crash generates Event ID 7034. Recovery command execution logged under 7036."
    }
    PHCanAccessShadowCopy = @{
        description = "Volume Shadow Copy contains accessible copies of sensitive system files (SAM, SYSTEM hives) that may have been deleted or patched on the live filesystem."
        abuse_info  = "Copy SAM and SYSTEM hives from the shadow copy path using copy or esentutl. Extract local password hashes offline with secretsdump or mimikatz. See MITRE T1003.002."
        opsec       = "Accessing shadow copies via direct path is low-noise. Shadow copies persist across reboots until deleted."
    }
    PHContainsSensitiveFile = @{
        description = "This shadow copy contains a sensitive system file that can be extracted for offline analysis."
        abuse_info  = "Copy the file from the shadow copy path to a staging directory. Process offline to extract credentials or hashes."
        opsec       = "File copy operations may trigger I/O monitoring. Process files offline to avoid detection."
    }
}

function Add-PHEdge([string]$StartId,[string]$EndId,[string]$Kind,[hashtable]$Properties=@{}) {
    $edgeKey = "$StartId|$EndId|$Kind"
    if ($Script:EdgeIds.ContainsKey($edgeKey)) { return }
    $Script:EdgeIds[$edgeKey] = $true
    if ($Script:EdgeAbuseInfo.ContainsKey($Kind)) {
        $info = $Script:EdgeAbuseInfo[$Kind]
        if (-not $Properties.ContainsKey("description"))  { $Properties["description"]  = $info.description }
        if (-not $Properties.ContainsKey("abuse_info"))    { $Properties["abuse_info"]    = $info.abuse_info }
        if (-not $Properties.ContainsKey("opsec"))         { $Properties["opsec"]         = $info.opsec }
    }
    # Remove null values — OpenGraph schema rejects them
    $nullKeys = @($Properties.Keys | Where-Object { $null -eq $Properties[$_] })
    foreach ($k in $nullKeys) { $Properties.Remove($k) }
    $e = @{ start=@{match_by="id";value=$StartId}; end=@{match_by="id";value=$EndId}; kind=$Kind }
    $e["properties"] = $Properties
    [void]$Script:Edges.Add($e)
}

function Add-PHFinding([string]$Check,[string]$Severity,[string]$Description,[string]$AbuseInfo) {
    [void]$Script:Findings.Add(@{Check=$Check;Severity=$Severity;Description=$Description;AbuseInfo=$AbuseInfo})
}

function Test-WritableAcl([string]$Path, [string[]]$Groups=$null) {
    try {
        if (-not (Test-Path $Path)) { return $false }
        if ($null -eq $Groups) {
            $Groups = @("Everyone","BUILTIN\\Users","Authenticated Users",$env:USERNAME)
            try { $Groups += ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }) } catch {}
        }
        foreach ($ace in (Get-Acl $Path -EA SilentlyContinue).Access) {
            if ($ace.AccessControlType -eq "Allow" -and
                ($ace.FileSystemRights -match "Write|Modify|FullControl") -and
                ($Groups | Where-Object { $ace.IdentityReference.Value -match [regex]::Escape($_) })) {
                return $true
            }
        }
    } catch {}
    return $false
}

# ── GPP CPASSWORD DECRYPTION ─────────
function Decrypt-GPPPassword([string]$Cpassword) {
    # MS14-025: Publicly known AES-256 key used by Microsoft for GPP cpassword encryption
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/
    try {
        # Pad Base64 to multiple of 4
        $pad = 4 - ($Cpassword.Length % 4)
        if ($pad -lt 4) { $Cpassword += "=" * $pad }
        $bytes = [Convert]::FromBase64String($Cpassword)
        $aesKey = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                           0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
        $aesIV = [byte[]](0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
        $aes.Dispose()
        return [System.Text.Encoding]::Unicode.GetString($decrypted)
    } catch {
        Write-PHStatus "Failed to decrypt GPP cpassword: $_" "warn"
        return $null
    }
}

# ── UNATTEND.XML PASSWORD EXTRACTION ──
function Get-UnattendPasswords([string]$FilePath) {
    $results = @()
    try {
        [xml]$xml = Get-Content $FilePath -Raw -EA Stop
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("u", "urn:schemas-microsoft-com:unattend")
        # Search for Password elements with Value children
        $passwordNodes = $xml.SelectNodes("//u:Password", $ns)
        if (-not $passwordNodes -or $passwordNodes.Count -eq 0) {
            # Try without namespace (some files lack it)
            $passwordNodes = $xml.SelectNodes("//Password")
        }
        foreach ($pwNode in $passwordNodes) {
            $value = $pwNode.Value
            $plainText = $pwNode.PlainText
            if (-not $value) { continue }
            # If PlainText is false, Base64-decode the value
            if ($plainText -eq "false") {
                try { $value = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($value)) }
                catch {
                    try { $value = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value)) }
                    catch { }
                }
                # Microsoft appends known suffixes before Base64 encoding; strip them
                foreach ($suffix in @("Password","AdministratorPassword")) {
                    if ($value -and $value.EndsWith($suffix)) { $value = $value.Substring(0, $value.Length - $suffix.Length) }
                }
            }
            # Try to find associated Username
            $username = $null
            $parent = $pwNode.ParentNode
            if ($parent) {
                $usernameNode = $parent.SelectSingleNode("u:Username", $ns)
                if (-not $usernameNode) { $usernameNode = $parent.SelectSingleNode("Username") }
                if ($usernameNode) { $username = $usernameNode.InnerText }
            }
            if ($value) {
                $results += @{ username = $username; password = $value }
            }
        }
        # Also check AdministratorPassword
        $adminPwNodes = $xml.SelectNodes("//u:AdministratorPassword", $ns)
        if (-not $adminPwNodes -or $adminPwNodes.Count -eq 0) {
            $adminPwNodes = $xml.SelectNodes("//AdministratorPassword")
        }
        foreach ($apNode in $adminPwNodes) {
            $value = $apNode.Value
            if (-not $value) {
                $valNode = $apNode.SelectSingleNode("u:Value", $ns)
                if (-not $valNode) { $valNode = $apNode.SelectSingleNode("Value") }
                if ($valNode) { $value = $valNode.InnerText }
            }
            $ptNode = $apNode.SelectSingleNode("u:PlainText", $ns)
            if (-not $ptNode) { $ptNode = $apNode.SelectSingleNode("PlainText") }
            $plainText = if ($ptNode) { $ptNode.InnerText } else { $null }
            if (-not $value) { continue }
            if ($plainText -eq "false") {
                try { $value = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($value)) }
                catch {
                    try { $value = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value)) }
                    catch { }
                }
                # Microsoft appends known suffixes before Base64 encoding; strip them
                foreach ($suffix in @("AdministratorPassword","Password")) {
                    if ($value -and $value.EndsWith($suffix)) { $value = $value.Substring(0, $value.Length - $suffix.Length) }
                }
            }
            if ($value) {
                $results += @{ username = "Administrator"; password = $value }
            }
        }
    } catch {
        Write-PHStatus "Failed to parse unattend file $FilePath : $_" "warn"
    }
    return $results
}

# ── CACHED HELPERS ────────────────────
function Get-CachedServices {
    if ($null -eq $Script:CachedServices) {
        $Script:CachedServices = @(Get-CimInstance Win32_Service -EA SilentlyContinue)
    }
    return $Script:CachedServices
}

function Get-CachedLocalUsers {
    if ($null -eq $Script:CachedLocalUsers) {
        $Script:CachedLocalUsers = @(Get-LocalUsers)
    }
    return $Script:CachedLocalUsers
}

# ── LOCAL USER ENUMERATION ────────────
function Get-LocalUsers {
    $users = @()
    $adminMembers = @()
    # Get admin group members
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue
        $adminMembers = $adminGroup | ForEach-Object { $_.Name -replace '^[^\\]+\\', '' }
    } catch {
        try {
            $netOut = net localgroup Administrators 2>$null
            $inMembers = $false
            foreach ($line in $netOut) {
                if ($line -match "^-+$") { $inMembers = $true; continue }
                if ($inMembers -and $line -match "^\S" -and $line -notmatch "^The command") {
                    $adminMembers += ($line.Trim() -replace '^[^\\]+\\', '')
                }
            }
        } catch {}
    }
    # Get local users
    try {
        $localUsers = Get-LocalUser -EA SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        foreach ($u in $localUsers) {
            $isAdmin = $adminMembers -contains $u.Name
            $users += @{ Name = $u.Name; SID = $u.SID.Value; IsAdmin = $isAdmin }
        }
    } catch {
        # Fallback to net user
        try {
            $netOut = net user 2>$null
            $nameLines = $netOut | Where-Object { $_ -match "^\S+\s+\S+" -and $_ -notmatch "^User accounts|^-|^The command" }
            foreach ($line in $nameLines) {
                $names = $line.Trim() -split '\s{2,}'
                foreach ($name in $names) {
                    $name = $name.Trim()
                    if ($name) {
                        $isAdmin = $adminMembers -contains $name
                        $users += @{ Name = $name; SID = ""; IsAdmin = $isAdmin }
                    }
                }
            }
        } catch {}
    }
    return $users
}

# ── CREDENTIAL VALIDATION ─────────────
function Test-LocalCredential([string]$Username, [string]$Password) {
    if ($Script:NoCredTest) { return $false }
    # P/Invoke advapi32.dll LogonUser for non-interactive credential validation
    try {
        $logonUserSig = @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(
    string lpszUsername, string lpszDomain, string lpszPassword,
    int dwLogonType, int dwLogonProvider, out IntPtr phToken);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
'@
        if (-not ([System.Management.Automation.PSTypeName]'PrivHound.CredTest').Type) {
            Add-Type -MemberDefinition $logonUserSig -Name "CredTest" -Namespace "PrivHound" -EA Stop
        }
        $token = [IntPtr]::Zero
        # LOGON32_LOGON_NETWORK = 3, LOGON32_PROVIDER_DEFAULT = 0
        $result = [PrivHound.CredTest]::LogonUser($Username, ".", $Password, 3, 0, [ref]$token)
        if ($token -ne [IntPtr]::Zero) {
            [PrivHound.CredTest]::CloseHandle($token) | Out-Null
        }
        return $result
    } catch {
        Write-PHStatus "Credential test error for ${Username}: $_" "warn"
        return $false
    }
}

# ── TOKEN INFO P/INVOKE ───────────────
function Initialize-TokenInfoType {
    if (-not ([System.Management.Automation.PSTypeName]'PrivHound.TokenInfo').Type) {
        Add-Type -EA Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PrivHound {
    public class TokenInfo {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName, IntPtr lpLuid,
            StringBuilder lpName, ref int cchName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(
            string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);
    }
}
'@
    }
}

function Get-TokenWithCredential([string]$Username, [string]$Password) {
    try {
        Initialize-TokenInfoType
        $token = [IntPtr]::Zero
        # LOGON32_LOGON_NETWORK = 3, LOGON32_PROVIDER_DEFAULT = 0
        $result = [PrivHound.TokenInfo]::LogonUser($Username, ".", $Password, 3, 0, [ref]$token)
        if ($result) { return $token }
    } catch {
        Write-PHStatus "Token acquisition error for ${Username}: $_" "warn"
    }
    return [IntPtr]::Zero
}

function Get-TokenGroupSids([IntPtr]$TokenHandle) {
    $groups = [System.Collections.ArrayList]::new()
    [void]$groups.Add("Everyone")
    [void]$groups.Add("Authenticated Users")
    try {
        Initialize-TokenInfoType
        # TokenGroups = 2
        $tokenInfoLen = 0
        [PrivHound.TokenInfo]::GetTokenInformation($TokenHandle, 2, [IntPtr]::Zero, 0, [ref]$tokenInfoLen) | Out-Null
        if ($tokenInfoLen -eq 0) { return $groups.ToArray() }
        $tokenInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal($tokenInfoLen)
        try {
            if (-not [PrivHound.TokenInfo]::GetTokenInformation($TokenHandle, 2, $tokenInfo, $tokenInfoLen, [ref]$tokenInfoLen)) {
                return $groups.ToArray()
            }
            # TOKEN_GROUPS: first 4 bytes = GroupCount, then array of SID_AND_ATTRIBUTES (IntPtr Sid + uint Attributes)
            $groupCount = [Runtime.InteropServices.Marshal]::ReadInt32($tokenInfo)
            $ptrSize = [IntPtr]::Size
            $structSize = $ptrSize + 4  # IntPtr Sid + DWORD Attributes
            for ($i = 0; $i -lt $groupCount; $i++) {
                $offset = 4 + ($i * $structSize)
                # Align offset for pointer size
                if ($ptrSize -eq 8) {
                    $rem = $offset % 8
                    if ($rem -ne 0) { $offset += (8 - $rem) }
                }
                $sidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($tokenInfo, $offset)
                if ($sidPtr -eq [IntPtr]::Zero) { continue }
                $sidStr = $null
                if ([PrivHound.TokenInfo]::ConvertSidToStringSid($sidPtr, [ref]$sidStr)) {
                    [void]$groups.Add($sidStr)
                    # Translate SID to NTAccount name
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                        $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                        [void]$groups.Add($ntAccount)
                    } catch {}
                }
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($tokenInfo)
        }
    } catch {
        Write-PHStatus "Token group extraction error: $_" "warn"
    }
    return $groups.ToArray()
}

function Get-TokenPrivilegeNames([IntPtr]$TokenHandle) {
    $privNames = [System.Collections.ArrayList]::new()
    try {
        Initialize-TokenInfoType
        # TokenPrivileges = 3
        $tokenInfoLen = 0
        [PrivHound.TokenInfo]::GetTokenInformation($TokenHandle, 3, [IntPtr]::Zero, 0, [ref]$tokenInfoLen) | Out-Null
        if ($tokenInfoLen -eq 0) { return $privNames.ToArray() }
        $tokenInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal($tokenInfoLen)
        try {
            if (-not [PrivHound.TokenInfo]::GetTokenInformation($TokenHandle, 3, $tokenInfo, $tokenInfoLen, [ref]$tokenInfoLen)) {
                return $privNames.ToArray()
            }
            # TOKEN_PRIVILEGES: DWORD PrivilegeCount, then array of LUID_AND_ATTRIBUTES (8-byte LUID + 4-byte Attributes)
            $privCount = [Runtime.InteropServices.Marshal]::ReadInt32($tokenInfo)
            for ($i = 0; $i -lt $privCount; $i++) {
                $offset = 4 + ($i * 12)  # LUID(8) + Attributes(4) = 12 bytes each
                $luidPtr = [IntPtr]::Add($tokenInfo, $offset)
                $nameLen = 256
                $nameBuf = New-Object System.Text.StringBuilder $nameLen
                if ([PrivHound.TokenInfo]::LookupPrivilegeName($null, $luidPtr, $nameBuf, [ref]$nameLen)) {
                    [void]$privNames.Add($nameBuf.ToString())
                }
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($tokenInfo)
        }
    } catch {
        Write-PHStatus "Token privilege extraction error: $_" "warn"
    }
    return $privNames.ToArray()
}

# ── CORE NODES ────────────────────────
function Initialize-CoreNodes {
    Write-PHStatus "Creating core nodes..."
    $cu = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Script:CurrentUserId = New-PHId "user" $cu.Name
    Add-PHNode $Script:CurrentUserId @("PHUser") @{ name="$env:USERDOMAIN\$env:USERNAME@$Script:HOSTNAME"; username=$env:USERNAME; domain=$env:USERDOMAIN; sid=$cu.User.Value; hostname=$Script:HOSTNAME; is_admin=([Security.Principal.WindowsPrincipal]$cu).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

    $Script:SystemNodeId = New-PHId "target" "SYSTEM"
    Add-PHNode $Script:SystemNodeId @("PHPrivTarget") @{ name="NT AUTHORITY\SYSTEM@$Script:HOSTNAME"; hostname=$Script:HOSTNAME; account="NT AUTHORITY\SYSTEM" }

    $Script:AdminNodeId = New-PHId "target" "LocalAdmin"
    Add-PHNode $Script:AdminNodeId @("PHPrivTarget") @{ name="LOCAL ADMINISTRATOR@$Script:HOSTNAME"; hostname=$Script:HOSTNAME; account="BUILTIN\Administrators" }

    $os = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption
    $Script:ComputerNodeId = New-PHId "computer" $Script:HOSTNAME
    Add-PHNode $Script:ComputerNodeId @("PHEndpoint") @{ name=$Script:HOSTNAME; hostname=$Script:HOSTNAME; os=$(if($os){$os}else{"Unknown"}); os_version=[Environment]::OSVersion.Version.ToString(); arch=$env:PROCESSOR_ARCHITECTURE }

    Add-PHEdge $Script:ComputerNodeId $Script:SystemNodeId "PHHosts"
    Add-PHEdge $Script:ComputerNodeId $Script:AdminNodeId "PHHosts"
    Add-PHEdge $Script:CurrentUserId $Script:ComputerNodeId "PHHasSessionOn"
}

# ── CHECK 1: SERVICES ─────────────────
function Check-WeakServicePermissions {
    Write-PHStatus "Checking service permissions..."
    $count = 0
    $svcs = Get-CachedServices | Where-Object { $_.PathName }
    $localUsers = $null
    foreach ($svc in $svcs) {
        # Check if current user can modify service config via SDDL
        $canModify = $false
        try {
            $sd = sc.exe sdshow $svc.Name 2>$null
            if ($sd) { $Script:CachedServiceSDDL[$svc.Name] = $sd }
            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if ($sd -match "\(A;;[A-Z]*?(WP|DC|WD|CC)[A-Z]*?;;;(BU|AU|WD|IU)\)" -or
                ($currentSid -and $sd -match "\(A;;[A-Z]*?(WP|DC|WD|CC)[A-Z]*?;;;$([regex]::Escape($currentSid))\)")) {
                $canModify = $true
            }
        } catch {}

        # Extract and check binary path writability
        $bin = $null
        if ($svc.PathName -match '^"([^"]+)"') { $bin = $Matches[1] }
        elseif ($svc.PathName -match '(\S+\.exe)') { $bin = $Matches[1] }
        else { $bin = ($svc.PathName -split '\s+')[0] }
        $bin = $bin.Trim()
        $binWritable = if ($bin -and (Test-Path $bin -EA SilentlyContinue)) { Test-WritableAcl $bin } else { $false }

        if ($canModify -or $binWritable) {
            $nid = New-PHId "service" $svc.Name
            $isSystem = $svc.StartName -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\SYSTEM)$"
            $isLimitedService = $svc.StartName -match "LocalService|NetworkService"
            Add-PHNode $nid @("PHService") @{
                name         = "SVC:$($svc.Name)@$Script:HOSTNAME"
                service_name = $svc.Name
                display_name = $svc.DisplayName
                start_name   = $svc.StartName
                binary_path  = $svc.PathName
                start_mode   = $svc.StartMode
                state        = $svc.State
                hostname     = $Script:HOSTNAME
                can_modify   = $canModify
                bin_writable = $binWritable
            }

            if ($isSystem) {
                Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName}
            } elseif ($isLimitedService) {
                Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName;limited_account=$true}
            } else {
                # Non-SYSTEM service account: resolve to local user
                $svcUserName = $svc.StartName -replace '^[^\\]+\\', '' -replace '@.*$', ''
                if (-not $localUsers) { $localUsers = Get-CachedLocalUsers }
                $matchedUser = $localUsers | Where-Object { $_.Name -eq $svcUserName }
                if ($matchedUser) {
                    $luNodeId = New-PHId "localuser" $matchedUser.Name
                    Add-PHNode $luNodeId @("PHLocalUser") @{
                        name     = "LOCALUSER:$($matchedUser.Name)@$Script:HOSTNAME"
                        username = $matchedUser.Name
                        sid      = $matchedUser.SID
                        is_admin = $matchedUser.IsAdmin
                        hostname = $Script:HOSTNAME
                    }
                    Add-PHEdge $nid $luNodeId "PHRunsAsUser" @{run_account=$svc.StartName}
                    if ($matchedUser.IsAdmin) {
                        Add-PHEdge $luNodeId $Script:AdminNodeId "PHMemberOf" @{group="BUILTIN\Administrators"}
                    }
                } else {
                    # Can't resolve - still create edge to indicate the run-as account
                    Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName}
                }
            }

            if ($canModify) {
                Add-PHEdge $Script:CurrentUserId $nid "PHCanModifyService" @{technique="sc config binpath";mitre="T1574.011"}
                Add-PHFinding "SvcPerms" "HIGH" "Modifiable service '$($svc.Name)' runs as $($svc.StartName)" "sc config"
                $count++
            }
            if ($binWritable) {
                Add-PHEdge $Script:CurrentUserId $nid "PHCanWriteBinary" @{technique="Replace binary";mitre="T1574.010"}
                Add-PHFinding "SvcBin" "HIGH" "Writable binary for '$($svc.Name)': $bin" "copy payload"
                $count++
            }
        }
    }
    Write-PHStatus "Found $count weak service(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 2: UNQUOTED PATHS ───────────
function Check-UnquotedServicePaths {
    Write-PHStatus "Checking unquoted service paths..."
    $count = 0
    $svcs = Get-CachedServices | Where-Object { $_.PathName -and $_.PathName -notlike '"*' -and $_.PathName -match '\s' -and $_.PathName -notlike 'C:\Windows\system32\*' }
    foreach ($svc in $svcs) {
        $parts = $svc.PathName -split '\s+'
        $build = ""; $hijack = ""
        foreach ($p in $parts) {
            if ($build) { $build += " " }
            $build += $p
            if ($build -match "\.exe$") { break }
            $d = Split-Path $build -EA SilentlyContinue
            if ($d -and (Test-WritableAcl $d)) { $hijack = "$build.exe"; break }
        }
        if ($hijack) {
            $nid = New-PHId "unquoted" $svc.Name
            Add-PHNode $nid @("PHUnquotedPath") @{name="UNQUOTED:$($svc.Name)@$Script:HOSTNAME";service_name=$svc.Name;original_path=$svc.PathName;hijack_path=$hijack;start_name=$svc.StartName;hostname=$Script:HOSTNAME}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanHijackPath" @{hijack_path=$hijack;mitre="T1574.009"}
            if ($svc.StartName -match "SYSTEM|LocalSystem") { Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName} }
            Add-PHFinding "Unquoted" "HIGH" "Unquoted '$($svc.Name)': $($svc.PathName)" "Place $hijack"
            $count++
        }
    }
    Write-PHStatus "Found $count unquoted path(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 3: DLL HIJACKING ────────────
function Check-DLLHijacking {
    Write-PHStatus "Checking writable PATH dirs..."
    $count = 0
    foreach ($dir in ($env:PATH -split ";")) {
        if (-not $dir -or $dir -match "^C:\\Windows") { continue }
        if (Test-WritableAcl $dir) {
            $nid = New-PHId "pathdir" $dir
            Add-PHNode $nid @("PHWritablePath") @{name="PATH:$dir@$Script:HOSTNAME";directory=$dir;hostname=$Script:HOSTNAME}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanWriteTo" @{mitre="T1574.001"}
            Add-PHEdge $nid $Script:SystemNodeId "PHDLLHijackTo"
            Add-PHFinding "DLLHijack" "MEDIUM" "Writable PATH: $dir" "Place DLL"; $count++
        }
    }
    Write-PHStatus "Found $count writable PATH dir(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 4: ALWAYSINSTALLELEVATED ────
function Check-AlwaysInstallElevated {
    Write-PHStatus "Checking AlwaysInstallElevated..."
    try {
        $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
    } catch { $hklm = 0; $hkcu = 0 }
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        $nid = New-PHId "regkey" "AIE"
        Add-PHNode $nid @("PHRegistryMisconfig") @{name="ALWAYSINSTALLELEVATED@$Script:HOSTNAME";hostname=$Script:HOSTNAME}
        Add-PHEdge $Script:CurrentUserId $nid "PHCanExploit" @{mitre="T1548.002"}
        Add-PHEdge $nid $Script:SystemNodeId "PHEscalatesTo"
        Add-PHFinding "AIE" "CRITICAL" "AlwaysInstallElevated enabled!" "msiexec /quiet /qn /i evil.msi"
        Write-PHStatus "AlwaysInstallElevated ENABLED!" "finding"
    } else { Write-PHStatus "Not set" "info" }
}

# ── CHECK 5: TOKEN PRIVILEGES ─────────
function Check-TokenPrivileges {
    Write-PHStatus "Checking token privileges..."
    $count = 0; $out=whoami /priv 2>$null
    foreach ($priv in $Script:DangerousPrivileges) {
        $privLine = $out | Where-Object { $_ -match "^\s*$priv\s+" }
        if ($privLine) {
            $enabled = $privLine -match "Enabled"
            $privAbuse=switch($priv){
                "SeImpersonatePrivilege"{@{technique="Token impersonation via named pipe/COM coercion";abuse_info="Coerce a SYSTEM-level authentication to a named pipe or COM object, then impersonate the resulting token. Works on Win 8-11, Server 2012-2022. See MITRE T1134.001."}}
                "SeAssignPrimaryTokenPrivilege"{@{technique="Token impersonation";abuse_info="Same technique as SeImpersonate. Coerce and impersonate a SYSTEM token via named pipe relay. See MITRE T1134.001."}}
                "SeBackupPrivilege"{@{technique="Read protected registry hives";abuse_info="Export SAM and SYSTEM hives with backup privilege, then extract password hashes offline. For DCs: shadow copy ntds.dit. See MITRE T1003.002."}}
                "SeRestorePrivilege"{@{technique="Write any file";abuse_info="Grants write access to any file bypassing ACLs. Replace a service binary or DLL loaded by a SYSTEM process. See MITRE T1574.010."}}
                "SeDebugPrivilege"{@{technique="Process injection / credential dump";abuse_info="Attach to any process including SYSTEM. Inject into a privileged process or dump credentials from memory. See MITRE T1055."}}
                "SeTakeOwnershipPrivilege"{@{technique="Take ownership of protected objects";abuse_info="Take ownership of protected files or service registry keys, grant yourself full access, then modify. See MITRE T1222."}}
                "SeLoadDriverPrivilege"{@{technique="Load vulnerable kernel driver";abuse_info="Load a vulnerable signed kernel driver, then exploit it to gain kernel-level code execution. See MITRE T1068."}}
                "SeCreateTokenPrivilege"{@{technique="Create arbitrary tokens";abuse_info="Create a token with SYSTEM privileges using NtCreateToken API. Rare privilege, usually only held by SYSTEM. See MITRE T1134.001."}}
                "SeTcbPrivilege"{@{technique="Act as part of OS";abuse_info="Full SYSTEM-equivalent. Create tokens for any user without credentials via logon API. See MITRE T1134.001."}}
                "SeManageVolumePrivilege"{@{technique="Arbitrary file write via IOCTL";abuse_info="Gain write access to system files via volume management IOCTL, then DLL hijack a SYSTEM service. See MITRE T1574.001."}}
                default{@{technique="Privilege abuse";abuse_info="Research specific abuse for this privilege. See MITRE T1134.001."}}
            }
            $severity = if($enabled){"HIGH"}else{"MEDIUM"}
            $nid = New-PHId "priv" $priv
            Add-PHNode $nid @("PHTokenPrivilege") @{name="$priv@$Script:HOSTNAME";privilege=$priv;enabled=$enabled;hostname=$Script:HOSTNAME}
            Add-PHEdge $Script:CurrentUserId $nid "PHHasPrivilege" @{mitre="T1134.001"}
            Add-PHEdge $nid $Script:SystemNodeId "PHCanEscalateTo" @{technique=$privAbuse.technique;mitre="T1134.001";abuse_info=$privAbuse.abuse_info}

            # Sub-chain edges for specific privileges
            if ($priv -eq "SeBackupPrivilege") {
                # SeBackup → SAM/SYSTEM hives → hash extraction → Admin
                $samNid = New-PHId "sensfile" "SAM_hive"
                Add-PHNode $samNid @("PHSensitiveFile") @{name="FILE:SAM@$Script:HOSTNAME";file_path="HKLM\SAM";description="SAM registry hive (local account hashes)";hostname=$Script:HOSTNAME}
                $sysHiveNid = New-PHId "sensfile" "SYSTEM_hive"
                Add-PHNode $sysHiveNid @("PHSensitiveFile") @{name="FILE:SYSTEM@$Script:HOSTNAME";file_path="HKLM\SYSTEM";description="SYSTEM registry hive (boot key)";hostname=$Script:HOSTNAME}
                Add-PHEdge $nid $samNid "PHCanReadProtected" @{technique="reg save HKLM\\SAM"}
                Add-PHEdge $nid $sysHiveNid "PHCanReadProtected" @{technique="reg save HKLM\\SYSTEM"}
                Add-PHEdge $samNid $Script:AdminNodeId "PHCanExtractHashes" @{technique="secretsdump / mimikatz lsadump::sam"}
            }
            if ($priv -eq "SeRestorePrivilege") {
                Add-PHEdge $nid $Script:SystemNodeId "PHCanWriteProtected" @{technique="Overwrite protected service binary or DLL"}
            }
            if ($priv -eq "SeDebugPrivilege") {
                Add-PHEdge $nid $Script:SystemNodeId "PHCanInjectInto" @{technique="Inject into SYSTEM process (winlogon, lsass)"}
            }

            $state=if($enabled){"Enabled"}else{"Disabled"}
            Add-PHFinding "Priv" $severity "Has $priv ($state)" $privAbuse.technique; $count++
        }
    }
    Write-PHStatus "Found $count dangerous privilege(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 6: SCHEDULED TASKS ──────────
function Check-ScheduledTasks {
    Write-PHStatus "Checking scheduled tasks..."
    $count = 0
    try { $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.Principal.UserId -match "SYSTEM|LocalSystem|S-1-5-18" -and $_.State -ne "Disabled" } } catch { return }
    foreach ($t in $tasks) {
        foreach ($a in $t.Actions) {
            $exe = ($a.Execute -replace '^"([^"]+)".*','$1').Trim()
            if ($exe -and (Test-Path $exe -EA SilentlyContinue) -and (Test-WritableAcl $exe)) {
                $nid = New-PHId "task" $t.TaskName
                Add-PHNode $nid @("PHScheduledTask") @{name="TASK:$($t.TaskName)@$Script:HOSTNAME";task_name=$t.TaskName;executable=$exe;hostname=$Script:HOSTNAME}
                Add-PHEdge $Script:CurrentUserId $nid "PHCanWriteTaskBinary" @{mitre="T1053.005"}
                Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs"
                Add-PHFinding "Task" "HIGH" "Writable task binary '$($t.TaskName)': $exe" "Replace binary"
                $count++
            }
        }
    }
    Write-PHStatus "Found $count writable task(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 7: AUTORUNS ─────────────────
function Check-AutoRuns {
    Write-PHStatus "Checking autoruns..."
    $count = 0
    $runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    foreach ($rp in $runKeys) {
        try {
            $items = Get-ItemProperty $rp -EA SilentlyContinue
            if (-not $items) { continue }
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                if ($_.Value -match '([A-Za-z]:\\[^\s"]+\.exe)') {
                    $exe = $Matches[1]
                    if ((Test-Path $exe -EA SilentlyContinue) -and (Test-WritableAcl $exe)) {
                        $nid = New-PHId "autorun" "$($_.Name)_$rp"
                        Add-PHNode $nid @("PHAutoRun") @{name="AUTORUN:$($_.Name)@$Script:HOSTNAME";reg_key=$rp;executable=$exe;hostname=$Script:HOSTNAME}
                        Add-PHEdge $Script:CurrentUserId $nid "PHCanWriteAutorun" @{mitre="T1547.001"}
                        if ($rp -match "^HKLM") { Add-PHEdge $nid $Script:AdminNodeId "PHExecutesAs" }
                        Add-PHFinding "Autorun" "MEDIUM" "Writable autorun '$($_.Name)': $exe" "Replace binary"
                        $count++
                    }
                }
            }
        } catch {}
    }
    Write-PHStatus "Found $count writable autorun(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 8: REGISTRY KEYS ────────────
function Check-ServiceRegistryKeys {
    Write-PHStatus "Checking service registry keys..."
    $count = 0
    try { $keys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue } catch { return }
    foreach ($key in $keys) {
        try {
            foreach ($ace in (Get-Acl $key.PSPath -EA SilentlyContinue).Access) {
                if ($ace.IdentityReference.Value -match "Everyone|BUILTIN\\Users|Authenticated Users" -and
                    $ace.AccessControlType -eq "Allow" -and
                    $ace.RegistryRights -match "WriteKey|FullControl|SetValue") {
                    $p = Get-ItemProperty $key.PSPath -EA SilentlyContinue
                    if ($p.Start -le 3 -and $p.ImagePath) {
                        $sn = $key.PSChildName
                        $nid = New-PHId "regservice" $sn
                        Add-PHNode $nid @("PHWritableRegKey") @{name="REGKEY:$sn@$Script:HOSTNAME";service=$sn;image_path=$p.ImagePath;hostname=$Script:HOSTNAME}
                        Add-PHEdge $Script:CurrentUserId $nid "PHCanModifyRegKey" @{mitre="T1574.011"}
                        if (-not $p.ObjectName -or $p.ObjectName -match "SYSTEM|LocalSystem") { Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" }
                        Add-PHFinding "RegKey" "HIGH" "Writable reg for '$sn'" "Modify ImagePath"
                        $count++
                    }
                }
            }
        } catch {}
    }
    Write-PHStatus "Found $count writable reg key(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 9: STORED CREDS ─────────────
function Check-StoredCredentials {
    Write-PHStatus "Checking stored credentials..."
    $count = 0
    $ck = cmdkey /list 2>$null
    $ckEntries = @(); $currentEntry = $null
    foreach ($line in $ck) {
        if ($line -match '^\s*Target:\s*(.+)') {
            if ($currentEntry) { $ckEntries += $currentEntry }
            $currentEntry = @{ Target=$Matches[1].Trim(); Type=$null; User=$null }
        } elseif ($currentEntry -and $line -match '^\s*Type:\s*(.+)') {
            $currentEntry.Type = $Matches[1].Trim()
        } elseif ($currentEntry -and $line -match '^\s*User:\s*(.+)') {
            $currentEntry.User = $Matches[1].Trim()
        }
    }
    if ($currentEntry) { $ckEntries += $currentEntry }

    if ($ckEntries.Count -gt 0) {
        $localUsers = Get-CachedLocalUsers
        foreach ($entry in $ckEntries) {
            $entryLabel = ($entry.Target -replace '[^a-zA-Z0-9_\-]','_')
            $nid = New-PHId "cred" "cmdkey_$entryLabel"
            Add-PHNode $nid @("PHStoredCredential") @{
                name       = "STOREDCREDS:$($entry.Target)@$Script:HOSTNAME"
                source     = "cmdkey"
                target     = $entry.Target
                cred_type  = $entry.Type
                cred_user  = $entry.User
                hostname   = $Script:HOSTNAME
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHHasStoredCreds"
            $count++
            # Try to resolve target user and create PHCanLoginViaRunas edge
            if ($entry.User) {
                $targetUserName = $entry.User -replace '^[^\\]+\\', ''
                $matchedUser = $localUsers | Where-Object { $_.Name -eq $targetUserName }
                if ($matchedUser) {
                    $luNodeId = New-PHId "localuser" $matchedUser.Name
                    Add-PHNode $luNodeId @("PHLocalUser") @{
                        name     = "LOCALUSER:$($matchedUser.Name)@$Script:HOSTNAME"
                        username = $matchedUser.Name
                        sid      = $matchedUser.SID
                        is_admin = $matchedUser.IsAdmin
                        hostname = $Script:HOSTNAME
                    }
                    Add-PHEdge $nid $luNodeId "PHCanLoginViaRunas" @{mitre="T1555.004";technique="runas /savecred"}
                    if ($matchedUser.IsAdmin) {
                        Add-PHEdge $luNodeId $Script:AdminNodeId "PHMemberOf" @{group="BUILTIN\Administrators"}
                    }
                    Add-PHFinding "Creds" "HIGH" "Stored cred for '$($entry.User)' → can runas '$($matchedUser.Name)'" "runas /savecred /user:$($entry.User) cmd.exe"
                } else {
                    Add-PHFinding "Creds" "MEDIUM" "Stored cred for '$($entry.User)' (target: $($entry.Target))" "runas /savecred /user:$($entry.User) cmd.exe"
                }
            } else {
                Add-PHFinding "Creds" "MEDIUM" "Stored credential for target: $($entry.Target)" "cmdkey /list"
            }
        }
    }
    try{$al=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue
        if ($al.DefaultPassword) {
            $nid = New-PHId "cred" "autologon"
            Add-PHNode $nid @("PHStoredCredential") @{
                name     = "AUTOLOGON:$($al.DefaultUserName)@$Script:HOSTNAME"
                source   = "WinlogonAutoLogon"
                username = $al.DefaultUserName
                hostname = $Script:HOSTNAME
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHCanReadCreds"
            Add-PHFinding "AutoLogon" "CRITICAL" "AutoLogon creds for $($al.DefaultDomainName)\$($al.DefaultUserName)" "reg query Winlogon"
            $count++
        }
    }catch{}
    Write-PHStatus "Found $count stored credential(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 10: GPP CACHED PASSWORDS ────
function Check-GPPPasswords {
    Write-PHStatus "Checking for GPP cached passwords..."
    $count = 0
    $gppFiles = @("Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml")
    $searchPaths = @(
        "$env:SystemDrive\ProgramData\Microsoft\Group Policy\History",
        "$env:SystemRoot\SYSVOL"
    )
    foreach ($base in $searchPaths) {
        if (-not (Test-Path $base -EA SilentlyContinue)) { continue }
        foreach ($gf in $gppFiles) {
            try {
                $files = Get-ChildItem -Path $base -Filter $gf -Recurse -EA SilentlyContinue
                foreach ($f in $files) {
                    $content = Get-Content $f.FullName -Raw -EA SilentlyContinue
                    if ($content -match 'cpassword="([^"]+)"') {
                        $nid = New-PHId "gpp" $f.FullName
                        Add-PHNode $nid @("PHGPPPassword") @{name="GPP:$($f.Name)@$Script:HOSTNAME";file_path=$f.FullName;file_name=$f.Name;hostname=$Script:HOSTNAME}
                        Add-PHEdge $Script:CurrentUserId $nid "PHCanDecryptGPP" @{mitre="T1552.006"}
                        Add-PHFinding "GPP" "CRITICAL" "GPP password in $($f.FullName)" "Get-GPPPassword / gpp-decrypt"
                        $count++
                    }
                }
            } catch {}
        }
    }
    Write-PHStatus "Found $count GPP password file(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 11: UNATTENDED INSTALL FILES ─
function Check-UnattendFiles {
    Write-PHStatus "Checking for unattended install files..."
    $count = 0; $seen=@{}
    $paths = @(
        "$env:SystemDrive\unattend.xml",
        "$env:SystemRoot\Panther\unattend.xml",
        "$env:SystemRoot\Panther\Unattend\unattend.xml",
        "$env:SystemRoot\system32\sysprep\unattend.xml",
        "$env:SystemRoot\system32\sysprep\sysprep.xml",
        "$env:SystemRoot\system32\sysprep\Panther\unattend.xml"
    )
    foreach ($p in $paths) {
        if (Test-Path $p -EA SilentlyContinue) {
            # Resolve to actual path and dedup (Windows paths are case-insensitive)
            $resolved = (Resolve-Path $p -EA SilentlyContinue).Path
            if (-not $resolved) { continue }
            $key = $resolved.ToLower()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $content = Get-Content $resolved -Raw -EA SilentlyContinue
            if ($content -match '(?i)<Password>|<AutoLogon>|<AdministratorPassword>') {
                $nid = New-PHId "unattend" $key
                Add-PHNode $nid @("PHUnattendFile") @{name="UNATTEND:$(Split-Path $resolved -Leaf)@$Script:HOSTNAME";file_path=$resolved;hostname=$Script:HOSTNAME}
                Add-PHEdge $Script:CurrentUserId $nid "PHCanReadCreds" @{mitre="T1552.001"}
                Add-PHEdge $nid $Script:AdminNodeId "PHEscalatesTo"
                Add-PHFinding "Unattend" "HIGH" "Unattend file with credentials: $p" "type $p | findstr Password"
                $count++
            }
        }
    }
    Write-PHStatus "Found $count unattend file(s) with credentials" $(if($count){"finding"}else{"info"})
}

# ── CHECK 12: POWERSHELL HISTORY ───────
function Check-PSHistory {
    Write-PHStatus "Checking PowerShell history/transcripts..."
    $count = 0
    $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath -EA SilentlyContinue) {
        $nid = New-PHId "pshist" "ConsoleHost_history"
        Add-PHNode $nid @("PHPSHistory") @{name="PSHIST:ConsoleHost_history@$Script:HOSTNAME";file_path=$histPath;source="PSReadLine";hostname=$Script:HOSTNAME}
        Add-PHEdge $Script:CurrentUserId $nid "PHCanReadHistory" @{mitre="T1552.001"}
        Add-PHFinding "PSHistory" "MEDIUM" "PowerShell history: $histPath" "type $histPath"
        $count++
        # Mine credentials from history
        try {
            $histContent = Get-Content $histPath -Raw -EA SilentlyContinue
            if ($histContent) {
                $credPatterns = @(
                    @{Pattern='ConvertTo-SecureString\s+[''"]([^''"]+)[''"]\s+-AsPlainText';Group=1;Label="SecureString"},
                    @{Pattern='-Password\s+[''"]([^''"]+)[''"]';Group=1;Label="Password param"},
                    @{Pattern='net\s+use\s+.*?/user:(\S+)\s+(\S+)';Group=2;UserGroup=1;Label="net use"},
                    @{Pattern='PSCredential\(\s*[''"]([^''"]+)[''"]\s*,';Group=0;UserGroup=1;Label="PSCredential"}
                )
                $foundCreds = $false
                foreach ($cp in $credPatterns) {
                    $ms = [regex]::Matches($histContent, $cp.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    foreach ($m in $ms) {
                        $pw = $m.Groups[$cp.Group].Value
                        $un = if ($cp.UserGroup) { $m.Groups[$cp.UserGroup].Value } else { $null }
                        if ($pw) {
                            [void]$Script:ExtractedCreds.Add(@{ source="PSHistory"; username=$un; password=$pw; nodeId=$nid })
                            $foundCreds = $true
                        }
                    }
                }
                if ($foundCreds) {
                    Add-PHEdge $nid $nid "PHContainsCreds" @{source="PSHistory"}
                    Add-PHFinding "PSHistory" "HIGH" "Credentials found in PS history" "Review $histPath for passwords"
                }
            }
        } catch {}
    }
    # Check transcript logging settings
    try {
        $transcriptReg = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -EA SilentlyContinue
        if ($transcriptReg -and $transcriptReg.EnableTranscripting -eq 1 -and $transcriptReg.OutputDirectory) {
            $tDir = $transcriptReg.OutputDirectory
            if (Test-Path $tDir -EA SilentlyContinue) {
                $nid = New-PHId "pshist" "Transcripts"
                Add-PHNode $nid @("PHPSHistory") @{name="PSHIST:Transcripts@$Script:HOSTNAME";file_path=$tDir;source="Transcription";hostname=$Script:HOSTNAME}
                Add-PHEdge $Script:CurrentUserId $nid "PHCanReadHistory" @{mitre="T1552.001"}
                Add-PHFinding "PSTranscript" "MEDIUM" "PS transcript dir: $tDir" "dir $tDir"
                $count++
            }
        }
    } catch {}
    Write-PHStatus "Found $count PS history/transcript source(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 13: SENSITIVE FILES ──────────
function Check-SensitiveFiles {
    Write-PHStatus "Checking for sensitive files..."
    $count = 0
    $candidates = @(
        @{Path="$env:USERPROFILE\.git-credentials";Desc="Git credentials"},
        @{Path="$env:SystemRoot\repair\SAM";Desc="SAM backup"},
        @{Path="$env:SystemRoot\repair\SYSTEM";Desc="SYSTEM backup"},
        @{Path="$env:SystemRoot\System32\config\RegBack\SAM";Desc="SAM RegBack"},
        @{Path="$env:SystemRoot\System32\config\RegBack\SYSTEM";Desc="SYSTEM RegBack"}
    )
    foreach ($c in $candidates) {
        if (Test-Path $c.Path -EA SilentlyContinue) {
            $nid = New-PHId "sensfile" $c.Path
            Add-PHNode $nid @("PHSensitiveFile") @{name="FILE:$(Split-Path $c.Path -Leaf)@$Script:HOSTNAME";file_path=$c.Path;description=$c.Desc;hostname=$Script:HOSTNAME}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanAccessFile" @{mitre="T1552.001"}
            Add-PHFinding "SensFile" "MEDIUM" "$($c.Desc): $($c.Path)" "type $($c.Path)"
            $count++
            # Parse .git-credentials for plaintext creds
            if ($c.Path -match '\.git-credentials$') {
                try {
                    $gitLines = Get-Content $c.Path -EA SilentlyContinue
                    foreach ($gl in $gitLines) {
                        if ($gl -match 'https?://([^:]+):([^@]+)@') {
                            [void]$Script:ExtractedCreds.Add(@{ source="GitCredentials"; username=$Matches[1]; password=$Matches[2]; nodeId=$nid })
                            Add-PHEdge $nid $nid "PHContainsCreds" @{source="GitCredentials"}
                        }
                    }
                } catch {}
            }
        }
    }
    # Search for .kdbx and .rdg files in user profile
    foreach ($ext in @("*.kdbx","*.rdg")) {
        try {
            $files = Get-ChildItem -Path $env:USERPROFILE -Filter $ext -Recurse -Depth 3 -EA SilentlyContinue | Select-Object -First 5
            foreach ($f in $files) {
                $nid = New-PHId "sensfile" $f.FullName
                Add-PHNode $nid @("PHSensitiveFile") @{name="FILE:$($f.Name)@$Script:HOSTNAME";file_path=$f.FullName;description="$ext file";hostname=$Script:HOSTNAME}
                Add-PHEdge $Script:CurrentUserId $nid "PHCanAccessFile" @{mitre="T1552.001"}
                Add-PHFinding "SensFile" "MEDIUM" "Sensitive file: $($f.FullName)" "copy $($f.FullName)"
                $count++
                # Parse .rdg files for DPAPI-encrypted credentials
                if ($ext -eq "*.rdg") {
                    try {
                        [xml]$rdgXml = Get-Content $f.FullName -Raw -EA SilentlyContinue
                        $credNodes = $rdgXml.SelectNodes("//logonCredentials") + $rdgXml.SelectNodes("//credentialsProfile")
                        foreach ($cn in $credNodes) {
                            if (-not $cn) { continue }
                            $rdgUser = $cn.userName
                            $rdgPwB64 = $cn.password
                            if ($rdgPwB64) {
                                try {
                                    $rdgPwBytes = [Convert]::FromBase64String($rdgPwB64)
                                    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($rdgPwBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                                    $rdgPw = [System.Text.Encoding]::Unicode.GetString($decrypted)
                                    if ($rdgPw) {
                                        [void]$Script:ExtractedCreds.Add(@{ source="RDGFile"; username=$rdgUser; password=$rdgPw; nodeId=$nid })
                                        Add-PHEdge $nid $nid "PHContainsCreds" @{source="RDGFile"}
                                    }
                                } catch {
                                    Add-PHFinding "SensFile" "LOW" "RDG file '$($f.Name)' has encrypted creds (different user's DPAPI, manual decryption needed)" "Use mimikatz dpapi::rdg"
                                }
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    Write-PHStatus "Found $count sensitive file(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 14: UAC BYPASS ──────────────
function Check-UACBypass {
    Write-PHStatus "Checking UAC bypass opportunities..."
    try {
        $uacReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue
        $enableLUA = $uacReg.EnableLUA
        $consentBehavior = $uacReg.ConsentPromptBehaviorAdmin
        $localFilter = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -EA SilentlyContinue).LocalAccountTokenFilterPolicy
        $cu = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = ([Security.Principal.WindowsPrincipal]$cu).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $inAdminGroup = $false
        try { $inAdminGroup = (net localgroup Administrators 2>$null | ForEach-Object { $_.Trim() }) -contains $env:USERNAME -or (net localgroup Administrators 2>$null | ForEach-Object { $_.Trim() }) -contains "$env:USERDOMAIN\$env:USERNAME" } catch {}

        if ($enableLUA -eq 0) {
            $nid = New-PHId "uac" "LUA_disabled"
            Add-PHNode $nid @("PHUACBypass") @{name="UAC:DISABLED@$Script:HOSTNAME";hostname=$Script:HOSTNAME;enableLUA=0;consentBehavior=$consentBehavior}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanBypassUAC" @{mitre="T1548.002"}
            Add-PHEdge $nid $Script:AdminNodeId "PHEscalatesTo"
            Add-PHFinding "UAC" "HIGH" "UAC is DISABLED (EnableLUA=0)" "All processes run elevated"
            Write-PHStatus "UAC disabled!" "finding"
        } elseif ($consentBehavior -eq 0 -and $inAdminGroup) {
            $nid = New-PHId "uac" "NoPrompt"
            Add-PHNode $nid @("PHUACBypass") @{name="UAC:NOPROMPT@$Script:HOSTNAME";hostname=$Script:HOSTNAME;enableLUA=$enableLUA;consentBehavior=0}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanBypassUAC" @{mitre="T1548.002"}
            Add-PHEdge $nid $Script:AdminNodeId "PHEscalatesTo"
            Add-PHFinding "UAC" "HIGH" "UAC set to never prompt (ConsentBehaviorAdmin=0)" "Start-Process -Verb RunAs"
            Write-PHStatus "UAC never prompts!" "finding"
        } elseif ($inAdminGroup -and -not $isElevated) {
            $nid = New-PHId "uac" "AdminNotElevated"
            Add-PHNode $nid @("PHUACBypass") @{name="UAC:ADMIN_NOT_ELEVATED@$Script:HOSTNAME";hostname=$Script:HOSTNAME;enableLUA=$enableLUA;consentBehavior=$consentBehavior}
            Add-PHEdge $Script:CurrentUserId $nid "PHCanBypassUAC" @{mitre="T1548.002";technique="fodhelper/eventvwr bypass"}
            Add-PHEdge $nid $Script:AdminNodeId "PHEscalatesTo"
            Add-PHFinding "UAC" "HIGH" "User in Administrators group but not elevated" "fodhelper.exe / eventvwr.exe UAC bypass"
            Write-PHStatus "Admin user not elevated - UAC bypass possible" "finding"
        } else {
            Write-PHStatus "UAC configured (EnableLUA=$enableLUA, Consent=$consentBehavior)" "info"
        }

        if ($localFilter -eq 1) {
            Add-PHFinding "UAC" "MEDIUM" "LocalAccountTokenFilterPolicy=1 (remote admin via local accounts)" "Pass-the-hash with local admin"
            Write-PHStatus "LocalAccountTokenFilterPolicy=1" "finding"
        }
    } catch { Write-PHStatus "Error checking UAC: $_" "error" }
}

# ── CHECK 15: WRITABLE PROGRAM DIRS ───
function Check-WritableProgramDirs {
    Write-PHStatus "Checking writable Program Files directories..."
    $count = 0
    # Cache services and scheduled tasks for cross-referencing
    $allServices = Get-CachedServices
    $allTasks = @()
    try { $allTasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.State -ne "Disabled" } } catch {}

    foreach ($root in @("$env:ProgramFiles","${env:ProgramFiles(x86)}")) {
        if (-not (Test-Path $root -EA SilentlyContinue)) { continue }
        try {
            $dirs = Get-ChildItem -Path $root -Directory -EA SilentlyContinue
            foreach ($d in $dirs) {
                if (Test-WritableAcl $d.FullName) {
                    $nid = New-PHId "progdir" $d.FullName
                    Add-PHNode $nid @("PHWritableProgramDir") @{name="PROGDIR:$($d.Name)@$Script:HOSTNAME";directory=$d.FullName;hostname=$Script:HOSTNAME}
                    Add-PHEdge $Script:CurrentUserId $nid "PHCanWriteProgDir" @{mitre="T1574.010"}
                    Add-PHFinding "ProgDir" "HIGH" "Writable program dir: $($d.FullName)" "Place malicious DLL/EXE"
                    $count++

                    # Cross-reference: services with binaries in this directory
                    $dirPattern = [regex]::Escape($d.FullName)
                    foreach ($svc in $allServices) {
                        if ($svc.PathName -and $svc.PathName -match $dirPattern) {
                            $svcNid = New-PHId "service" $svc.Name
                            Add-PHNode $svcNid @("PHService") @{name="SVC:$($svc.Name)@$Script:HOSTNAME";service_name=$svc.Name;display_name=$svc.DisplayName;start_name=$svc.StartName;binary_path=$svc.PathName;start_mode=$svc.StartMode;state=$svc.State;hostname=$Script:HOSTNAME}
                            Add-PHEdge $nid $svcNid "PHHostsBinaryFor" @{binary_path=$svc.PathName}
                            if ($svc.StartName -match "SYSTEM|LocalSystem") {
                                Add-PHEdge $svcNid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName}
                            }
                            Add-PHFinding "ProgDir" "HIGH" "Writable dir hosts service '$($svc.Name)' binary" "Replace binary in $($d.FullName)"
                        }
                    }
                    # Cross-reference: scheduled tasks with binaries in this directory
                    foreach ($task in $allTasks) {
                        foreach ($a in $task.Actions) {
                            $taskExe = ($a.Execute -replace '^"([^"]+)".*','$1').Trim()
                            if ($taskExe -and $taskExe -match $dirPattern) {
                                $taskNid = New-PHId "task" $task.TaskName
                                Add-PHNode $taskNid @("PHScheduledTask") @{name="TASK:$($task.TaskName)@$Script:HOSTNAME";task_name=$task.TaskName;executable=$taskExe;hostname=$Script:HOSTNAME}
                                Add-PHEdge $nid $taskNid "PHHostsBinaryFor" @{binary_path=$taskExe}
                                if ($task.Principal.UserId -match "SYSTEM|LocalSystem") {
                                    Add-PHEdge $taskNid $Script:SystemNodeId "PHRunsAs"
                                }
                                Add-PHFinding "ProgDir" "HIGH" "Writable dir hosts task '$($task.TaskName)' binary" "Replace binary in $($d.FullName)"
                            }
                        }
                    }
                }
            }
        } catch {}
    }
    Write-PHStatus "Found $count writable program dir(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 16: CROSS-USER PROFILES ────
function Check-CrossUserProfiles {
    Write-PHStatus "Checking cross-user profile access..."
    $count = 0
    $usersDir = "$env:SystemDrive\Users"
    if (-not (Test-Path $usersDir)) { return }
    $currentUser = $env:USERNAME
    $excludeDirs = @("Public","Default","Default User","All Users",$currentUser)

    try {
        $profiles = Get-ChildItem -Path $usersDir -Directory -EA SilentlyContinue | Where-Object { $_.Name -notin $excludeDirs }
    } catch { return }

    $sensitivePatterns = @(
        @{Filter=".git-credentials";Desc="Git credentials"},
        @{Filter="*.kdbx";Desc="KeePass database"},
        @{Filter="*.rdg";Desc="RDCMan file"}
    )
    $knownDeepFiles = @(
        @{RelPath="AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";Desc="PS history"}
    )

    foreach ($profile in $profiles) {
        # Test read access
        $canRead = $false
        try {
            $null = Get-ChildItem -Path $profile.FullName -EA Stop | Select-Object -First 1
            $canRead = $true
        } catch {}
        if (-not $canRead) { continue }

        # Create PHUserProfile node
        $profileNid = New-PHId "userprofile" $profile.Name
        Add-PHNode $profileNid @("PHUserProfile") @{
            name     = "PROFILE:$($profile.Name)@$Script:HOSTNAME"
            username = $profile.Name
            profile_path = $profile.FullName
            hostname = $Script:HOSTNAME
        }
        Add-PHEdge $Script:CurrentUserId $profileNid "PHCanAccessProfile"
        Add-PHFinding "CrossProfile" "MEDIUM" "Can access profile: $($profile.FullName)" "dir $($profile.FullName)"
        $count++

        $allFound = [System.Collections.ArrayList]::new()
        foreach ($sp in $sensitivePatterns) {
            try {
                $hits = Get-ChildItem -Path $profile.FullName -Filter $sp.Filter -Recurse -Depth 4 -EA SilentlyContinue | Select-Object -First 3
                foreach ($h in $hits) { [void]$allFound.Add(@{File=$h;Desc=$sp.Desc}) }
            } catch {}
        }
        foreach ($kf in $knownDeepFiles) {
            $knownPath = Join-Path $profile.FullName $kf.RelPath
            if (Test-Path $knownPath -EA SilentlyContinue) {
                try { [void]$allFound.Add(@{File=(Get-Item $knownPath -EA Stop);Desc=$kf.Desc}) } catch {}
            }
        }

        foreach ($entry in $allFound) {
            $sf = $entry.File; $spDesc = $entry.Desc
            try {
                $sfNid = New-PHId "sensfile" $sf.FullName
                Add-PHNode $sfNid @("PHSensitiveFile") @{
                    name        = "FILE:$($sf.Name)@$Script:HOSTNAME"
                    file_path   = $sf.FullName
                    description = "$spDesc (in $($profile.Name)'s profile)"
                    hostname    = $Script:HOSTNAME
                }
                Add-PHEdge $profileNid $sfNid "PHProfileContains"
                Add-PHEdge $Script:CurrentUserId $sfNid "PHCanAccessFile" @{mitre="T1552.001"}
                Add-PHFinding "CrossProfile" "HIGH" "$spDesc in $($profile.Name)'s profile: $($sf.FullName)" "type $($sf.FullName)"

                # Parse credential files and push to shared accumulator
                if ($sf.Name -eq ".git-credentials") {
                    try {
                        $gitLines = Get-Content $sf.FullName -EA SilentlyContinue
                        foreach ($gl in $gitLines) {
                            if ($gl -match 'https?://([^:]+):([^@]+)@') {
                                [void]$Script:ExtractedCreds.Add(@{ source="CrossProfile-Git"; username=$Matches[1]; password=$Matches[2]; nodeId=$sfNid })
                                Add-PHEdge $sfNid $sfNid "PHContainsCreds" @{source="GitCredentials"}
                            }
                        }
                    } catch {}
                }
                if ($sf.Name -eq "ConsoleHost_history.txt") {
                    try {
                        $histContent = Get-Content $sf.FullName -Raw -EA SilentlyContinue
                        if ($histContent) {
                            $credPatterns = @(
                                @{Pattern='ConvertTo-SecureString\s+[''"]([^''"]+)[''"]\s+-AsPlainText';Group=1},
                                @{Pattern='-Password\s+[''"]([^''"]+)[''"]';Group=1},
                                @{Pattern='net\s+use\s+.*?/user:(\S+)\s+(\S+)';Group=2;UserGroup=1}
                            )
                            foreach ($cp in $credPatterns) {
                                $ms = [regex]::Matches($histContent, $cp.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                                foreach ($m in $ms) {
                                    $pw = $m.Groups[$cp.Group].Value
                                    $un = if ($cp.UserGroup) { $m.Groups[$cp.UserGroup].Value } else { $null }
                                    if ($pw) {
                                        [void]$Script:ExtractedCreds.Add(@{ source="CrossProfile-PSHistory"; username=$un; password=$pw; nodeId=$sfNid })
                                        Add-PHEdge $sfNid $sfNid "PHContainsCreds" @{source="PSHistory"}
                                    }
                                }
                            }
                        }
                    } catch {}
                }
                if ($sf.Name -match '\.rdg$') {
                    try {
                        [xml]$rdgXml = Get-Content $sf.FullName -Raw -EA SilentlyContinue
                        $credNodes = $rdgXml.SelectNodes("//logonCredentials") + $rdgXml.SelectNodes("//credentialsProfile")
                        foreach ($cn in $credNodes) {
                            if (-not $cn) { continue }
                            $rdgPwB64 = $cn.password
                            if ($rdgPwB64) {
                                try {
                                    $rdgPwBytes = [Convert]::FromBase64String($rdgPwB64)
                                    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($rdgPwBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                                    $rdgPw = [System.Text.Encoding]::Unicode.GetString($decrypted)
                                    if ($rdgPw) {
                                        [void]$Script:ExtractedCreds.Add(@{ source="CrossProfile-RDG"; username=$cn.userName; password=$rdgPw; nodeId=$sfNid })
                                        Add-PHEdge $sfNid $sfNid "PHContainsCreds" @{source="RDGFile"}
                                    }
                                } catch {}
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    }
    Write-PHStatus "Found $count accessible cross-user profile(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 17: CREDENTIAL LOGIN PATHS ──
function Check-CredentialLoginPaths {
    Write-PHStatus "Checking credential login paths..."
    $count = 0

    # Phase 1: Collect credentials from AutoLogon, GPP, Unattend into shared accumulator
    try {
        $al = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue
        if ($al.DefaultPassword) {
            [void]$Script:ExtractedCreds.Add(@{
                source   = "AutoLogon"
                username = $al.DefaultUserName
                password = $al.DefaultPassword
                nodeId   = New-PHId "cred" "autologon"
            })
        }
    } catch {}

    # GPP XML credential collection
    $gppFiles = @("Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml")
    $gppSearchPaths = @("$env:SystemDrive\ProgramData\Microsoft\Group Policy\History","$env:SystemRoot\SYSVOL")
    foreach ($base in $gppSearchPaths) {
        if (-not (Test-Path $base -EA SilentlyContinue)) { continue }
        foreach ($gf in $gppFiles) {
            try {
                $files = Get-ChildItem -Path $base -Filter $gf -Recurse -EA SilentlyContinue
                foreach ($f in $files) {
                    $content = Get-Content $f.FullName -Raw -EA SilentlyContinue
                    $matches_ = [regex]::Matches($content, 'cpassword="([^"]+)"')
                    $userMatches = [regex]::Matches($content, 'userName="([^"]*)"')
                    for ($i = 0; $i -lt $matches_.Count; $i++) {
                        $cpass = $matches_[$i].Groups[1].Value
                        $gppUser = if ($i -lt $userMatches.Count) { $userMatches[$i].Groups[1].Value } else { $null }
                        $decrypted = Decrypt-GPPPassword $cpass
                        if ($decrypted) {
                            [void]$Script:ExtractedCreds.Add(@{
                                source   = "GPP"
                                username = $gppUser
                                password = $decrypted
                                nodeId   = New-PHId "gpp" $f.FullName
                            })
                        }
                    }
                }
            } catch {}
        }
    }

    # Unattend.xml credential collection
    $unattendPaths = @(
        "$env:SystemDrive\unattend.xml",
        "$env:SystemRoot\Panther\unattend.xml",
        "$env:SystemRoot\Panther\Unattend\unattend.xml",
        "$env:SystemRoot\system32\sysprep\unattend.xml",
        "$env:SystemRoot\system32\sysprep\sysprep.xml",
        "$env:SystemRoot\system32\sysprep\Panther\unattend.xml"
    )
    $seenUnattend = @{}
    foreach ($p in $unattendPaths) {
        if (-not (Test-Path $p -EA SilentlyContinue)) { continue }
        $resolved = (Resolve-Path $p -EA SilentlyContinue).Path
        if (-not $resolved) { continue }
        $key = $resolved.ToLower()
        if ($seenUnattend.ContainsKey($key)) { continue }
        $seenUnattend[$key] = $true
        $passwords = Get-UnattendPasswords $resolved
        foreach ($pw in $passwords) {
            if ($pw.password) {
                [void]$Script:ExtractedCreds.Add(@{
                    source   = "Unattend"
                    username = $pw.username
                    password = $pw.password
                    nodeId   = New-PHId "unattend" $key
                })
            }
        }
    }

    # Phase 2: Validate all accumulated credentials against local users
    if ($Script:ExtractedCreds.Count -eq 0) {
        Write-PHStatus "No extracted credentials to test" "info"
        return
    }

    if ($Script:NoCredTest) {
        Write-PHStatus "Collected $($Script:ExtractedCreds.Count) credential(s), skipping validation (NoCredTest)" "warn"
        return
    }

    Write-PHStatus "Collected $($Script:ExtractedCreds.Count) credential(s), enumerating local users..."

    $localUsers = Get-CachedLocalUsers
    if ($localUsers.Count -eq 0) {
        Write-PHStatus "Could not enumerate local users" "warn"
        return
    }
    Write-PHStatus "Found $($localUsers.Count) enabled local user(s)"

    $testedPairs = @{}
    foreach ($cred in $Script:ExtractedCreds) {
        foreach ($lu in $localUsers) {
            $pairKey = "$($lu.Name)|$($cred.password)"
            if ($testedPairs.ContainsKey($pairKey)) { continue }
            $testedPairs[$pairKey] = $true

            $valid = Test-LocalCredential $lu.Name $cred.password
            if ($valid) {
                Write-PHStatus "Valid credential: $($cred.source) password works for $($lu.Name)!" "finding"

                $luNodeId = New-PHId "localuser" $lu.Name
                Add-PHNode $luNodeId @("PHLocalUser") @{
                    name     = "LOCALUSER:$($lu.Name)@$Script:HOSTNAME"
                    username = $lu.Name
                    sid      = $lu.SID
                    is_admin = $lu.IsAdmin
                    hostname = $Script:HOSTNAME
                }

                Add-PHEdge $cred.nodeId $luNodeId "PHCanLoginAs" @{
                    source_type = $cred.source
                    mitre       = "T1078.003"
                    tested      = $true
                    password_reuse = ($lu.Name -ne $cred.username)
                }

                if ($lu.IsAdmin) {
                    Add-PHEdge $luNodeId $Script:AdminNodeId "PHMemberOf" @{
                        group = "BUILTIN\Administrators"
                    }
                }

                # Store validated credential for cross-user privilege analysis
                [void]$Script:ValidatedCreds.Add(@{
                    username = $lu.Name
                    password = $cred.password
                    nodeId   = $luNodeId
                    isAdmin  = $lu.IsAdmin
                    sid      = $lu.SID
                })

                $reuseNote = if ($lu.Name -ne $cred.username) { " (password reuse!)" } else { "" }
                Add-PHFinding "CredLogin" "CRITICAL" "$($cred.source) credential valid for local user '$($lu.Name)'$reuseNote" "runas /user:$($lu.Name) cmd.exe"
                $count++
            }
        }
    }

    Write-PHStatus "Found $count credential login path(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 18: CROSS-USER PRIVILEGE ESCALATION ────
function Check-CrossUserPrivileges {
    Write-PHStatus "Checking cross-user privilege escalation paths..."

    if ($Script:NoCredTest) {
        Write-PHStatus "Skipping cross-user checks (NoCredTest)" "warn"
        return
    }

    if ($Script:ValidatedCreds.Count -eq 0) {
        Write-PHStatus "No validated credentials for cross-user analysis" "info"
        return
    }

    # Deduplicate by username, skip current user
    $currentUser = $env:USERNAME.ToLower()
    $seen = @{}
    $usersToCheck = @()
    foreach ($vc in $Script:ValidatedCreds) {
        $uLower = $vc.username.ToLower()
        if ($uLower -eq $currentUser) { continue }
        if ($seen.ContainsKey($uLower)) { continue }
        $seen[$uLower] = $true
        $usersToCheck += $vc
    }

    if ($usersToCheck.Count -eq 0) {
        Write-PHStatus "No cross-user credentials to analyze (all match current user)" "info"
        return
    }

    Write-PHStatus "Analyzing privileges for $($usersToCheck.Count) discovered user(s)..."
    $count = 0
    $svcs = Get-CachedServices | Where-Object { $_.PathName }

    foreach ($vc in $usersToCheck) {
        $token = Get-TokenWithCredential $vc.username $vc.password
        if ($token -eq [IntPtr]::Zero) {
            Write-PHStatus "Could not obtain token for $($vc.username), skipping" "warn"
            continue
        }

        try {
            $userGroups = Get-TokenGroupSids $token
            $userPrivs = Get-TokenPrivilegeNames $token
            $luNodeId = $vc.nodeId
            $userSid = $vc.sid

            # Also add the user's own SID and username to the groups list for ACL matching
            $allGroups = @($userGroups)
            if ($vc.username) { $allGroups += $vc.username }
            if ($userSid) { $allGroups += $userSid }

            # ── Sub-check A: Service binary write ──
            foreach ($svc in $svcs) {
                $bin = $null
                if ($svc.PathName -match '^"([^"]+)"') { $bin = $Matches[1] }
                elseif ($svc.PathName -match '(\S+\.exe)') { $bin = $Matches[1] }
                else { $bin = ($svc.PathName -split '\s+')[0] }
                $bin = if ($bin) { $bin.Trim() } else { $null }

                if ($bin -and (Test-Path $bin -EA SilentlyContinue) -and (Test-WritableAcl $bin $allGroups)) {
                    $svcNodeId = New-PHId "service" $svc.Name
                    $isSystem = $svc.StartName -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\SYSTEM)$"
                    Add-PHNode $svcNodeId @("PHService") @{
                        name=$("SVC:$($svc.Name)@$Script:HOSTNAME"); service_name=$svc.Name
                        display_name=$svc.DisplayName; start_name=$svc.StartName
                        binary_path=$svc.PathName; hostname=$Script:HOSTNAME
                    }
                    if ($isSystem) { Add-PHEdge $svcNodeId $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName} }
                    Add-PHEdge $luNodeId $svcNodeId "PHCanWriteBinary" @{
                        technique="Replace binary"; mitre="T1574.010"; discovered_via="credential"
                    }
                    $count++
                }
            }

            # ── Sub-check B: Service SDDL modify ──
            foreach ($svc in $svcs) {
                $sd = $Script:CachedServiceSDDL[$svc.Name]
                if (-not $sd) { continue }
                $canMod = $false
                # Check well-known group SIDs
                if ($sd -match "\(A;;[A-Z]*?(WP|DC|WD|CC)[A-Z]*?;;;(BU|AU|WD|IU)\)") { $canMod = $true }
                # Check user-specific SID
                if (-not $canMod -and $userSid -and $sd -match "\(A;;[A-Z]*?(WP|DC|WD|CC)[A-Z]*?;;;$([regex]::Escape($userSid))\)") { $canMod = $true }
                # Check group SIDs from token
                if (-not $canMod) {
                    foreach ($g in $userGroups) {
                        if ($g -match '^S-1-') {
                            if ($sd -match "\(A;;[A-Z]*?(WP|DC|WD|CC)[A-Z]*?;;;$([regex]::Escape($g))\)") { $canMod = $true; break }
                        }
                    }
                }
                if ($canMod) {
                    $svcNodeId = New-PHId "service" $svc.Name
                    $isSystem = $svc.StartName -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\SYSTEM)$"
                    Add-PHNode $svcNodeId @("PHService") @{
                        name=$("SVC:$($svc.Name)@$Script:HOSTNAME"); service_name=$svc.Name
                        display_name=$svc.DisplayName; start_name=$svc.StartName
                        binary_path=$svc.PathName; hostname=$Script:HOSTNAME
                    }
                    if ($isSystem) { Add-PHEdge $svcNodeId $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName} }
                    Add-PHEdge $luNodeId $svcNodeId "PHCanModifyService" @{
                        technique="sc config binpath"; mitre="T1574.011"; discovered_via="credential"
                    }
                    $count++
                }
            }

            # ── Sub-check C: Unquoted path hijack ──
            $uqSvcs = $svcs | Where-Object { $_.PathName -and $_.PathName -notlike '"*' -and $_.PathName -match '\s' -and $_.PathName -notlike 'C:\Windows\system32\*' }
            foreach ($svc in $uqSvcs) {
                $parts = $svc.PathName -split '\s+'
                $build = ""; $hijack = ""
                foreach ($p in $parts) {
                    if ($build) { $build += " " }; $build += $p
                    if ($build -match "\.exe$") { break }
                    $d = Split-Path $build -EA SilentlyContinue
                    if ($d -and (Test-WritableAcl $d $allGroups)) { $hijack = "$build.exe"; break }
                }
                if ($hijack) {
                    $nid = New-PHId "unquoted" $svc.Name
                    Add-PHNode $nid @("PHUnquotedPath") @{
                        name="UNQUOTED:$($svc.Name)@$Script:HOSTNAME"; service_name=$svc.Name
                        original_path=$svc.PathName; hijack_path=$hijack
                        start_name=$svc.StartName; hostname=$Script:HOSTNAME
                    }
                    if ($svc.StartName -match "SYSTEM|LocalSystem") {
                        Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName}
                    }
                    Add-PHEdge $luNodeId $nid "PHCanHijackPath" @{
                        hijack_path=$hijack; mitre="T1574.009"; discovered_via="credential"
                    }
                    $count++
                }
            }

            # ── Sub-check D: DLL hijack PATH dirs ──
            foreach ($dir in ($env:PATH -split ";")) {
                if (-not $dir -or $dir -match "^C:\\Windows") { continue }
                if (Test-WritableAcl $dir $allGroups) {
                    $nid = New-PHId "pathdir" $dir
                    Add-PHNode $nid @("PHWritablePath") @{
                        name="PATH:$dir@$Script:HOSTNAME"; directory=$dir; hostname=$Script:HOSTNAME
                    }
                    Add-PHEdge $nid $Script:SystemNodeId "PHDLLHijackTo"
                    Add-PHEdge $luNodeId $nid "PHCanWriteTo" @{
                        mitre="T1574.001"; discovered_via="credential"
                    }
                    $count++
                }
            }

            # ── Sub-check E: Scheduled task binary ──
            try {
                $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {
                    $_.Principal.UserId -match "SYSTEM|LocalSystem" -and $_.State -ne "Disabled"
                }
                foreach ($task in $tasks) {
                    foreach ($action in $task.Actions) {
                        if ($action.Execute -and (Test-Path $action.Execute -EA SilentlyContinue) -and (Test-WritableAcl $action.Execute $allGroups)) {
                            $taskNodeId = New-PHId "task" $task.TaskName
                            Add-PHNode $taskNodeId @("PHScheduledTask") @{
                                name="TASK:$($task.TaskName)@$Script:HOSTNAME"
                                task_name=$task.TaskName; binary=$action.Execute
                                run_as=$task.Principal.UserId; hostname=$Script:HOSTNAME
                            }
                            Add-PHEdge $taskNodeId $Script:SystemNodeId "PHRunsAs" @{run_account=$task.Principal.UserId}
                            Add-PHEdge $luNodeId $taskNodeId "PHCanWriteTaskBinary" @{
                                binary=$action.Execute; mitre="T1053.005"; discovered_via="credential"
                            }
                            $count++
                        }
                    }
                }
            } catch {}

            # ── Sub-check F: Autorun binary ──
            try {
                $runKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
                foreach ($rk in $runKeys) {
                    if (-not (Test-Path $rk -EA SilentlyContinue)) { continue }
                    $props = Get-ItemProperty $rk -EA SilentlyContinue
                    if (-not $props) { continue }
                    foreach ($name in ($props.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSProvider","PSDrive") })) {
                        $arBin = $name.Value
                        if ($arBin -match '^"([^"]+)"') { $arBin = $Matches[1] }
                        elseif ($arBin -match '(\S+\.exe)') { $arBin = $Matches[1] }
                        if ($arBin -and (Test-Path $arBin -EA SilentlyContinue) -and (Test-WritableAcl $arBin $allGroups)) {
                            $arNodeId = New-PHId "autorun" "$rk\$($name.Name)"
                            Add-PHNode $arNodeId @("PHAutoRun") @{
                                name="AUTORUN:$($name.Name)@$Script:HOSTNAME"
                                key=$rk; entry_name=$name.Name; binary=$arBin
                                hostname=$Script:HOSTNAME
                            }
                            Add-PHEdge $luNodeId $arNodeId "PHCanWriteAutorun" @{
                                binary=$arBin; mitre="T1547.001"; discovered_via="credential"
                            }
                            $count++
                        }
                    }
                }
            } catch {}

            # ── Sub-check G: Writable Program Files dirs ──
            try {
                $progDirs = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}")
                foreach ($pd in $progDirs) {
                    if (-not (Test-Path $pd -EA SilentlyContinue)) { continue }
                    foreach ($sub in (Get-ChildItem $pd -Directory -EA SilentlyContinue)) {
                        if (Test-WritableAcl $sub.FullName $allGroups) {
                            $pdNodeId = New-PHId "progdir" $sub.FullName
                            Add-PHNode $pdNodeId @("PHWritableProgramDir") @{
                                name="PROGDIR:$($sub.Name)@$Script:HOSTNAME"
                                directory=$sub.FullName; hostname=$Script:HOSTNAME
                            }
                            Add-PHEdge $luNodeId $pdNodeId "PHCanWriteProgDir" @{
                                mitre="T1574.010"; discovered_via="credential"
                            }
                            $count++
                        }
                    }
                }
            } catch {}

            # ── Sub-check H: Token privileges ──
            foreach ($priv in $userPrivs) {
                if ($priv -in $Script:DangerousPrivileges) {
                    $privNodeId = New-PHId "privilege" "$($vc.username)_$priv"
                    Add-PHNode $privNodeId @("PHTokenPrivilege") @{
                        name="PRIV:$priv@$($vc.username)@$Script:HOSTNAME"
                        privilege=$priv; username=$vc.username; hostname=$Script:HOSTNAME
                    }
                    Add-PHEdge $luNodeId $privNodeId "PHHasPrivilege" @{
                        privilege=$priv; discovered_via="credential"
                    }
                    Add-PHEdge $privNodeId $Script:SystemNodeId "PHCanEscalateTo" @{
                        privilege=$priv; discovered_via="credential"
                    }
                    $count++
                }
            }

            # ── Sub-check I: Service recovery command binary ──
            foreach ($svcName in $Script:CachedServiceRecovery.Keys) {
                $recoveryBin = $Script:CachedServiceRecovery[$svcName]
                if ($recoveryBin -and (Test-Path $recoveryBin -EA SilentlyContinue) -and (Test-WritableAcl $recoveryBin $allGroups)) {
                    $svcObj = $svcs | Where-Object { $_.Name -eq $svcName } | Select-Object -First 1
                    if (-not $svcObj) { continue }
                    $svcNodeId = New-PHId "service" $svcName
                    $isSystem = $svcObj.StartName -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\SYSTEM)$"
                    Add-PHNode $svcNodeId @("PHService") @{
                        name="SVC:$svcName@$Script:HOSTNAME"; service_name=$svcName
                        display_name=$svcObj.DisplayName; start_name=$svcObj.StartName
                        binary_path=$svcObj.PathName; recovery_binary=$recoveryBin
                        hostname=$Script:HOSTNAME
                    }
                    if ($isSystem) { Add-PHEdge $svcNodeId $Script:SystemNodeId "PHRunsAs" @{run_account=$svcObj.StartName} }
                    Add-PHEdge $luNodeId $svcNodeId "PHCanWriteRecoveryBin" @{
                        recovery_binary=$recoveryBin; mitre="T1574.010"; discovered_via="credential"
                    }
                    $count++
                }
            }

        } finally {
            if ($token -ne [IntPtr]::Zero) {
                try { [PrivHound.TokenInfo]::CloseHandle($token) | Out-Null } catch {}
            }
        }
    }

    Write-PHStatus "Found $count cross-user privilege escalation path(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 19: JIT ADMIN DETECTION ────
function Check-JITAdminTools {
    Write-PHStatus "Checking for JIT admin tools (MakeMeAdmin, CyberArk EPM, BeyondTrust, Delinea)..."
    $count = 0
    $jitTools = @(
        @{Name="MakeMeAdmin"; Service="MakeMeAdminService"; RegPath="HKLM:\SOFTWARE\Sinclair Community College\Make Me Admin"; BinPaths=@("$env:ProgramFiles\Make Me Admin\MakeMeAdminService.exe","${env:ProgramFiles(x86)}\Make Me Admin\MakeMeAdminService.exe")},
        @{Name="CyberArkEPM"; Service="VfBackgroundService"; RegPath="HKLM:\SOFTWARE\CyberArk\Endpoint Privilege Manager\Agent"; BinPaths=@()},
        @{Name="BeyondTrust"; Service="BeyondTrustPrivilegeManagement"; RegPath="HKLM:\SOFTWARE\Avecto\Privilege Guard Client"; BinPaths=@()},
        @{Name="DelineaAgent"; Service="ThycoticAgent"; RegPath="HKLM:\SOFTWARE\Thycotic\Agent"; BinPaths=@()}
    )
    foreach ($tool in $jitTools) {
        $found = $false; $details = @{}
        # Check service existence
        try { $svc = Get-Service -Name $tool.Service -EA SilentlyContinue; if ($svc) { $found = $true; $details["service_state"] = $svc.Status.ToString() } } catch {}
        # Check registry
        if (-not $found -and $tool.RegPath) {
            try { if (Test-Path $tool.RegPath -EA SilentlyContinue) { $found = $true; $details["reg_path"] = $tool.RegPath } } catch {}
        }
        # Check binary paths
        if (-not $found) {
            foreach ($bp in $tool.BinPaths) { if (Test-Path $bp -EA SilentlyContinue) { $found = $true; $details["binary"] = $bp; break } }
        }
        if ($found) {
            $nid = New-PHId "jitadmin" $tool.Name
            $props = @{ name="JIT:$($tool.Name)@$Script:HOSTNAME"; tool_name=$tool.Name; hostname=$Script:HOSTNAME }
            foreach ($k in $details.Keys) { $props[$k] = $details[$k] }
            Add-PHNode $nid @("PHJITAdminTool") $props
            # Check MakeMeAdmin allow/deny configuration
            $userAllowed = $true
            if ($tool.Name -eq "MakeMeAdmin" -and (Test-Path $tool.RegPath -EA SilentlyContinue)) {
                try {
                    $mmaReg = Get-ItemProperty $tool.RegPath -EA SilentlyContinue
                    if ($mmaReg.AllowedEntities) {
                        $allowed = $mmaReg.AllowedEntities -split ';'
                        $userAllowed = ($allowed | Where-Object { $env:USERNAME -match [regex]::Escape($_) -or $env:USERDOMAIN -match [regex]::Escape($_) }).Count -gt 0
                    }
                    if ($mmaReg.DeniedEntities) {
                        $denied = $mmaReg.DeniedEntities -split ';'
                        if (($denied | Where-Object { $env:USERNAME -match [regex]::Escape($_) }).Count -gt 0) { $userAllowed = $false }
                    }
                    $props["timeout_minutes"] = $mmaReg.AdminDurationMinutes
                } catch {}
            }
            if ($userAllowed) {
                Add-PHEdge $Script:CurrentUserId $nid "PHCanRequestJIT" @{mitre="T1548";tool=$tool.Name}
                Add-PHEdge $nid $Script:AdminNodeId "PHGrantsTempAdmin" @{tool=$tool.Name}
                Add-PHFinding "JITAdmin" "HIGH" "JIT admin tool '$($tool.Name)' detected - user can request temp admin" "Request elevation via $($tool.Name)"
                $count++
            } else {
                Add-PHFinding "JITAdmin" "LOW" "JIT admin tool '$($tool.Name)' detected but user not in allow list" "Check allow/deny config"
            }
        }
    }
    Write-PHStatus "Found $count JIT admin tool(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 19: PRINT SPOOLER / PRINTNIGHTMARE ──
function Check-PrintSpooler {
    Write-PHStatus "Checking Print Spooler configuration..."
    try {
        $spoolerSvc = Get-Service -Name "Spooler" -EA SilentlyContinue
        if (-not $spoolerSvc -or $spoolerSvc.Status -ne "Running") {
            Write-PHStatus "Print Spooler not running" "info"; return
        }
        $vulnerable = $false; $reasons = @()
        # Check Point and Print NoWarningNoElevationOnInstall
        $ppRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        try {
            $ppReg = Get-ItemProperty $ppRegPath -EA SilentlyContinue
            if ($ppReg -and $ppReg.NoWarningNoElevationOnInstall -eq 1) {
                $vulnerable = $true; $reasons += "NoWarningNoElevationOnInstall=1"
            }
        } catch {}
        # Check RestrictDriverInstallationToAdministrators
        $restrictRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        try {
            $restrictReg = Get-ItemProperty $restrictRegPath -EA SilentlyContinue
            if (-not $restrictReg -or $null -eq $restrictReg.RestrictDriverInstallationToAdministrators -or $restrictReg.RestrictDriverInstallationToAdministrators -eq 0) {
                $vulnerable = $true; $reasons += "RestrictDriverInstallationToAdministrators=0/absent"
            }
        } catch { $vulnerable = $true; $reasons += "RestrictDriverInstallationToAdministrators=absent" }
        # Check for CVE-2021-34527 patch
        $patched = $false
        try { $patched = (Get-HotFix -EA SilentlyContinue | Where-Object { $_.HotFixID -match "KB5005010|KB5005565|KB5005566|KB5005568|KB5005033" }).Count -gt 0 } catch {}
        if (-not $patched) { $reasons += "PrintNightmare patch (KB5005010) not found" }
        if ($vulnerable -or -not $patched) {
            $nid = New-PHId "printspooler" "Spooler"
            Add-PHNode $nid @("PHPrintSpooler") @{
                name     = "PRINTSPOOLER@$Script:HOSTNAME"
                hostname = $Script:HOSTNAME
                state    = $spoolerSvc.Status.ToString()
                reasons  = ($reasons -join "; ")
                patched  = $patched
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHCanExploitSpooler" @{mitre="T1068";reasons=($reasons -join "; ")}
            Add-PHEdge $nid $Script:SystemNodeId "PHEscalatesTo"
            Add-PHFinding "PrintSpooler" "CRITICAL" "Print Spooler vulnerable: $($reasons -join ', ')" "Use PrintNightmare PoC or malicious print server"
            Write-PHStatus "Print Spooler vulnerable!" "finding"
        } else {
            Write-PHStatus "Print Spooler running but appears patched" "info"
        }
    } catch { Write-PHStatus "Error checking Print Spooler: $_" "error" }
}

# ── CHECK 20: WSUS HTTP (NON-SSL) ───
function Check-WSUSConfig {
    Write-PHStatus "Checking WSUS configuration..."
    try {
        $wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $wuReg = Get-ItemProperty $wuRegPath -EA SilentlyContinue
        if (-not $wuReg -or -not $wuReg.WUServer) {
            Write-PHStatus "WSUS not configured" "info"; return
        }
        $wuServer = $wuReg.WUServer
        $useWU = $wuReg.UseWUServer
        if ($wuServer -match "^http://" -and $useWU -eq 1) {
            $nid = New-PHId "wsus" "WSUSConfig"
            Add-PHNode $nid @("PHWSUSConfig") @{
                name      = "WSUS:$wuServer@$Script:HOSTNAME"
                hostname  = $Script:HOSTNAME
                wu_server = $wuServer
                use_ssl   = $false
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHCanExploitWSUS" @{mitre="T1557";wu_server=$wuServer}
            Add-PHEdge $nid $Script:SystemNodeId "PHEscalatesTo"
            Add-PHFinding "WSUS" "HIGH" "WSUS uses HTTP (not HTTPS): $wuServer - MITM possible" "Use SharpWSUS or WSUSpendu for update injection"
            Write-PHStatus "WSUS HTTP found!" "finding"
        } else {
            Write-PHStatus "WSUS uses HTTPS or not active (UseWUServer=$useWU)" "info"
        }
    } catch { Write-PHStatus "Error checking WSUS: $_" "error" }
}

# ── CHECK 21: SCCM/MECM NAA CREDENTIALS ──
function Check-SCCMCredentials {
    Write-PHStatus "Checking for SCCM/MECM NAA credentials..."
    $found = $false
    # Check if SCCM client is installed
    $sccmInstalled = $false
    try { if (Test-Path "HKLM:\SOFTWARE\Microsoft\CCMSetup" -EA SilentlyContinue) { $sccmInstalled = $true } } catch {}
    if (-not $sccmInstalled) {
        try { $svc = Get-Service -Name "CcmExec" -EA SilentlyContinue; if ($svc) { $sccmInstalled = $true } } catch {}
    }
    if (-not $sccmInstalled) { Write-PHStatus "SCCM client not installed" "info"; return }

    # Check for NAA in WMI
    try {
        $naa = Get-CimInstance -Namespace "root\ccm\policy\Machine\ActualConfig" -ClassName "CCM_NetworkAccessAccount" -EA SilentlyContinue
        if ($naa) {
            $nid = New-PHId "sccmcred" "NAA"
            Add-PHNode $nid @("PHSCCMCredential") @{
                name     = "SCCM:NAA@$Script:HOSTNAME"
                hostname = $Script:HOSTNAME
                source   = "CCM_NetworkAccessAccount"
                description = "SCCM Network Access Account (DPAPI-protected)"
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHCanReadNAA" @{mitre="T1552.001";source="WMI CCM_NetworkAccessAccount"}
            Add-PHEdge $nid $nid "PHContainsCreds" @{source="SCCM_NAA"}
            Add-PHFinding "SCCM" "CRITICAL" "SCCM NAA credentials found in WMI - decrypt with SharpSCCM" "SharpSCCM local secrets -m wmi"
            $found = $true
            Write-PHStatus "SCCM NAA credentials found!" "finding"
        }
    } catch {}

    # Check for task sequences
    try {
        $taskSeq = Get-CimInstance -Namespace "root\ccm\Policy\Machine" -ClassName "CCM_TaskSequence" -EA SilentlyContinue
        if ($taskSeq) {
            $tsNid = New-PHId "sccmcred" "TaskSequence"
            Add-PHNode $tsNid @("PHSCCMCredential") @{
                name     = "SCCM:TaskSequence@$Script:HOSTNAME"
                hostname = $Script:HOSTNAME
                source   = "CCM_TaskSequence"
                description = "SCCM Task Sequence (may contain embedded credentials)"
            }
            Add-PHEdge $Script:CurrentUserId $tsNid "PHCanReadNAA" @{mitre="T1552.001";source="CCM_TaskSequence"}
            Add-PHEdge $tsNid $tsNid "PHContainsCreds" @{source="SCCM_TaskSequence"}
            Add-PHFinding "SCCM" "HIGH" "SCCM Task Sequences found - may contain embedded creds" "SharpSCCM local secrets"
            $found = $true
        }
    } catch {}

    if (-not $found) { Write-PHStatus "SCCM client installed but no NAA/TaskSequence creds accessible" "info" }
}

# ── CHECK 22: COM OBJECT HIJACKING ──
function Check-COMHijacking {
    Write-PHStatus "Checking COM object hijacking opportunities..."
    $count = 0
    # Known hijackable CLSIDs that run in SYSTEM context
    $hijackableCLSIDs = @(
        @{CLSID="{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}"; Desc="Scheduled Task Handler"},
        @{CLSID="{4590F811-1D3A-11D0-891F-00AA004B2E24}"; Desc="WBEM Locator"},
        @{CLSID="{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}"; Desc="TaskBand Shell"},
        @{CLSID="{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"; Desc="SysTray"},
        @{CLSID="{E6015C5B-B743-4A65-A1CF-4F26D877354A}"; Desc="DeviceAssociation"},
        @{CLSID="{97D17A04-4438-4C29-A86A-4D2C2BC8B952}"; Desc="EventViewer COM"}
    )
    foreach ($entry in $hijackableCLSIDs) {
        $clsid = $entry.CLSID
        # Check if HKCR has the CLSID (system-wide registration exists)
        $hkcrPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32"
        $hkcuPath = "HKCU:\Software\Classes\CLSID\$clsid"
        try {
            $hkcrExists = Test-Path $hkcrPath -EA SilentlyContinue
            $hkcuExists = Test-Path $hkcuPath -EA SilentlyContinue
            if ($hkcrExists -and -not $hkcuExists) {
                # HKCR entry exists but HKCU override does not - hijackable
                $dllPath = (Get-ItemProperty $hkcrPath -EA SilentlyContinue).'(default)'
                $nid = New-PHId "comhijack" $clsid
                Add-PHNode $nid @("PHCOMHijack") @{
                    name     = "COM:$($entry.Desc)@$Script:HOSTNAME"
                    clsid    = $clsid
                    description = $entry.Desc
                    dll_path = $dllPath
                    hostname = $Script:HOSTNAME
                }
                Add-PHEdge $Script:CurrentUserId $nid "PHCanHijackCOM" @{mitre="T1546.015";clsid=$clsid}
                Add-PHEdge $nid $Script:AdminNodeId "PHExecutesAs" @{technique="COM hijack to privileged context"}
                Add-PHFinding "COMHijack" "MEDIUM" "Hijackable COM object: $($entry.Desc) ($clsid)" "Create HKCU\\Classes\\CLSID\\$clsid\\InprocServer32 with malicious DLL"
                $count++
            }
        } catch {}
    }
    Write-PHStatus "Found $count hijackable COM object(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 23: NAMED PIPE PERMISSIONS ──
function Check-NamedPipePermissions {
    Write-PHStatus "Checking named pipe permissions..."
    $count = 0
    # Known pipes associated with SYSTEM services that may allow impersonation
    $interestingPipes = @(
        @{Name="spoolss";Desc="Print Spooler";Service="Spooler"},
        @{Name="epmapper";Desc="RPC Endpoint Mapper";Service="RpcEptMapper"},
        @{Name="lsarpc";Desc="LSA RPC";Service="SamSs"},
        @{Name="netlogon";Desc="Netlogon";Service="Netlogon"},
        @{Name="samr";Desc="SAM Remote";Service="SamSs"}
    )
    try {
        $pipes = Get-ChildItem "\\.\pipe\" -EA SilentlyContinue | Select-Object -ExpandProperty Name
    } catch { $pipes = @() }

    foreach ($ip in $interestingPipes) {
        $pipeExists = $pipes | Where-Object { $_ -eq $ip.Name -or $_ -match "^$([regex]::Escape($ip.Name))$" }
        if (-not $pipeExists) { continue }
        # Test if we can connect to the pipe
        $canConnect = $false
        try {
            $pipeClient = [System.IO.Pipes.NamedPipeClientStream]::new(".", $ip.Name, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
            $pipeClient.Connect(500)
            $canConnect = $true
            $pipeClient.Close()
            $pipeClient.Dispose()
        } catch { }
        if ($canConnect) {
            $nid = New-PHId "namedpipe" $ip.Name
            Add-PHNode $nid @("PHNamedPipe") @{
                name     = "PIPE:$($ip.Name)@$Script:HOSTNAME"
                pipe_name = $ip.Name
                description = $ip.Desc
                service  = $ip.Service
                hostname = $Script:HOSTNAME
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHCanImpersonatePipe" @{mitre="T1134.001";pipe=$ip.Name}
            Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account="SYSTEM";service=$ip.Service}
            Add-PHFinding "NamedPipe" "MEDIUM" "Connectable SYSTEM pipe: \\.\pipe\$($ip.Name) ($($ip.Desc))" "Use token impersonation (PrintSpoofer/EfsPotato)"
            $count++
        }
    }
    Write-PHStatus "Found $count accessible SYSTEM pipe(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 24: CACHED DOMAIN CREDENTIALS / CREDENTIAL FILES ──
function Check-CachedCredentials {
    Write-PHStatus "Checking cached credentials and credential stores..."
    $count = 0

    # DCC2 cached logon count
    try {
        $winlogonReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue
        $cachedCount = $winlogonReg.CachedLogonsCount
        if ($null -ne $cachedCount -and [int]$cachedCount -gt 0) {
            $nid = New-PHId "cachedcreds" "DCC2"
            Add-PHNode $nid @("PHCachedCreds") @{
                name        = "CACHED:DCC2@$Script:HOSTNAME"
                hostname    = $Script:HOSTNAME
                source      = "DCC2"
                description = "Domain Cached Credentials (CachedLogonsCount=$cachedCount)"
                cached_count = [int]$cachedCount
            }
            Add-PHEdge $Script:CurrentUserId $nid "PHHasCachedCreds" @{mitre="T1552.001";cached_count=[int]$cachedCount}
            Add-PHFinding "CachedCreds" "MEDIUM" "Domain cached credentials enabled (CachedLogonsCount=$cachedCount) - DCC2 hashes in SECURITY hive" "Extract with mimikatz lsadump::cache (requires SYSTEM)"
            $count++
        }
    } catch {}

    # WinSCP stored sessions
    $winscpRegPath = "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
    try {
        if (Test-Path $winscpRegPath -EA SilentlyContinue) {
            $sessions = Get-ChildItem $winscpRegPath -EA SilentlyContinue
            foreach ($sess in $sessions) {
                $sessProps = Get-ItemProperty $sess.PSPath -EA SilentlyContinue
                if ($sessProps.Password -or $sessProps.HostName) {
                    $sessName = $sess.PSChildName
                    $nid = New-PHId "cachedcreds" "WinSCP_$sessName"
                    Add-PHNode $nid @("PHCachedCreds") @{
                        name     = "CACHED:WinSCP:$sessName@$Script:HOSTNAME"
                        hostname = $Script:HOSTNAME
                        source   = "WinSCP"
                        description = "WinSCP stored session: $sessName"
                        host     = $sessProps.HostName
                        username = $sessProps.UserName
                    }
                    Add-PHEdge $Script:CurrentUserId $nid "PHHasCachedCreds" @{mitre="T1552.001";source="WinSCP"}
                    if ($sessProps.Password) {
                        Add-PHEdge $nid $nid "PHContainsCreds" @{source="WinSCP"}
                        [void]$Script:ExtractedCreds.Add(@{ source="WinSCP"; username=$sessProps.UserName; password="[WinSCP-encrypted]"; nodeId=$nid })
                    }
                    Add-PHFinding "CachedCreds" "HIGH" "WinSCP stored session: $sessName ($($sessProps.HostName))" "Decrypt with WinSCP password recovery tools"
                    $count++
                }
            }
        }
    } catch {}

    # FileZilla stored credentials
    $fzPaths = @("$env:APPDATA\FileZilla\sitemanager.xml","$env:APPDATA\FileZilla\recentservers.xml")
    foreach ($fzPath in $fzPaths) {
        if (Test-Path $fzPath -EA SilentlyContinue) {
            try {
                [xml]$fzXml = Get-Content $fzPath -Raw -EA SilentlyContinue
                $servers = $fzXml.SelectNodes("//Server")
                foreach ($srv in $servers) {
                    $fzHost = $srv.Host
                    $fzUser = $srv.User
                    $fzPass = $srv.Pass
                    if ($fzPass) {
                        $nid = New-PHId "cachedcreds" "FileZilla_$fzHost"
                        Add-PHNode $nid @("PHCachedCreds") @{
                            name     = "CACHED:FileZilla:$fzHost@$Script:HOSTNAME"
                            hostname = $Script:HOSTNAME
                            source   = "FileZilla"
                            description = "FileZilla saved server: $fzHost"
                            host     = $fzHost
                            username = $fzUser
                        }
                        Add-PHEdge $Script:CurrentUserId $nid "PHHasCachedCreds" @{mitre="T1552.001";source="FileZilla"}
                        # FileZilla stores base64-encoded plaintext passwords
                        $decodedPass = $null
                        try { $decodedPass = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fzPass)) } catch { $decodedPass = $fzPass }
                        if ($decodedPass) {
                            Add-PHEdge $nid $nid "PHContainsCreds" @{source="FileZilla"}
                            [void]$Script:ExtractedCreds.Add(@{ source="FileZilla"; username=$fzUser; password=$decodedPass; nodeId=$nid })
                        }
                        Add-PHFinding "CachedCreds" "HIGH" "FileZilla stored creds for $fzUser@$fzHost" "Read $fzPath"
                        $count++
                    }
                }
            } catch {}
        }
    }

    # PuTTY saved sessions with proxy passwords
    $puttyRegPath = "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions"
    try {
        if (Test-Path $puttyRegPath -EA SilentlyContinue) {
            $sessions = Get-ChildItem $puttyRegPath -EA SilentlyContinue
            foreach ($sess in $sessions) {
                $sessProps = Get-ItemProperty $sess.PSPath -EA SilentlyContinue
                if ($sessProps.ProxyPassword) {
                    $sessName = $sess.PSChildName
                    $nid = New-PHId "cachedcreds" "PuTTY_$sessName"
                    Add-PHNode $nid @("PHCachedCreds") @{
                        name     = "CACHED:PuTTY:$sessName@$Script:HOSTNAME"
                        hostname = $Script:HOSTNAME
                        source   = "PuTTY"
                        description = "PuTTY session with proxy password: $sessName"
                    }
                    Add-PHEdge $Script:CurrentUserId $nid "PHHasCachedCreds" @{mitre="T1552.001";source="PuTTY"}
                    Add-PHEdge $nid $nid "PHContainsCreds" @{source="PuTTY"}
                    [void]$Script:ExtractedCreds.Add(@{ source="PuTTY"; username=$sessProps.ProxyUsername; password=$sessProps.ProxyPassword; nodeId=$nid })
                    Add-PHFinding "CachedCreds" "HIGH" "PuTTY session '$sessName' has proxy password" "Read from registry"
                    $count++
                }
            }
        }
    } catch {}

    # WiFi profile passwords
    try {
        $wlanProfiles = netsh wlan show profiles 2>$null
        $profileNames = [regex]::Matches($wlanProfiles, 'All User Profile\s*:\s*(.+)') | ForEach-Object { $_.Groups[1].Value.Trim() }
        foreach ($pName in $profileNames) {
            try {
                $profileDetail = netsh wlan show profile name="$pName" key=clear 2>$null
                $keyMatch = [regex]::Match(($profileDetail -join "`n"), 'Key Content\s*:\s*(.+)')
                if ($keyMatch.Success) {
                    $wifiKey = $keyMatch.Groups[1].Value.Trim()
                    $nid = New-PHId "cachedcreds" "WiFi_$pName"
                    Add-PHNode $nid @("PHCachedCreds") @{
                        name     = "CACHED:WiFi:$pName@$Script:HOSTNAME"
                        hostname = $Script:HOSTNAME
                        source   = "WiFi"
                        description = "WiFi profile with cleartext key: $pName"
                    }
                    Add-PHEdge $Script:CurrentUserId $nid "PHHasCachedCreds" @{mitre="T1552.001";source="WiFi"}
                    Add-PHEdge $nid $nid "PHContainsCreds" @{source="WiFi"}
                    [void]$Script:ExtractedCreds.Add(@{ source="WiFi"; username=$pName; password=$wifiKey; nodeId=$nid })
                    Add-PHFinding "CachedCreds" "LOW" "WiFi profile '$pName' key readable" "netsh wlan show profile name=$pName key=clear"
                    $count++
                }
            } catch {}
        }
    } catch {}

    Write-PHStatus "Found $count cached credential source(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 25: WMI EVENT SUBSCRIPTIONS ──
function Check-WMISubscriptions {
    Write-PHStatus "Checking WMI permanent event subscriptions..."
    $count = 0
    try {
        $consumers = Get-CimInstance -Namespace "root\subscription" -ClassName "__EventConsumer" -EA SilentlyContinue
        foreach ($consumer in $consumers) {
            $consumerType = $consumer.CimClass.CimClassName
            $binaryPath = $null
            if ($consumerType -eq "CommandLineEventConsumer") {
                $binaryPath = $consumer.ExecutablePath
                if (-not $binaryPath) { $binaryPath = ($consumer.CommandLineTemplate -split '\s+')[0] -replace '^"([^"]+)".*','$1' }
            } elseif ($consumerType -eq "ActiveScriptEventConsumer") {
                $binaryPath = $consumer.ScriptFileName
            }
            if (-not $binaryPath) { continue }
            # Check if the binary/script path is writable
            $isWritable = $false
            if (Test-Path $binaryPath -EA SilentlyContinue) {
                $isWritable = Test-WritableAcl $binaryPath
            } else {
                # Check if parent directory is writable (binary doesn't exist yet)
                $parentDir = Split-Path $binaryPath -Parent -EA SilentlyContinue
                if ($parentDir -and (Test-Path $parentDir -EA SilentlyContinue)) {
                    $isWritable = Test-WritableAcl $parentDir
                }
            }
            if ($isWritable) {
                $nid = New-PHId "wmisub" $consumer.Name
                Add-PHNode $nid @("PHWMISubscription") @{
                    name          = "WMI:$($consumer.Name)@$Script:HOSTNAME"
                    consumer_name = $consumer.Name
                    consumer_type = $consumerType
                    binary_path   = $binaryPath
                    hostname      = $Script:HOSTNAME
                }
                Add-PHEdge $Script:CurrentUserId $nid "PHCanModifyWMI" @{mitre="T1546.003";consumer=$consumer.Name}
                Add-PHEdge $nid $Script:SystemNodeId "PHRunsAs" @{run_account="SYSTEM"}
                Add-PHFinding "WMISub" "HIGH" "Writable WMI consumer '$($consumer.Name)': $binaryPath" "Replace consumer binary/script"
                $count++
            }
        }
    } catch { Write-PHStatus "Error checking WMI subscriptions: $_" "warn" }
    Write-PHStatus "Found $count writable WMI consumer(s)" $(if($count){"finding"}else{"info"})
}

function Check-WebClientRelay {
    Write-PHStatus "Checking WebClient relay attack surface..."
    # Step 1: Check domain membership
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -EA Stop
        if (-not $cs.PartOfDomain) {
            Write-PHStatus "Not domain-joined - WebClient relay not applicable" "info"
            return
        }
    } catch {
        Write-PHStatus "Could not determine domain membership: $_" "warn"
        return
    }
    # Step 2: Check WebClient service
    $svc = Get-Service "WebClient" -EA SilentlyContinue
    if (-not $svc) {
        Write-PHStatus "WebClient service not installed - skipping" "info"
        return
    }
    $startType = try { (Get-CimInstance Win32_Service -Filter "Name='WebClient'" -EA Stop).StartMode } catch { "Unknown" }
    if ($startType -eq "Disabled") {
        # Still flag as medium — admin could re-enable
        $severity = "MEDIUM"
        $detail = "WebClient installed but Disabled (admin could re-enable)"
    } else {
        # Manual or Auto — triggerable without admin
        $severity = "CRITICAL"
        $detail = "WebClient start type '$startType' - triggerable without admin"
    }
    # Step 3: Check LDAP signing policy
    $ldapSigning = "not enforced"
    $policyVal = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LDAP" -Name "LDAPClientIntegrity" -EA SilentlyContinue).LDAPClientIntegrity
    if ($null -eq $policyVal) {
        $policyVal = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -EA SilentlyContinue).LDAPClientIntegrity
    }
    if ($policyVal -eq 2) {
        $ldapSigning = "required"
        if ($severity -eq "CRITICAL") { $severity = "MEDIUM" }
        else { $severity = "LOW"; return } # Disabled + signing required = not exploitable
    }
    # Step 4: Create graph nodes/edges
    $nid = New-PHId "webclientrelay" "$Script:HOSTNAME"
    Add-PHNode $nid @("PHWebClientRelay") @{
        name           = "WebClientRelay@$Script:HOSTNAME"
        hostname       = $Script:HOSTNAME
        domain         = $cs.Domain
        webclient_start = $startType
        webclient_status = "$($svc.Status)"
        ldap_signing   = $ldapSigning
    }
    Add-PHEdge $Script:CurrentUserId $nid "PHCanRelayWebClient" @{
        mitre        = "T1187"
        start_type   = $startType
        ldap_signing = $ldapSigning
    }
    Add-PHEdge $nid $Script:SystemNodeId "PHEscalatesTo" @{method="NTLM relay to LDAP → Shadow Credentials/RBCD → S4U2Self → SYSTEM service"}
    Add-PHFinding "WebClientRelay" $severity "$detail | LDAP signing: $ldapSigning | Domain: $($cs.Domain)" "Use WebClientRelayUp/DavRelayUp/KrbRelayUp"
    Write-PHStatus "WebClient relay: $severity ($detail, LDAP signing $ldapSigning)" $(if($severity -in @("CRITICAL","HIGH")){"finding"}else{"warn"})
}

# ── CHECK 28: SERVICE RECOVERY ACTIONS ─
function Check-ServiceRecoveryActions {
    Write-PHStatus "Checking service failure recovery commands..."
    $count = 0
    $svcs = Get-CachedServices
    foreach ($svc in $svcs) {
        try {
            $output = sc.exe qfailure $svc.Name 2>$null
            if (-not $output) { continue }
            $joined = $output -join "`n"
            if ($joined -match 'COMMAND\s+LINE[^:]*:\s*(.+)') {
                $cmdLine = $Matches[1].Trim()
                if (-not $cmdLine -or $cmdLine -match '^\s*$') { continue }
                # Extract binary path (same parsing as service PathName)
                $recoveryBin = $null
                if ($cmdLine -match '^"([^"]+)"') { $recoveryBin = $Matches[1] }
                elseif ($cmdLine -match '(\S+\.exe)') { $recoveryBin = $Matches[1] }
                else { $recoveryBin = ($cmdLine -split '\s+')[0] }
                $recoveryBin = if ($recoveryBin) { $recoveryBin.Trim() } else { $null }
                if (-not $recoveryBin) { continue }
                $Script:CachedServiceRecovery[$svc.Name] = $recoveryBin
                if (Test-Path $recoveryBin -EA SilentlyContinue) {
                    if (Test-WritableAcl $recoveryBin) {
                        $svcNodeId = New-PHId "service" $svc.Name
                        $isSystem = $svc.StartName -match "^(SYSTEM|LocalSystem|NT AUTHORITY\\SYSTEM)$"
                        Add-PHNode $svcNodeId @("PHService") @{
                            name="SVC:$($svc.Name)@$Script:HOSTNAME"; service_name=$svc.Name
                            display_name=$svc.DisplayName; start_name=$svc.StartName
                            binary_path=$svc.PathName; recovery_command=$cmdLine
                            recovery_binary=$recoveryBin; hostname=$Script:HOSTNAME
                        }
                        if ($isSystem) { Add-PHEdge $svcNodeId $Script:SystemNodeId "PHRunsAs" @{run_account=$svc.StartName} }
                        Add-PHEdge $Script:CurrentUserId $svcNodeId "PHCanWriteRecoveryBin" @{
                            recovery_binary=$recoveryBin; recovery_command=$cmdLine; mitre="T1574.010"
                        }
                        Add-PHFinding "SvcRecovery" "HIGH" "Service '$($svc.Name)' recovery command binary is writable: $recoveryBin" "Replace $recoveryBin, crash the service, recovery runs as $($svc.StartName)"
                        $count++
                        Write-PHStatus "Writable recovery binary: $($svc.Name) -> $recoveryBin" "finding"
                    }
                }
            }
        } catch {}
    }
    Write-PHStatus "Found $count writable service recovery command(s)" $(if($count){"finding"}else{"info"})
}

# ── CHECK 29: SHADOW COPY SENSITIVE FILES ─
function Check-ShadowCopyFiles {
    Write-PHStatus "Checking shadow copy sensitive files..."
    $count = 0
    try {
        $output = vssadmin list shadows 2>$null
        if (-not $output) {
            Write-PHStatus "No shadow copies found or vssadmin not available" "info"
            return
        }
        $joined = $output -join "`n"
        $shadowPaths = [regex]::Matches($joined, 'Shadow Copy Volume:\s*(\\\\[^\s]+)') | ForEach-Object { $_.Groups[1].Value }
        if (-not $shadowPaths -or $shadowPaths.Count -eq 0) {
            Write-PHStatus "No shadow copy volumes found" "info"
            return
        }
        $sensitiveRelPaths = @(
            "Windows\System32\config\SAM",
            "Windows\System32\config\SYSTEM",
            "Windows\System32\config\SECURITY",
            "Windows\Panther\unattend.xml",
            "Windows\System32\config\RegBack\SAM",
            "Windows\System32\config\RegBack\SYSTEM"
        )
        foreach ($shadowPath in $shadowPaths) {
            $scNodeId = $null
            $samFileId = $null
            $systemFileId = $null
            foreach ($relPath in $sensitiveRelPaths) {
                $fullPath = Join-Path $shadowPath $relPath
                if (Test-Path $fullPath -EA SilentlyContinue) {
                    # Create shadow copy node on first accessible file
                    if (-not $scNodeId) {
                        $scNodeId = New-PHId "shadowcopy" $shadowPath
                        Add-PHNode $scNodeId @("PHShadowCopy") @{
                            name="SHADOW:$shadowPath@$Script:HOSTNAME"
                            shadow_path=$shadowPath; hostname=$Script:HOSTNAME
                        }
                        Add-PHEdge $Script:CurrentUserId $scNodeId "PHCanAccessShadowCopy" @{
                            shadow_path=$shadowPath; mitre="T1003.002"
                        }
                    }
                    $fileNodeId = New-PHId "sensfile" "$shadowPath\$relPath"
                    Add-PHNode $fileNodeId @("PHSensitiveFile") @{
                        name="SENSFILE:$relPath@$Script:HOSTNAME"
                        file_path="$shadowPath\$relPath"; shadow_path=$shadowPath
                        relative_path=$relPath; hostname=$Script:HOSTNAME
                    }
                    Add-PHEdge $scNodeId $fileNodeId "PHContainsSensitiveFile" @{
                        file_path="$shadowPath\$relPath"
                    }
                    # Track SAM and SYSTEM for hash extraction edge
                    if ($relPath -match '\\SAM$') { $samFileId = $fileNodeId }
                    if ($relPath -eq "Windows\System32\config\SYSTEM") { $systemFileId = $fileNodeId }
                    $count++
                    Write-PHStatus "Accessible shadow file: $shadowPath\$relPath" "finding"
                }
            }
            # If both SAM and SYSTEM accessible in same shadow, add hash extraction edge
            if ($samFileId -and $systemFileId) {
                Add-PHEdge $samFileId $Script:AdminNodeId "PHCanExtractHashes" @{
                    sam_path="$shadowPath\Windows\System32\config\SAM"
                    system_path="$shadowPath\Windows\System32\config\SYSTEM"
                    mitre="T1003.002"
                }
            }
            if ($scNodeId) {
                Add-PHFinding "ShadowCopy" "HIGH" "Shadow copy '$shadowPath' contains accessible sensitive files" "Copy SAM/SYSTEM hives from shadow path, extract hashes with secretsdump"
            }
        }
    } catch {
        Write-PHStatus "Error checking shadow copies: $_" "warn"
    }
    Write-PHStatus "Found $count accessible shadow copy file(s)" $(if($count){"finding"}else{"info"})
}

# ── CUSTOM ICONS JSON ─────────────────
function Get-CustomNodeKinds {
    return [ordered]@{
        PHUser              = @{icon=@{name="user-secret";color="#58a6ff";type="font-awesome"}}
        PHPrivTarget        = @{icon=@{name="crown";color="#f85149";type="font-awesome"}}
        PHEndpoint          = @{icon=@{name="desktop";color="#8b949e";type="font-awesome"}}
        PHService           = @{icon=@{name="gear";color="#d29922";type="font-awesome"}}
        PHUnquotedPath      = @{icon=@{name="route";color="#f0883e";type="font-awesome"}}
        PHWritablePath      = @{icon=@{name="folder-open";color="#da3633";type="font-awesome"}}
        PHRegistryMisconfig = @{icon=@{name="key";color="#f85149";type="font-awesome"}}
        PHTokenPrivilege    = @{icon=@{name="shield-halved";color="#a371f7";type="font-awesome"}}
        PHScheduledTask     = @{icon=@{name="clock";color="#7ee787";type="font-awesome"}}
        PHAutoRun           = @{icon=@{name="play";color="#f0883e";type="font-awesome"}}
        PHWritableRegKey    = @{icon=@{name="pen-to-square";color="#da3633";type="font-awesome"}}
        PHStoredCredential  = @{icon=@{name="unlock";color="#f85149";type="font-awesome"}}
        PHGPPPassword       = @{icon=@{name="key";color="#f85149";type="font-awesome"}}
        PHUnattendFile      = @{icon=@{name="file-lines";color="#f0883e";type="font-awesome"}}
        PHPSHistory         = @{icon=@{name="terminal";color="#58a6ff";type="font-awesome"}}
        PHSensitiveFile     = @{icon=@{name="file-shield";color="#f0883e";type="font-awesome"}}
        PHUACBypass         = @{icon=@{name="shield";color="#f85149";type="font-awesome"}}
        PHWritableProgramDir= @{icon=@{name="folder";color="#da3633";type="font-awesome"}}
        PHLocalUser         = @{icon=@{name="user";color="#d29922";type="font-awesome"}}
        PHUserProfile       = @{icon=@{name="address-card";color="#58a6ff";type="font-awesome"}}
        PHJITAdminTool      = @{icon=@{name="user-clock";color="#f0883e";type="font-awesome"}}
        PHPrintSpooler      = @{icon=@{name="print";color="#f85149";type="font-awesome"}}
        PHWSUSConfig        = @{icon=@{name="download";color="#f85149";type="font-awesome"}}
        PHSCCMCredential    = @{icon=@{name="server";color="#f85149";type="font-awesome"}}
        PHCOMHijack         = @{icon=@{name="puzzle-piece";color="#a371f7";type="font-awesome"}}
        PHNamedPipe         = @{icon=@{name="faucet";color="#f0883e";type="font-awesome"}}
        PHCachedCreds       = @{icon=@{name="database";color="#d29922";type="font-awesome"}}
        PHWMISubscription   = @{icon=@{name="bolt";color="#a371f7";type="font-awesome"}}
        PHWebClientRelay    = @{icon=@{name="share-nodes";color="#f85149";type="font-awesome"}}
        PHShadowCopy        = @{icon=@{name="hard-drive";color="#8b949e";type="font-awesome"}}
    }
}

function Export-CustomNodeIcons([string]$OutDir=".") {
    $kinds = Get-CustomNodeKinds
    # Build POST /api/v2/custom-nodes payload: { custom_types: { NodeKind: { icon: {...} } } }
    $customTypes = [ordered]@{}
    foreach ($kind in $kinds.Keys) {
        $customTypes[$kind] = $kinds[$kind]
    }
    $apiPayload = @{ custom_types = $customTypes }
    $combinedFile = Join-Path $(Get-Item $OutDir).FullName "privhound_customnodes.json"
    $json = $apiPayload | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($combinedFile, $json, [System.Text.UTF8Encoding]::new($false))
    return $combinedFile
}

# ── OUTPUT ────────────────────────────
function Export-OpenGraphJson([string]$Path) {
    $payload = @{ metadata=@{source_kind=""}; graph=@{nodes=$Script:Nodes;edges=$Script:Edges} }
    $json = $payload | ConvertTo-Json -Depth 10
    # Write UTF-8 without BOM — BOM breaks BloodHound's JSON parser
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location) $Path }
    [System.IO.File]::WriteAllText($resolvedPath, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Host "`n  === COLLECTION COMPLETE ===" -ForegroundColor Green
    Write-PHStatus "Nodes: $($Script:Nodes.Count) | Edges: $($Script:Edges.Count) | Findings: $($Script:Findings.Count)" "info"
    if ($Script:Findings.Count -gt 0) {
        $sevColors = @{ CRITICAL = "Red"; HIGH = "Red"; MEDIUM = "Yellow" }
        foreach ($sev in @("CRITICAL","HIGH","MEDIUM")) {
            $group = $Script:Findings | Where-Object { $_.Severity -eq $sev }
            foreach ($f in $group) {
                Write-Host "  [$sev] $($f.Description)" -ForegroundColor $sevColors[$sev]
            }
        }
    }
    Write-Host "`n  Output: $resolvedPath" -ForegroundColor Green
    Write-Host "  Upload: Administration -> File Ingest" -ForegroundColor Cyan
    Write-Host "  Icons:  POST privhound_customnodes.json to /api/v2/custom-nodes" -ForegroundColor Cyan
    Write-Host "  Query:  Explore -> Cypher tab (pathfinding UI not supported for custom nodes yet)`n" -ForegroundColor Yellow
}

# ── MAIN ──────────────────────────────
function Invoke-PrivHound {
    Write-PHBanner
    if ($OutputFormat -in @("BloodHound-customnodes","All")) {
        $ip = Export-CustomNodeIcons
        Write-PHStatus "Custom icons -> $ip (POST to /api/v2/custom-nodes)" "finding"
    }
    if ($OutputFormat -eq "BloodHound-customnodes") { return }

    Initialize-CoreNodes
    $checks = @(
        @{N="Services";F={Check-WeakServicePermissions}},@{N="UnquotedPaths";F={Check-UnquotedServicePaths}},
        @{N="DLLHijacking";F={Check-DLLHijacking}},@{N="AlwaysInstall";F={Check-AlwaysInstallElevated}},
        @{N="TokenPrivileges";F={Check-TokenPrivileges}},@{N="ScheduledTasks";F={Check-ScheduledTasks}},
        @{N="Autoruns";F={Check-AutoRuns}},@{N="RegistryKeys";F={Check-ServiceRegistryKeys}},
        @{N="StoredCreds";F={Check-StoredCredentials}},@{N="GPPPasswords";F={Check-GPPPasswords}},
        @{N="UnattendFiles";F={Check-UnattendFiles}},@{N="PSHistory";F={Check-PSHistory}},
        @{N="SensitiveFiles";F={Check-SensitiveFiles}},@{N="UACBypass";F={Check-UACBypass}},
        @{N="WritableProgDirs";F={Check-WritableProgramDirs}},
        @{N="CrossUserProfiles";F={Check-CrossUserProfiles}},
        @{N="CredLoginPaths";F={Check-CredentialLoginPaths}},
        @{N="CrossUserPriv";F={Check-CrossUserPrivileges}},
        @{N="JITAdmin";F={Check-JITAdminTools}},
        @{N="PrintSpooler";F={Check-PrintSpooler}},
        @{N="WSUSConfig";F={Check-WSUSConfig}},
        @{N="SCCMCreds";F={Check-SCCMCredentials}},
        @{N="COMHijacking";F={Check-COMHijacking}},
        @{N="NamedPipes";F={Check-NamedPipePermissions}},
        @{N="CachedCreds";F={Check-CachedCredentials}},
        @{N="WMISubscriptions";F={Check-WMISubscriptions}},
        @{N="WebClientRelay";F={Check-WebClientRelay}},
        @{N="SvcRecovery";F={Check-ServiceRecoveryActions}},
        @{N="ShadowCopies";F={Check-ShadowCopyFiles}}
    )
    foreach ($c in $checks) {
        if ($SkipChecks -contains $c.N) { Write-PHStatus "Skipping $($c.N)" "warn"; continue }
        try { & $c.F } catch { Write-PHStatus "Error in $($c.N): $_" "error" }
    }
    Export-OpenGraphJson $OutputPath
}

Invoke-PrivHound
