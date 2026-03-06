# PrivHound - Prebuilt Cypher Queries for BloodHound
# Import these as custom searches in BloodHound UI
# Navigate to: Explore → Cypher tab → paste and run
#
# NOTE: BloodHound CE's Cypher engine may not support property access
# (e.g., n.property_name) on OpenGraph custom nodes. If a "Table View"
# query returns "No results", use the graph/path version instead.

# ─────────────────────────────────────────────────
# DISCOVERY: Show the full PrivHound attack graph
# ─────────────────────────────────────────────────

## All PrivHound paths to SYSTEM
MATCH p=(u:PHUser)-[*1..5]->(t:PHPrivTarget)
WHERE t.account = "NT AUTHORITY\\SYSTEM"
RETURN p

## All PrivHound paths to Local Admin
MATCH p=(u:PHUser)-[*1..5]->(t:PHPrivTarget)
WHERE t.account = "BUILTIN\\Administrators"
RETURN p

## Full PrivHound graph (all nodes and edges)
MATCH p=()-[:PHCanModifyService|PHCanWriteBinary|PHCanHijackPath|PHCanWriteTo|PHDLLHijackTo|PHCanExploit|PHHasPrivilege|PHCanEscalateTo|PHCanWriteTaskBinary|PHCanWriteAutorun|PHCanModifyRegKey|PHCanReadCreds|PHHasStoredCreds|PHCanDecryptGPP|PHCanReadHistory|PHCanAccessFile|PHCanBypassUAC|PHCanWriteProgDir|PHCanLoginAs|PHMemberOf|PHHostsBinaryFor|PHRunsAsUser|PHRunsAs|PHEscalatesTo|PHExecutesAs|PHHosts|PHHasSessionOn|PHCanReadProtected|PHCanExtractHashes|PHCanWriteProtected|PHCanInjectInto|PHCanLoginViaRunas|PHCanAccessProfile|PHProfileContains|PHContainsCreds|PHCanRequestJIT|PHGrantsTempAdmin|PHCanExploitSpooler|PHCanExploitWSUS|PHCanReadNAA|PHCanHijackCOM|PHCanImpersonatePipe|PHHasCachedCreds|PHCanModifyWMI|PHCanRelayWebClient|PHCanWriteRecoveryBin|PHCanAccessShadowCopy|PHContainsSensitiveFile]->()
RETURN p

# ─────────────────────────────────────────────────
# SERVICES: Weak permissions and writable binaries
# ─────────────────────────────────────────────────

## Modifiable services running as SYSTEM
MATCH p=(u:PHUser)-[:PHCanModifyService]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## Services with writable binaries
MATCH p=(u:PHUser)-[:PHCanWriteBinary]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## List all vulnerable services
MATCH p=(u:PHUser)-[:PHCanModifyService|PHCanWriteBinary]->(s:PHService)
RETURN p

## Non-SYSTEM service accounts → local user → admin
MATCH p=(u:PHUser)-[:PHCanModifyService|PHCanWriteBinary]->(s:PHService)-[:PHRunsAsUser]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# UNQUOTED PATHS
# ─────────────────────────────────────────────────

## Unquoted service path hijacking opportunities
MATCH p=(u:PHUser)-[:PHCanHijackPath]->(uq:PHUnquotedPath)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## List unquoted paths
MATCH p=(u:PHUser)-[:PHCanHijackPath]->(uq:PHUnquotedPath)
RETURN p

# ─────────────────────────────────────────────────
# DLL HIJACKING
# ─────────────────────────────────────────────────

## Writable PATH directories (DLL hijack)
MATCH p=(u:PHUser)-[:PHCanWriteTo]->(d:PHWritablePath)-[:PHDLLHijackTo]->(t:PHPrivTarget)
RETURN p

## List writable PATH dirs
MATCH p=(u:PHUser)-[:PHCanWriteTo]->(d:PHWritablePath)
RETURN p

# ─────────────────────────────────────────────────
# TOKEN PRIVILEGES
# ─────────────────────────────────────────────────

## Dangerous token privileges → SYSTEM
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanEscalateTo]->(t:PHPrivTarget)
RETURN p

## List dangerous privileges
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)
RETURN p

## SeBackup: privilege → SAM/SYSTEM hives → hash extraction → admin
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanReadProtected]->(f:PHSensitiveFile)-[:PHCanExtractHashes]->(t:PHPrivTarget)
RETURN p

## SeDebug: privilege → process injection → SYSTEM
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanInjectInto]->(t:PHPrivTarget)
RETURN p

## SeRestore: privilege → write protected files → SYSTEM
MATCH p=(u:PHUser)-[:PHHasPrivilege]->(priv:PHTokenPrivilege)-[:PHCanWriteProtected]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# REGISTRY & MISCONFIGURATIONS
# ─────────────────────────────────────────────────

## AlwaysInstallElevated path
MATCH p=(u:PHUser)-[:PHCanExploit]->(r:PHRegistryMisconfig)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

## Writable service registry keys
MATCH p=(u:PHUser)-[:PHCanModifyRegKey]->(rk:PHWritableRegKey)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# SCHEDULED TASKS & AUTORUNS
# ─────────────────────────────────────────────────

## Writable scheduled task binaries → SYSTEM
MATCH p=(u:PHUser)-[:PHCanWriteTaskBinary]->(task:PHScheduledTask)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## Writable autorun executables
MATCH p=(u:PHUser)-[:PHCanWriteAutorun]->(ar:PHAutoRun)-[:PHExecutesAs]->()
RETURN p

# ─────────────────────────────────────────────────
# CREDENTIALS
# ─────────────────────────────────────────────────

## Stored/cached credentials
MATCH p=(u:PHUser)-[:PHHasStoredCreds|PHCanReadCreds]->(c:PHStoredCredential)
RETURN p

## cmdkey → runas /savecred → local user → admin
MATCH p=(u:PHUser)-[:PHHasStoredCreds]->(c:PHStoredCredential)-[:PHCanLoginViaRunas]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# GPP PASSWORDS
# ─────────────────────────────────────────────────

## GPP cached password files → credential pipeline → admin
MATCH p=(u:PHUser)-[:PHCanDecryptGPP]->(g:PHGPPPassword)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## List GPP password files
MATCH p=(u:PHUser)-[:PHCanDecryptGPP]->(g:PHGPPPassword)
RETURN p

# ─────────────────────────────────────────────────
# CREDENTIAL LOGIN PATHS (multi-hop)
# ─────────────────────────────────────────────────

## Credential login paths (cleartext creds → user login)
MATCH p=(u:PHUser)-[:PHCanReadCreds|PHCanDecryptGPP]->(c)-[:PHCanLoginAs]->(lu:PHLocalUser)
RETURN p

## Credential paths to Admin
MATCH p=(u:PHUser)-[:PHCanReadCreds|PHCanDecryptGPP]->(c)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## Full credential escalation chain (any source with embedded creds)
MATCH p=(u:PHUser)-[*1..6]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
RETURN p

## Credential pipeline: file with embedded creds → login → admin
MATCH p=(u:PHUser)-[:PHCanReadHistory|PHCanAccessFile]->(f)-[:PHContainsCreds]->(f)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## List local users with valid credentials
MATCH (c)-[:PHCanLoginAs]->(lu:PHLocalUser)
RETURN lu

# ─────────────────────────────────────────────────
# WRITABLE PROGRAM DIRS → SERVICE/TASK
# ─────────────────────────────────────────────────

## Writable program dir → service binary → SYSTEM
MATCH p=(u:PHUser)-[:PHCanWriteProgDir]->(d:PHWritableProgramDir)-[:PHHostsBinaryFor]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## Writable program dir → scheduled task binary → SYSTEM
MATCH p=(u:PHUser)-[:PHCanWriteProgDir]->(d:PHWritableProgramDir)-[:PHHostsBinaryFor]->(task:PHScheduledTask)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## Writable directories in Program Files (all)
MATCH p=(u:PHUser)-[:PHCanWriteProgDir]->(d:PHWritableProgramDir)
RETURN p

# ─────────────────────────────────────────────────
# CROSS-USER PROFILES
# ─────────────────────────────────────────────────

## Accessible cross-user profiles with sensitive files
MATCH p=(u:PHUser)-[:PHCanAccessProfile]->(prof:PHUserProfile)-[:PHProfileContains]->(f:PHSensitiveFile)
RETURN p

## Cross-user profile files that contain credentials (self-edge)
MATCH p=(u:PHUser)-[:PHCanAccessProfile]->(prof:PHUserProfile)-[:PHProfileContains]->(f:PHSensitiveFile)-[:PHContainsCreds]->(f)
RETURN p

## Cross-user profile → creds → login → admin (full chain)
MATCH p=(u:PHUser)-[:PHCanAccessProfile]->(prof:PHUserProfile)-[:PHProfileContains]->(f:PHSensitiveFile)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## Cross-user profile → creds → login → admin (via any path length)
MATCH p=(u:PHUser)-[*1..6]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanAccessProfile")
  AND any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
RETURN p

# ─────────────────────────────────────────────────
# UNATTENDED INSTALL FILES
# ─────────────────────────────────────────────────

## Unattend files with credentials → credential pipeline → admin
MATCH p=(u:PHUser)-[:PHCanReadCreds]->(f:PHUnattendFile)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## List unattend files
MATCH p=(u:PHUser)-[:PHCanReadCreds]->(f:PHUnattendFile)
RETURN p

# ─────────────────────────────────────────────────
# POWERSHELL HISTORY
# ─────────────────────────────────────────────────

## PowerShell history with embedded credentials (self-edge)
MATCH p=(u:PHUser)-[:PHCanReadHistory]->(h:PHPSHistory)-[:PHContainsCreds]->(h)
RETURN p

## PowerShell history → credential login → admin
MATCH p=(u:PHUser)-[:PHCanReadHistory]->(h:PHPSHistory)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

## PowerShell history and transcript files
MATCH p=(u:PHUser)-[:PHCanReadHistory]->(h:PHPSHistory)
RETURN p

# ─────────────────────────────────────────────────
# SENSITIVE FILES
# ─────────────────────────────────────────────────

## Accessible sensitive files
MATCH p=(u:PHUser)-[:PHCanAccessFile]->(f:PHSensitiveFile)
RETURN p

## Sensitive files with embedded credentials (self-edge)
MATCH p=(u:PHUser)-[:PHCanAccessFile]->(f:PHSensitiveFile)-[:PHContainsCreds]->(f)
RETURN p

## Sensitive file → credential login → admin
MATCH p=(u:PHUser)-[:PHCanAccessFile]->(f:PHSensitiveFile)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# UAC BYPASS
# ─────────────────────────────────────────────────

## UAC bypass opportunities → admin
MATCH p=(u:PHUser)-[:PHCanBypassUAC]->(uac:PHUACBypass)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# CROSS-PLATFORM: Link to existing BloodHound AD data
# ─────────────────────────────────────────────────

## Find AD users that have local privesc paths
## (requires both SharpHound and PrivHound data)
MATCH (adUser:User)-[:HasSession]->(comp:Computer)
WHERE comp.name CONTAINS toUpper(
  [(ep:PHEndpoint) | ep.hostname][0]
)
MATCH p2=(phu:PHUser)-[*1..5]->(target:PHPrivTarget)
RETURN adUser.name AS ADUser, p2

## Endpoints with PrivHound findings + AD context
MATCH (ep:PHEndpoint)
OPTIONAL MATCH (comp:Computer) WHERE comp.name CONTAINS toUpper(ep.hostname)
RETURN ep.hostname AS Host, ep.os AS OS, comp.name AS ADComputer

# ─────────────────────────────────────────────────
# JIT ADMIN (MakeMeAdmin, CyberArk EPM, etc.)
# ─────────────────────────────────────────────────

## JIT admin tool → temporary admin
MATCH p=(u:PHUser)-[:PHCanRequestJIT]->(jit:PHJITAdminTool)-[:PHGrantsTempAdmin]->(t:PHPrivTarget)
RETURN p

## List JIT admin tools
MATCH p=(u:PHUser)-[:PHCanRequestJIT]->(jit:PHJITAdminTool)
RETURN p

# ─────────────────────────────────────────────────
# PRINT SPOOLER / PRINTNIGHTMARE
# ─────────────────────────────────────────────────

## Print Spooler exploitation → SYSTEM
MATCH p=(u:PHUser)-[:PHCanExploitSpooler]->(ps:PHPrintSpooler)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# WSUS HTTP (NON-SSL)
# ─────────────────────────────────────────────────

## WSUS HTTP MITM → SYSTEM
MATCH p=(u:PHUser)-[:PHCanExploitWSUS]->(ws:PHWSUSConfig)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# SCCM/MECM NAA CREDENTIALS
# ─────────────────────────────────────────────────

## SCCM NAA → credential pipeline → admin
MATCH p=(u:PHUser)-[:PHCanReadNAA]->(sccm:PHSCCMCredential)-[:PHContainsCreds]->(sccm)
RETURN p

## SCCM NAA → login → admin (full chain)
MATCH p=(u:PHUser)-[:PHCanReadNAA]->(sccm:PHSCCMCredential)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# COM OBJECT HIJACKING
# ─────────────────────────────────────────────────

## COM hijack → privileged execution
MATCH p=(u:PHUser)-[:PHCanHijackCOM]->(com:PHCOMHijack)-[:PHExecutesAs]->(t:PHPrivTarget)
RETURN p

## List hijackable COM objects
MATCH p=(u:PHUser)-[:PHCanHijackCOM]->(com:PHCOMHijack)
RETURN p

# ─────────────────────────────────────────────────
# NAMED PIPE PERMISSIONS
# ─────────────────────────────────────────────────

## Named pipe impersonation → SYSTEM
MATCH p=(u:PHUser)-[:PHCanImpersonatePipe]->(pipe:PHNamedPipe)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## List accessible SYSTEM pipes
MATCH p=(u:PHUser)-[:PHCanImpersonatePipe]->(pipe:PHNamedPipe)
RETURN p

# ─────────────────────────────────────────────────
# CACHED CREDENTIALS
# ─────────────────────────────────────────────────

## Cached credential sources
MATCH p=(u:PHUser)-[:PHHasCachedCreds]->(cc:PHCachedCreds)
RETURN p

## Cached creds with embedded passwords → login → admin
MATCH p=(u:PHUser)-[:PHHasCachedCreds]->(cc:PHCachedCreds)-[:PHCanLoginAs]->(lu:PHLocalUser)-[:PHMemberOf]->(t:PHPrivTarget)
RETURN p

# ─────────────────────────────────────────────────
# WMI EVENT SUBSCRIPTIONS
# ─────────────────────────────────────────────────

## WMI subscription → SYSTEM
MATCH p=(u:PHUser)-[:PHCanModifyWMI]->(wmi:PHWMISubscription)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## List writable WMI consumers
MATCH p=(u:PHUser)-[:PHCanModifyWMI]->(wmi:PHWMISubscription)
RETURN p

# ─────────────────────────────────────────────────
# WEBCLIENT RELAY (NTLM RELAY TO LDAP)
# ─────────────────────────────────────────────────

## WebClient relay → SYSTEM
MATCH p=(u:PHUser)-[:PHCanRelayWebClient]->(wc:PHWebClientRelay)-[:PHEscalatesTo]->(t:PHPrivTarget)
RETURN p

## List WebClient relay opportunities
MATCH p=(u:PHUser)-[:PHCanRelayWebClient]->(wc:PHWebClientRelay)
RETURN p

# ─────────────────────────────────────────────────
# SERVICE RECOVERY ACTIONS
# ─────────────────────────────────────────────────

## Writable service recovery command → SYSTEM
MATCH p=(u:PHUser)-[:PHCanWriteRecoveryBin]->(s:PHService)-[:PHRunsAs]->(t:PHPrivTarget)
RETURN p

## List services with writable recovery binaries
MATCH p=(u:PHUser)-[:PHCanWriteRecoveryBin]->(s:PHService)
RETURN p

# ─────────────────────────────────────────────────
# SHADOW COPY FILES
# ─────────────────────────────────────────────────

## Shadow copy → sensitive files
MATCH p=(u:PHUser)-[:PHCanAccessShadowCopy]->(sc:PHShadowCopy)-[:PHContainsSensitiveFile]->(f:PHSensitiveFile)
RETURN p

## Shadow copy → SAM/SYSTEM → hash extraction → admin
MATCH p=(u:PHUser)-[:PHCanAccessShadowCopy]->(sc:PHShadowCopy)-[:PHContainsSensitiveFile]->(f:PHSensitiveFile)-[:PHCanExtractHashes]->(t:PHPrivTarget)
RETURN p

## List accessible shadow copies
MATCH p=(u:PHUser)-[:PHCanAccessShadowCopy]->(sc:PHShadowCopy)
RETURN p

# ─────────────────────────────────────────────────
# COMPLEX MULTI-HOP PATHS
# ─────────────────────────────────────────────────

## Any credential source → login → admin (unified)
MATCH p=(u:PHUser)-[*1..7]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) IN ["PHCanLoginAs","PHCanLoginViaRunas"])
RETURN p

## Combined: all shortest paths to SYSTEM or Admin
MATCH p=shortestPath((u:PHUser)-[*1..8]->(t:PHPrivTarget))
RETURN p

## Cross-domain: PrivHound + BloodHound AD overlay (enhanced)
MATCH (adUser:User)-[:HasSession]->(comp:Computer)
MATCH (ep:PHEndpoint) WHERE comp.name CONTAINS toUpper(ep.hostname)
MATCH p2=(phu:PHUser)-[*1..6]->(target:PHPrivTarget)
RETURN adUser.name AS ADUser, target.account AS EscTarget, length(p2) AS Hops, p2

# ─────────────────────────────────────────────────
# CROSS-USER PRIVILEGE ESCALATION
# ─────────────────────────────────────────────────

## Cross-user: credential → discovered user → service → SYSTEM
MATCH p=(u:PHUser)-[*1..8]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
  AND any(r IN relationships(p) WHERE type(r) IN ["PHCanWriteBinary","PHCanModifyService","PHCanHijackPath"])
RETURN p

## Discovered user privileges (edges with discovered_via property)
MATCH (lu:PHLocalUser)-[r]->(n)
WHERE r.discovered_via = "credential"
RETURN lu, type(r) AS EdgeType, n

## Cross-user: discovered user → writable task binary → SYSTEM
MATCH p=(u:PHUser)-[*1..8]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
  AND any(r IN relationships(p) WHERE type(r) = "PHCanWriteTaskBinary" AND r.discovered_via = "credential")
RETURN p

## Cross-user: discovered user → dangerous token privilege → SYSTEM
MATCH p=(u:PHUser)-[*1..8]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
  AND any(r IN relationships(p) WHERE type(r) = "PHHasPrivilege" AND r.discovered_via = "credential")
RETURN p

## Cross-user: discovered user → writable recovery binary → SYSTEM
MATCH p=(u:PHUser)-[*1..8]->(t:PHPrivTarget)
WHERE any(r IN relationships(p) WHERE type(r) = "PHCanLoginAs")
  AND any(r IN relationships(p) WHERE type(r) = "PHCanWriteRecoveryBin" AND r.discovered_via = "credential")
RETURN p

## Full multi-hop: any credential chain → any escalation
MATCH p=shortestPath((u:PHUser)-[*1..10]->(t:PHPrivTarget))
WHERE length(p) > 2
RETURN p

# ─────────────────────────────────────────────────
# SUMMARY & STATISTICS (Use Neo4j browser)
# ─────────────────────────────────────────────────

## Count findings by type
MATCH (u:PHUser)-[r]->(n)
WHERE type(r) STARTS WITH "PHCan" OR type(r) STARTS WITH "PHHas"
RETURN type(r) AS FindingType, count(*) AS Count
ORDER BY Count DESC

## All PrivHound node kinds
MATCH (n) WHERE any(k IN labels(n) WHERE k STARTS WITH "PH")
RETURN labels(n) AS Kind, count(*) AS Count
ORDER BY Count DESC

## All PrivHound edge types
MATCH ()-[r]->() WHERE type(r) STARTS WITH "PH"
RETURN type(r) AS EdgeType, count(*) AS Count
ORDER BY Count DESC
