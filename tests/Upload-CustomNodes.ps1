<#
.SYNOPSIS
    Uploads PrivHound custom node icons to BloodHound CE.
.DESCRIPTION
    Deletes any existing PH* custom node types and re-creates them via POST.
    Handles the 409 Conflict issue when types already exist.
.PARAMETER BHUrl
    BloodHound CE base URL. Default: http://localhost:8080
.PARAMETER Token
    JWT bearer token for BH CE API authentication.
.PARAMETER JsonPath
    Path to privhound_customnodes.json. Default: ..\privhound_customnodes.json
.EXAMPLE
    .\Upload-CustomNodes.ps1 -Token "eyJhbG..."
    .\Upload-CustomNodes.ps1 -BHUrl "http://192.168.1.50:8080" -Token "eyJhbG..."
#>
param(
    [Parameter(Mandatory)][string]$Token,
    [string]$BHUrl = "http://localhost:8080",
    [string]$JsonPath = (Join-Path $PSScriptRoot "..\privhound_customnodes.json")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $JsonPath)) {
    Write-Host "  [!] Custom nodes JSON not found: $JsonPath" -ForegroundColor Red
    Write-Host "      Run: .\PrivHound.ps1 -OutputFormat BloodHound-customnodes" -ForegroundColor Yellow
    exit 1
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.Headers.Add("Authorization", "Bearer $Token")
$baseApi = "$BHUrl/api/v2/custom-nodes"

# --- Get existing custom nodes ---
Write-Host "`n  PrivHound Custom Node Uploader" -ForegroundColor Cyan
Write-Host "  Target: $BHUrl`n"

try {
    $response = Invoke-RestMethod $baseApi -WebSession $session
} catch {
    Write-Host "  [!] Failed to connect to BH CE API: $_" -ForegroundColor Red
    Write-Host "      Check your -BHUrl and -Token values." -ForegroundColor Yellow
    exit 1
}

# --- Extract type names from GET response (.data[].kindName) ---
$typeNames = @($response.data | ForEach-Object { $_.kindName } | Where-Object { $_ })

Write-Host "  [i] Found $($typeNames.Count) existing custom type(s)"

# --- Delete existing PH* types ---
$phTypes = @($typeNames | Where-Object { $_ -like "PH*" })
if ($phTypes.Count -gt 0) {
    Write-Host "  [i] Deleting $($phTypes.Count) existing PH* custom type(s)..."
    foreach ($name in $phTypes) {
        try {
            Invoke-RestMethod "$baseApi/$name" -Method DELETE -WebSession $session | Out-Null
            Write-Host "      Deleted $name" -ForegroundColor DarkGray
        } catch {
            Write-Host "      [!] Failed to delete $name`: $_" -ForegroundColor Yellow
        }
    }
    Write-Host "  [+] Cleanup complete." -ForegroundColor Green
} else {
    Write-Host "  [i] No existing PH* types to delete."
}

# --- POST new custom nodes ---
Write-Host "  [i] Uploading custom node icons..."
$body = Get-Content $JsonPath -Raw -Encoding UTF8
try {
    Invoke-RestMethod $baseApi -Method POST -WebSession $session `
        -ContentType "application/json" -Body $body | Out-Null
    $count = ((ConvertFrom-Json $body).custom_types.PSObject.Properties | ForEach-Object { $_.Value }).Count
    Write-Host "  [+] Successfully registered $count custom node type(s)!" -ForegroundColor Green
    Write-Host "  [i] Hard-refresh your browser (Ctrl+Shift+R) to see the icons.`n" -ForegroundColor Cyan
} catch {
    Write-Host "  [!] POST failed: $_" -ForegroundColor Red
    exit 1
}
