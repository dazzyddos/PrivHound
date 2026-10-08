<#
.SYNOPSIS
    Registers PrivHound custom node icons in BloodHound CE.
.DESCRIPTION
    Updates existing types with PUT and creates missing types with POST.
    Does not use the deprecated custom-node DELETE endpoint.
.PARAMETER BHUrl
    BloodHound base URL. Default: http://localhost:8080
.PARAMETER Token
    JWT bearer token for BloodHound API authentication.
.PARAMETER JsonPath
    Custom-node JSON path. Default: ..\privhound_customnodes.json
.EXAMPLE
    .\Upload-CustomNodes.ps1 -Token "eyJhbG..."
#>
param(
    [Parameter(Mandatory)][string]$Token,
    [string]$BHUrl = "http://localhost:8080",
    [string]$JsonPath = (Join-Path $PSScriptRoot "..\privhound_customnodes.json")
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
    throw "Custom nodes JSON not found: $JsonPath. Generate it with -OutputFormat BloodHound-customnodes."
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.Headers.Add("Authorization", "Bearer $Token")
$baseApi = "$($BHUrl.TrimEnd('/'))/api/v2/custom-nodes"

try {
    $response = Invoke-RestMethod $baseApi -WebSession $session
} catch {
    throw "Failed to retrieve BloodHound custom node types: $_"
}

try { $definition = Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
catch { throw "Could not parse custom-node JSON: $_" }
$customTypes = $definition.custom_types
if (-not $customTypes) { throw "No custom_types found in $JsonPath." }

$existingNames = @($response.data | ForEach-Object { $_.kindName } | Where-Object { $_ })
$newTypes = @{}
$updatedCount = 0
foreach ($property in $customTypes.PSObject.Properties) {
    $name = $property.Name
    if ($name -notin $existingNames) {
        $newTypes[$name] = $property.Value
        continue
    }

    $encodedName = [Uri]::EscapeDataString($name)
    $body = @{ config = $property.Value } | ConvertTo-Json -Depth 8 -Compress
    try {
        Invoke-RestMethod "$baseApi/$encodedName" -Method PUT -WebSession $session `
            -ContentType "application/json" -Body $body | Out-Null
        $updatedCount++
    } catch {
        throw "Failed to update custom node type '$name': $_"
    }
}

$createdCount = 0
if ($newTypes.Count -gt 0) {
    $body = @{ custom_types = $newTypes } | ConvertTo-Json -Depth 8 -Compress
    try {
        Invoke-RestMethod $baseApi -Method POST -WebSession $session `
            -ContentType "application/json" -Body $body | Out-Null
        $createdCount = $newTypes.Count
    } catch {
        throw "Failed to create custom node types: $_"
    }
}

Write-Host "  [+] Created $createdCount and updated $updatedCount custom node type(s)!" -ForegroundColor Green
Write-Host "  [i] Hard-refresh your browser (Ctrl+Shift+R) to see the icons." -ForegroundColor Cyan
