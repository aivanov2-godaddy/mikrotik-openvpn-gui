[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^https?://")]
    [string]$BaseUri
)

$ErrorActionPreference = "Stop"
$healthUri = $BaseUri.TrimEnd("/") + "/healthz"
$response = Invoke-WebRequest -Uri $healthUri -Method Get -TimeoutSec 10 -MaximumRedirection 0 -UseBasicParsing

if ($response.StatusCode -ne 200) {
    throw "Health check returned HTTP $($response.StatusCode)."
}

$payload = $response.Content | ConvertFrom-Json
if ($payload.status -ne "ok") {
    throw "Health check did not return the expected status payload."
}

Write-Host "Health check passed: $healthUri"
