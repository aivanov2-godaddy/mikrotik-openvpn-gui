[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^https?://")]
    [string]$BaseUri,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$ExpectedRevision
)

$ErrorActionPreference = "Stop"
$healthUri = $BaseUri.TrimEnd("/") + "/readyz"
$response = Invoke-WebRequest -Uri $healthUri -Method Get -TimeoutSec 10 -MaximumRedirection 0 -UseBasicParsing

if ($response.StatusCode -ne 200) {
    throw "Health check returned HTTP $($response.StatusCode)."
}

$payload = $response.Content | ConvertFrom-Json
if ($payload.status -ne "ready") {
    throw "Health check did not return the expected status payload."
}
if ($payload.revision -cne $ExpectedRevision) {
    throw "Readiness revision does not match the approved release."
}

Write-Host "Readiness check passed for revision $ExpectedRevision at $healthUri"
