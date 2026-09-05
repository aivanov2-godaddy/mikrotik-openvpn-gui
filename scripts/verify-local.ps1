[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot

try {
    & $Python scripts/check-secrets.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $Python -m compileall -q app.py automation.py favicon.py icons.py qr.py routeros.py security.py store.py templates.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
