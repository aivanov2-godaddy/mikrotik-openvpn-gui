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

    & $Python -m compileall -q app.py automation.py cloudflare.py deploy_routeros_canary.py deployment.py favicon.py icons.py install_routeros.py qr.py routeros.py security.py store.py templates.py update_routeros_app.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
