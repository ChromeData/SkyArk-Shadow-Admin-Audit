<#
  Thin wrapper around AzureStealth (cyberark/SkyArk). Upstream MIT work; this only
  invokes it and normalises the output path for score.py.

  Prereqs: pwsh 7+, Az CLI logged in to the lab tenant (`az login`), and
  `make clone-skyark` already run. AzureStealth reads the Az context.
#>

$ErrorActionPreference = "Stop"
$labRoot = Split-Path -Parent $PSScriptRoot
$skyark  = Join-Path $labRoot "vendor/SkyArk/AzureStealth/AzureStealth.ps1"

if (-not (Test-Path $skyark)) {
    throw "AzureStealth not found at $skyark. Run 'make clone-skyark' first."
}

Write-Host "==> Confirm you are pointed at the LAB tenant, not anything real:"
az account show --query "{tenant:tenantId, sub:name}" -o table

Write-Host "==> Importing AzureStealth (upstream cyberark/SkyArk)"
. $skyark

Write-Host "==> Scanning directory + subscription role assignments (read-only)"
$outDir = Join-Path $labRoot "findings"
Scan-AzureAdmins -OutputFolder $outDir

$latest = Get-ChildItem $outDir -Filter "*AzureStealth*.csv" |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
    Copy-Item $latest.FullName (Join-Path $outDir "azurestealth-raw.csv") -Force
    Write-Host "==> Wrote findings/azurestealth-raw.csv"
} else {
    Write-Warning "No AzureStealth CSV found, check the scan output above."
}
