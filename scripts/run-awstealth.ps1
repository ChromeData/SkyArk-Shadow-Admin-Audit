<#
  Thin wrapper around AWStealth (cyberark/SkyArk). SkyArk is upstream MIT-licensed
  work; this script only invokes it and drops the output where score.py expects it.

  Prereqs: pwsh 7+, an AWS read-only credential for the lab account exported as
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, and `make clone-skyark` already run.
#>

$ErrorActionPreference = "Stop"
$labRoot = Split-Path -Parent $PSScriptRoot
$skyark  = Join-Path $labRoot "vendor/SkyArk/AWStealth/AWStealth.ps1"

if (-not (Test-Path $skyark)) {
    throw "AWStealth not found at $skyark. Run 'make clone-skyark' first."
}

Write-Host "==> Importing AWStealth (upstream cyberark/SkyArk)"
. $skyark

# AWStealth reads AWS creds from the standard SDK chain. Use a READ-ONLY key for
# the scan — the whole point is that discovery does not need write access.
Write-Host "==> Scanning. This enumerates IAM; it does not modify anything."
$outDir = Join-Path $labRoot "findings"
Scan-AWShadowAdmins -OutputFolder $outDir

# Normalise the filename SkyArk produces to what score.py looks for.
$latest = Get-ChildItem $outDir -Filter "*AWStealth*.csv" |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
    Copy-Item $latest.FullName (Join-Path $outDir "awstealth-raw.csv") -Force
    Write-Host "==> Wrote findings/awstealth-raw.csv"
} else {
    Write-Warning "No AWStealth CSV found — check the scan output above."
}
