# Periodic snapshot: commits local changes and pushes them to origin.
# Guarded so an idle run is a no-op. Intended to be called by an automation.
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot\..
$log = Join-Path (Get-Location) '.git\autocommit.log'
function Write-Log($msg) {
    $line = "$(Get-Date -Format o) $msg"
    Add-Content -Path $log -Value $line -ErrorAction SilentlyContinue
}
try {
    $changes = git status --porcelain
    if (-not $changes) {
        Write-Log 'no changes'
        return
    }
    git add -A
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
    git commit -m "auto: periodic snapshot $stamp" | Out-Null
    git push origin main | Out-Null
    Write-Log 'committed and pushed'
} catch {
    Write-Log "error: $($_.Exception.Message)"
}
