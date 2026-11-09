# Помощники шагов workflow spike-wfp. Подключается точкой: . spike/wfp/ci.ps1
$ErrorActionPreference = 'Continue'
$Exe = 'C:\ks\bin\wfpspike.exe'
$Allowed = 'C:\ks\bin\probe-allowed\wfpspike.exe'
$Denied = 'C:\ks\bin\probe-denied\wfpspike.exe'

function Result($id, $status, $detail) {
    $line = "RESULT $id $status $detail"
    Write-Host $line
    Add-Content -Path $env:KS_RESULTS -Value $line
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "| $id | $status | $($detail -replace '\|','/') |"
}

function Summary-Header($title) {
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "`n### $title`n`n| id | status | detail |`n|---|---|---|"
}

# Независимый watchdog: задача планировщика от SYSTEM снимает наше через N минут,
# даже если раннер убьёт дерево процессов шага.
function Arm-Watchdog($minutes) {
    $a = New-ScheduledTaskAction -Execute $Exe -Argument 'cleanup'
    $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($minutes)
    Register-ScheduledTask -TaskName ks-spike-watchdog -Action $a -Trigger $t -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest -Force | Out-Null
    Write-Host "watchdog: cleanup в $((Get-Date).AddMinutes($minutes).ToString('HH:mm:ss'))"
}

function Disarm-Watchdog {
    Unregister-ScheduledTask -TaskName ks-spike-watchdog -Confirm:$false -ErrorAction SilentlyContinue
}

function Probe($exe, $kind, $addr) {
    $out = & $exe probe $kind $addr 2>&1 | Out-String
    return [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Out = $out.Trim() }
}

function Expect($id, $wantOk, $p) {
    $st = if ($p.Ok -eq $wantOk) { 'PASS' } else { 'FAIL' }
    Result $id $st "ok=$($p.Ok) $($p.Out)"
}

function Count-InXml($file, $pattern) {
    if (-not (Test-Path $file)) { return -1 }
    return ([regex]::Matches((Get-Content $file -Raw), [regex]::Escape($pattern))).Count
}

function Snapshot-Netsh($tag) {
    netsh wfp show boottimepolicy file="C:\ks\boottime-$tag.xml" | Out-Null
    netsh wfp show filters file="C:\ks\filters-$tag.xml" | Out-Null
    $b = Count-InXml "C:\ks\boottime-$tag.xml" 'ks-spike/'
    $f = Count-InXml "C:\ks\filters-$tag.xml" 'ks-spike/'
    Write-Host "netsh $tag : boottimepolicy ks-spike=$b, filters ks-spike=$f"
    return [pscustomobject]@{ Boot = $b; Filters = $f }
}
