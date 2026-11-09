# Общее для живых сценариев WFP (ci.yml, live-windows). Только на одноразовом раннере windows-2025.
[Console]::OutputEncoding = [Text.Encoding]::UTF8
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'живые сценарии WFP — только на раннере GitHub'
}
$KsExe = "$env:KS\killswitch.exe"
$InstalledExe = "$env:ProgramFiles\killswitch\killswitch.exe"
$Results = "$env:KS\results.txt"
$script:Fails = 0

function Result($id, $st, $detail) {
    if ($st -eq 'FAIL') { $script:Fails++ }
    $line = "RESULT $id $st $detail"
    Write-Host $line
    Add-Content -Path $Results -Value $line
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "| $id | $st | $($detail -replace '\|', '/') |"
}
function Check($id, $ok, $detail) { if ($ok) { Result $id 'PASS' $detail } else { Result $id 'FAIL' $detail } }

function Expect-Code($id, $want, [scriptblock]$cmd) {
    $out = & $cmd 2>&1 | Out-String
    $code = $LASTEXITCODE
    Write-Host $out
    Check $id ($code -eq $want) "code=$code want=$want"
}
function Expect-Output($id, $pattern, [scriptblock]$cmd) {
    $out = & $cmd 2>&1 | Out-String
    Write-Host $out
    Check $id ($out.Contains($pattern)) "want '$pattern'"
}
# curl из каталога-пробы (своя копия — свой app-id): $true — сервер ответил.
function Curl-Ok($dir, $url) {
    & "$env:KS\$dir\curl.exe" -s -o NUL -m 6 $url 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function Expect-Probe($id, $wantOk, $dir, $url) {
    $ok = Curl-Ok $dir $url
    Check $id ($ok -eq $wantOk) "curl $dir $url ok=$ok want-ok=$wantOk"
}
# Ждать до $limit с, пока блок не вернёт $true; секунды или -1.
function Wait-For($limit, [scriptblock]$cond) {
    for ($s = 0; $s -le $limit; $s += 2) {
        if (& $cond) { return $s }
        Start-Sleep 2
    }
    return -1
}
# Boot-time-политика в netsh — без имён: считаем наши фильтры по ключам из KS_BOOTKEYS.
function Count-BootKeys($tag) {
    netsh wfp show boottimepolicy file="$env:KS\boottime-$tag.xml" | Out-Null
    $xml = (Get-Content "$env:KS\boottime-$tag.xml" -Raw).ToLower()
    $n = @(Get-Content $env:KS_BOOTKEYS | Where-Object { $_ -and $xml.Contains($_) }).Count
    "ours=$n"
}
# Служба enforce — как её регистрирует установка (имя, ImagePath, перезапуск при сбое).
function Install-Service {
    New-Item -ItemType Directory -Force "$env:ProgramFiles\killswitch" | Out-Null
    Copy-Item $KsExe $InstalledExe -Force
    if (-not (Get-Service killswitch -ErrorAction SilentlyContinue)) {
        New-Service -Name killswitch -BinaryPathName "`"$InstalledExe`" enforce" -DisplayName 'killswitch' -StartupType Automatic | Out-Null
        sc.exe failure killswitch reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    }
    Start-Service killswitch
}
function Finish {
    if ($script:Fails -gt 0) { throw "FAIL: $script:Fails" }
    $global:LASTEXITCODE = 0 # ожидаемо упавшая проба не должна ронять шаг
}
