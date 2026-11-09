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
# ksprobe из каталога-пробы: $true — сервер ответил (код 0); [интерфейс] — привязка сокета к нему.
function Probe-Ok($dir, $svc, $ip, $iface = '') {
    $a = @($svc, $ip); if ($iface) { $a += $iface }
    & "$env:KS\$dir\ksprobe.exe" @a 2>&1 | Write-Host
    return ($LASTEXITCODE -eq 0)
}
# Закрыто: ksprobe не получил ответа (код 1); ошибка привязки или аргументов (2) — не «закрыто».
function Probe-Blocked($dir, $svc, $ip, $iface = '') {
    $a = @($svc, $ip); if ($iface) { $a += $iface }
    & "$env:KS\$dir\ksprobe.exe" @a 2>&1 | Write-Host
    return ($LASTEXITCODE -eq 1)
}

# Конфиг стенда: доверенные из trust.toml (раннер по app-id, sing-box, разрешённая проба) + переменная часть.
function Write-Config([bool]$Lan = $true, [string]$Dns = 'open') {
    $l = @("lan = $($Lan.ToString().ToLower())", '', '[tunnel]', "interfaces = ['ks-tun*']", '', '[dns]', "mode = '$Dns'")
    if ($Dns -eq 'tunnel-up') { $l += "health = 'http://203.0.113.10:80/'" }
    $l += @('', '[repair]', "programs = ['$env:KS\probe-denied\curl.exe']", '', '[check]', "targets = ['203.0.113.10']", '')
    ($l + (Get-Content "$env:KS\trust.toml")) | Set-Content $env:KS_CONFIG
}

# Туннель стенда — sing-box TUN без strict_route: 1.1.1.1 — настоящий выход через туннель (sing-box доверен),
# 203.0.113.10 → цели check и dns.health на 127.0.0.2 (HTTP — на 18080: порт 80 на loopback держит система), резолвер DHCP — чтобы системный DNS шёл через TUN.
function Start-Tunnel($name) {
    $cfg = [ordered]@{
        log       = @{ level = 'warn'; timestamp = $true }
        dns       = @{ servers = @(@{ type = 'udp'; tag = 'dns-udp'; server = $env:KS_RESOLVER; server_port = 53 }) }
        inbounds  = @(@{ type = 'tun'; tag = 'tun-in'; interface_name = $name; address = @('172.19.0.1/30'); auto_route = $true
                stack = 'gvisor'; route_address = @('1.1.1.1/32', '203.0.113.10/32', "$env:KS_RESOLVER/32") })
        outbounds = @(@{ type = 'direct'; tag = 'direct' })
        route     = [ordered]@{ rules = @(@{ action = 'sniff' }, @{ protocol = 'dns'; action = 'hijack-dns' },
                @{ ip_cidr = @('203.0.113.10/32'); port = 80; action = 'route-options'; override_port = 18080 },
                @{ ip_cidr = @('203.0.113.10/32'); action = 'route-options'; override_address = '127.0.0.2' })
            final = 'direct'; auto_detect_interface = $true }
    }
    $file = "$env:KS\sb-$name.json"
    $cfg | ConvertTo-Json -Depth 8 | Set-Content $file
    $script:Sb = Start-Process "$env:KS\sb\sing-box.exe" -ArgumentList 'run', '-c', $file -PassThru -NoNewWindow `
        -RedirectStandardOutput "$env:KS\sb-$name.out.log" -RedirectStandardError "$env:KS\sb-$name.log"
    $s = Wait-For 30 { (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue).Status -eq 'Up' }
    Write-Host "туннель $name поднят через $s с"
    return $s
}
function Stop-Tunnel {
    if ($script:Sb) { Stop-Process $script:Sb -Force -ErrorAction SilentlyContinue; $script:Sb = $null }
    Start-Sleep 2
    Get-NetAdapter -Name 'ks-tun*' -ErrorAction SilentlyContinue | Format-Table Name, Status, ifIndex -AutoSize | Out-String | Write-Host
}

function Finish {
    if ($script:Fails -gt 0) { throw "FAIL: $script:Fails" }
    $global:LASTEXITCODE = 0 # ожидаемо упавшая проба не должна ронять шаг
}
