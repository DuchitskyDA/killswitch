# Живые сценарии WFP на одноразовом раннере windows-2025 (ci.yml, live-windows). Итог — строки RESULT S<n>.<id>;
# любой FAIL — исключение в конце. Сценарии — «Живые сценарии» эпика 1–9 и 10 (восстановление после чужого снятия).
. "$PSScriptRoot\lib.ps1"
"| id | итог | деталь |`n|---|---|---|" | Add-Content $env:GITHUB_STEP_SUMMARY
$nic = $env:KS_NIC
$resolver = $env:KS_RESOLVER
Write-Host "физический интерфейс: $nic, резолвер DHCP: $resolver"
Write-Config
$tg = Start-Process python -ArgumentList "$PSScriptRoot\..\targets.py", '127.0.0.2', '1500', '18080' -PassThru -NoNewWindow `
    -RedirectStandardOutput "$env:KS\targets.log" -RedirectStandardError "$env:KS\targets.err.log"

Write-Host '== S2: on, туннель опущен'
Expect-Code 'S2.on' 0 { & $KsExe on }
Expect-Code 'S2.status' 0 { & $KsExe status }
Expect-Probe 'S2.untrusted-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Probe 'S2.trusted-passes' $true 'probe-allowed' 'http://1.1.1.1/'
& "$env:KS\live.test.exe" '-test.run=^(TestLiveEvidence|TestLiveCollectionRestored)$' '-test.v'
Check 'S2.evidence' ($LASTEXITCODE -eq 0) "live.test TestLiveEvidence (отброс нашим фильтром): код $LASTEXITCODE"
$srv = Start-Process python -ArgumentList '-m', 'http.server', '8765', '--bind', '127.0.0.1' -PassThru -WindowStyle Hidden
Wait-For 20 { Curl-Ok 'probe-allowed' 'http://127.0.0.1:8765/' } | Out-Null
Expect-Probe 'S1.loopback' $true 'probe-denied' 'http://127.0.0.1:8765/'
Stop-Process $srv -ErrorAction SilentlyContinue
Install-Service

Write-Host '== S1: on, туннель поднят (адаптер появился после on — перепланирует служба)'
$up = Start-Tunnel 'ks-tun1'
$s = Wait-For 75 { Curl-Ok 'probe-denied' 'http://1.1.1.1/' }
Check 'S1.tunnel-exit' ($s -ge 0) "недоверенный curl → 1.1.1.1 через ks-tun1: через $s с (адаптер за $up с)"
Expect-Probe 'S1.direct-blocked' $false 'probe-denied' 'http://1.0.0.1/'
Check 'S1.direct-bound-blocked' (Probe-Blocked 'probe-denied' 'http' '1.1.1.1' $nic) "ksprobe http 1.1.1.1 с привязкой к $nic"
if (Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object InterfaceAlias -NotLike 'ks-tun*') {
    Expect-Probe 'S1.direct-v6-blocked' $false 'probe-denied' 'http://[2606:4700:4700::1111]/'
} else {
    Result 'S1.direct-v6-blocked' 'NOT_TESTED' 'на раннере нет маршрута ::/0'
}
$nat = Get-NetAdapter -Name 'vEthernet (nat)' -ErrorAction SilentlyContinue
if ($nat) {
    # Второй «физический» адаптер раннера — Hyper-V NAT без маршрута к цели: пробы через него без ответа и без
    # отброса (INCONCLUSIVE). Факт фиксируется, затем адаптер выключается на одноразовой ВМ для проверки кода 0.
    $out = & $KsExe check 2>&1 | Out-String; $code = $LASTEXITCODE; Write-Host $out
    Result 'S9.check-with-nat-adapter' 'INFO' "check при vEthernet (nat): код $code"
    Disable-NetAdapter -Name 'vEthernet (nat)' -Confirm:$false
}
Expect-Code 'S9.check-tunnel-up' 0 { & $KsExe check }

Write-Host '== S3: LAN и DNS'
& "$env:KS\wfptool.exe" collect # после live.test: TestLiveCollectionRestored выключает сбор событий
Check 'S3.dns-dhcp-open' (Probe-Ok 'probe-denied' 'dns-udp' $resolver $nic) "open: DNS к резолверу DHCP $resolver через $nic отвечает"
Check 'S3.dns-other-blocked' (Probe-Blocked 'probe-denied' 'dns-udp' '8.8.8.8' $nic) 'open: DNS к 8.8.8.8 через физику закрыт'
$t0 = (Get-Date).ToUniversalTime().ToString('o')
Probe-Ok 'probe-denied' 'udp-echo' '192.168.77.2' | Out-Null
& "$env:KS\wfptool.exe" drops 192.168.77.2 $t0
Check 'S3.lan-open' ($LASTEXITCODE -eq 1) "LAN=true: к 192.168.77.2 нашего отброса нет (drops код $LASTEXITCODE)"
Write-Config -Lan $false
Expect-Code 'S3.on-lan-false' 0 { & $KsExe on }
$t0 = (Get-Date).ToUniversalTime().ToString('o')
Probe-Ok 'probe-denied' 'udp-echo' '192.168.77.2' | Out-Null
& "$env:KS\wfptool.exe" drops 192.168.77.2 $t0
Check 'S3.lan-closed' ($LASTEXITCODE -eq 0) "LAN=false: к 192.168.77.2 отброс нашим block (drops код $LASTEXITCODE)"
Write-Config -Dns 'tunnel-up'
Expect-Code 'S3.on-tunnel-up' 0 { & $KsExe on }
Restart-Service killswitch # свежий шаг enforce с политикой tunnel-up: проверка здоровья раз в 5 с
$s = Wait-For 60 { Probe-Blocked 'probe-denied' 'dns-udp' $resolver $nic }
Check 'S3.dns-up-closed' ($s -ge 0) "tunnel-up, туннель здоров: DNS к $resolver через $nic закрыт через $s с"
Expect-Code 'S3.status-up' 0 { & $KsExe status }
Stop-Tunnel
$s = Wait-For 60 { Probe-Ok 'probe-denied' 'dns-udp' $resolver $nic }
Check 'S3.dns-down-open' ($s -ge 0) "tunnel-up, туннель снят: DNS к $resolver снова открыт через $s с"
Write-Config
Expect-Code 'S3.on-open' 0 { & $KsExe on }

Write-Host '== S4: переподключение с новым адаптером'
Start-Tunnel 'ks-tun2' | Out-Null
$s = Wait-For 60 { Curl-Ok 'probe-denied' 'http://1.1.1.1/' }
Check 'S4.first' ($s -ge 0) "выход через ks-tun2: через $s с"
Stop-Tunnel
$leaks = 0; $tries = 0
$adapterUp = Start-Tunnel 'ks-tun3'
$end = (Get-Date).AddSeconds(60); $back = -1; $t = Get-Date
while ((Get-Date) -lt $end) {
    $tries++
    if (Curl-Ok 'probe-denied' 'http://1.0.0.1/') { $leaks++ }
    if (-not (Probe-Blocked 'probe-denied' 'http' '1.1.1.1' $nic)) { $leaks++ }
    if (Curl-Ok 'probe-denied' 'http://1.1.1.1/') { $back = [int]((Get-Date) - $t).TotalSeconds; break }
}
Check 'S4.reconnect' ($back -ge 0) "выход через новый адаптер ks-tun3 вернулся через $back с после старта (адаптер за $adapterUp с)"
Check 'S4.no-leak-window' ($leaks -eq 0) "прямых проб в окне: $tries циклов, утечек $leaks"
Stop-Tunnel

Write-Host '== S6, S5: off и repair'
Expect-Code 'S6.off' 0 { & $KsExe off }
Expect-Output 'S6.status-off' 'режим=off' { & $KsExe status }
Expect-Probe 'S6.untrusted-passes' $true 'probe-denied' 'http://1.1.1.1/'
Expect-Code 'S5.repair' 0 { & $KsExe repair }
Expect-Output 'S5.status-repair' 'режим=repair' { & $KsExe status }
Expect-Probe 'S5.listed-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Probe 'S5.other-passes' $true 'probe-other' 'http://1.1.1.1/'
Expect-Code 'S6.on-again' 0 { & $KsExe on }
Expect-Probe 'S6.on-again-blocked' $false 'probe-other' 'http://1.1.1.1/'

Write-Host '== S7: перезапуск службы до старта клиента'
Restart-Service killswitch
Expect-Code 'S7.cli-during-service-step' 0 { & $KsExe on } # команда сразу после старта службы ждёт её замок
Stop-Service killswitch -Force
Expect-Probe 'S7.service-stopped-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Start-Service killswitch
Start-Sleep 5
Expect-Output 'S7.service-running' 'Running' { (Get-Service killswitch).Status }
Expect-Output 'S7.status-on' 'режим=on' { & $KsExe status }
Expect-Probe 'S7.service-started-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Code 'S7.bootkeys' 0 { & "$env:KS\live.test.exe" '-test.run=^TestLiveBootKeys$' '-test.v' }
Expect-Output 'S7.boottime-netsh' 'ours=12' { Count-BootKeys 'on' }

Write-Host '== S9, S10: правила сняты вручную'
Stop-Service killswitch -Force
Expect-Code 'S9.strip' 0 { & "$env:KS\wfptool.exe" strip }
Expect-Code 'S9.check-stripped' 4 { & $KsExe check }
Expect-Code 'S9.status-stripped' 4 { & $KsExe status }
Expect-Probe 'S9.leak-real' $true 'probe-denied' 'http://1.1.1.1/'
Start-Service killswitch
$s = Wait-For 70 { -not (Curl-Ok 'probe-denied' 'http://1.1.1.1/') }
Check 'S10.restored' ($s -ge 0) "служба восстановила защиту через $s с"
Expect-Code 'S10.status-restored' 0 { & $KsExe status }

Write-Host '== S9: ничья 0xFFFF — чужой sublayer раньше нашего'
Stop-Service killswitch -Force
Expect-Code 'S9.tie-uninstall' 0 { & $KsExe uninstall }
Remove-Item "$env:KS\tie.ready", "$env:KS\tie.stop" -ErrorAction SilentlyContinue
$tie = Start-Process "$env:KS\wfptool.exe" -ArgumentList 'tie', "$env:KS\tie.ready", "$env:KS\tie.stop", '180' -PassThru -NoNewWindow
$s = Wait-For 20 { Test-Path "$env:KS\tie.ready" }
Check 'S9.tie-foreign' ($s -ge 0) "чужой sublayer создан через $s с"
Expect-Code 'S9.tie-on' 0 { & $KsExe on }
Expect-Code 'S9.tie-status' 4 { & $KsExe status }
Expect-Code 'S9.tie-check' 4 { & $KsExe check }
New-Item "$env:KS\tie.stop" -ItemType File | Out-Null
$tie.WaitForExit(15000) | Out-Null
Expect-Code 'S9.tie-gone-status' 0 { & $KsExe status }

Write-Host '== S8: сломанное состояние и uninstall без конфига'
Start-Service killswitch
Start-Sleep 10 # первый шаг службы завершён (замок свободен)
Expect-Code 'S8.off' 0 { & $KsExe off }
Set-Content 'C:\ProgramData\killswitch\state.json' '{"gen": 7, "mode": "off", broken'
Restart-Service killswitch
$s = Wait-For 60 { -not (Curl-Ok 'probe-denied' 'http://1.1.1.1/') }
Check 'S8.corrupt-failclosed' ($s -ge 0) "state.json испорчен в off: служба вернула on через $s с"
Stop-Service killswitch -Force
foreach ($i in 1..5) {
    $verb = @('on', 'off')[$i % 2]
    $p = Start-Process $KsExe -ArgumentList $verb -PassThru -NoNewWindow
    Start-Sleep -Milliseconds (Get-Random -Minimum 20 -Maximum 400)
    Stop-Process $p -Force -ErrorAction SilentlyContinue
}
& $KsExe status | Write-Host
Set-Content 'C:\ProgramData\killswitch\state.json' 'not json'
Remove-Item $env:KS_CONFIG
sc.exe delete killswitch | Out-Null
Expect-Code 'S8.uninstall' 0 { & $InstalledExe uninstall }
Expect-Code 'S8.gone' 0 { & "$env:KS\live.test.exe" '-test.run=^TestLiveGone$' '-test.v' }
Expect-Output 'S8.boottime-netsh' 'ours=0' { Count-BootKeys 'gone' }
Expect-Probe 'S8.untrusted-passes' $true 'probe-denied' 'http://1.1.1.1/'
Stop-Process $tg -ErrorAction SilentlyContinue
Finish
