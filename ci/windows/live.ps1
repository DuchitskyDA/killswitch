# Живые сценарии WFP на одноразовом раннере windows-2025 (ci.yml, live-windows). Итог — строки RESULT; любой FAIL — исключение.
. "$PSScriptRoot\lib.ps1"
"| id | итог | деталь |`n|---|---|---|" | Add-Content $env:GITHUB_STEP_SUMMARY

Write-Host '== on'
Expect-Code 'S1.on' 0 { & $KsExe on }
Expect-Code 'S1.status' 0 { & $KsExe status }
Expect-Probe 'S2.denied-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Probe 'S2.trusted-passes' $true 'probe-allowed' 'http://1.1.1.1/'
$srv = Start-Process python -ArgumentList '-m', 'http.server', '8765', '--bind', '127.0.0.1' -PassThru -WindowStyle Hidden
Start-Sleep 3
Expect-Probe 'S1.loopback' $true 'probe-denied' 'http://127.0.0.1:8765/'
Stop-Process $srv -ErrorAction SilentlyContinue
& "$env:KS\live.test.exe" '-test.run=^(TestLiveEvidence|TestLiveCollectionRestored)$' '-test.v'
Check 'S2.evidence' ($LASTEXITCODE -eq 0) "live.test TestLiveEvidence: $LASTEXITCODE"

Write-Host '== off, repair'
Expect-Code 'S6.off' 0 { & $KsExe off }
Expect-Output 'S6.status-off' 'режим=off' { & $KsExe status }
Expect-Probe 'S6.denied-passes' $true 'probe-denied' 'http://1.1.1.1/'
Expect-Code 'S5.repair' 0 { & $KsExe repair }
Expect-Output 'S5.status-repair' 'режим=repair' { & $KsExe status }
Expect-Probe 'S5.listed-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Probe 'S5.other-passes' $true 'probe-other' 'http://1.1.1.1/'
Expect-Code 'S6.on-again' 0 { & $KsExe on }
Expect-Probe 'S6.on-again-blocked' $false 'probe-other' 'http://1.1.1.1/'

Write-Host '== check без туннеля и целей'
Expect-Code 'S9.check-no-targets' 5 { & $KsExe check }

Write-Host '== служба enforce'
Install-Service
Restart-Service killswitch
Start-Sleep 5
Expect-Output 'S7.service-running' 'Running' { (Get-Service killswitch).Status }
Expect-Output 'S7.status-on' 'режим=on' { & $InstalledExe status }
Expect-Probe 'S7.denied-blocked' $false 'probe-denied' 'http://1.1.1.1/'
Expect-Code 'S7.bootkeys' 0 { & "$env:KS\live.test.exe" '-test.run=^TestLiveBootKeys$' '-test.v' }
Expect-Output 'S7.boottime-netsh' 'ours=12' { Count-BootKeys 'on' }

Write-Host '== uninstall без конфига'
Stop-Service killswitch -Force
sc.exe delete killswitch | Out-Null
Remove-Item $env:KS_CONFIG
Expect-Code 'S8.uninstall' 0 { & $InstalledExe uninstall }
Expect-Code 'S8.gone' 0 { & "$env:KS\live.test.exe" '-test.run=^TestLiveGone$' '-test.v' }
Expect-Probe 'S8.denied-passes' $true 'probe-denied' 'http://1.1.1.1/'
Expect-Output 'S8.boottime-netsh' 'ours=0' { Count-BootKeys 'gone' }
Finish
