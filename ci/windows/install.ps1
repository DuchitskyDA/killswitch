# Установка killswitch.exe на одноразовом раннере windows-2025 (ci.yml, live-windows): отказ на каталоге настроек,
# в который может писать не администратор, и на ссылке вместо каталога; чистая установка без настроек (служба,
# ярлык, точные права каталогов, запись в «Приложения»), повторная установка с обновлением копии и полное удаление
# командой из «Приложений». Двойной клик без окна не повторить: killswitch.exe install — та же установка без окна.
. "$PSScriptRoot\lib.ps1"
$State = "$env:ProgramData\killswitch"
$InstallDir = "$env:ProgramFiles\killswitch"
$Shortcut = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'killswitch.lnk'
$AppKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\killswitch'
$Admins = 'S-1-5-32-544'

function Run-Ks([string]$Exe, [string[]]$KsArgs) {
    $script:KsOut = & $Exe @KsArgs 2>&1 | Out-String
    $script:KsCode = $LASTEXITCODE
    Write-Host $script:KsOut
}
function Service-Exists { [bool](Get-Service killswitch -ErrorAction SilentlyContinue) }
function App-Exists { Test-Path -LiteralPath $AppKey }
function Reset-State {
    if (Service-Exists) { Stop-Service killswitch -Force -ErrorAction SilentlyContinue; sc.exe delete killswitch | Out-Null }
    foreach ($dir in $State, $InstallDir) { if (Test-Path -LiteralPath $dir) { cmd /c rmdir /s /q "$dir" } }
    Remove-Item -LiteralPath $Shortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AppKey -Force -ErrorAction SilentlyContinue
}
# Права каталога точные: владелец — администраторы, наследование снято, записи только трёх групп.
function Acl-Exact($dir) {
    $acl = Get-Acl -LiteralPath $dir
    $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Write-Host "acl $dir owner=$owner protected=$($acl.AreAccessRulesProtected) sids=$($sids -join ',')"
    return ($owner -eq $Admins) -and $acl.AreAccessRulesProtected -and (($sids -join ',') -eq 'S-1-5-18,S-1-5-32-544,S-1-5-32-545')
}
function Same-Hash($a, $b) { (Get-FileHash -LiteralPath $a).Hash -eq (Get-FileHash -LiteralPath $b).Hash }

# I1: каталог настроек создан заранее с правами ProgramData (пользователи могут создавать в нём файлы) и с настройками.
Reset-State
New-Item -ItemType Directory -Force $State | Out-Null
Set-Content (Join-Path $State 'config.toml') "profile = 'wireguard'"
Run-Ks $KsExe @('install')
Check 'I1.refused' ($KsCode -ne 0 -and $KsOut.Contains('небезопасный каталог')) "code=$KsCode"
Check 'I1.no-service' (-not (Service-Exists)) 'служба не создана'
Check 'I1.no-app' (-not (App-Exists)) 'записи в «Приложениях» нет'

# I2: вместо каталога настроек — ссылка на чужой каталог.
Reset-State
$target = "$env:KS\junction-target"
New-Item -ItemType Directory -Force $target | Out-Null
New-Item -ItemType Junction -Path $State -Target $target | Out-Null
Run-Ks $KsExe @('install')
Check 'I2.refused' ($KsCode -ne 0 -and $KsOut.Contains('ссылка')) "code=$KsCode"
Check 'I2.target-untouched' (-not (Get-ChildItem -LiteralPath $target -Force)) 'в каталог по ссылке ничего не записано'
Check 'I2.no-service' (-not (Service-Exists)) 'служба не создана'
cmd /c rmdir "$State"

# I3: чистая установка без настроек.
Run-Ks $KsExe @('install')
Check 'I3.installed' ($KsCode -eq 0) "code=$KsCode"
Check 'I3.service-running' ((Get-Service killswitch -ErrorAction SilentlyContinue).Status -eq 'Running') 'служба killswitch запущена'
$svc = Get-CimInstance Win32_Service -Filter "Name='killswitch'"
Check 'I3.service-path' ($svc.PathName -eq "`"$InstalledExe`" enforce" -and $svc.StartMode -eq 'Auto') "PathName=$($svc.PathName) StartMode=$($svc.StartMode)"
$failure = sc.exe qfailure killswitch | Out-String
Write-Host $failure
Check 'I3.service-restart' (([regex]::Matches($failure, 'RESTART -- Delay = 5000')).Count -eq 3) 'перезапуск через 5 с трижды'
Check 'I3.exe' (Same-Hash $KsExe $InstalledExe) $InstalledExe
Check 'I3.shortcut' (Test-Path -LiteralPath $Shortcut) $Shortcut
if (Test-Path -LiteralPath $Shortcut) {
    $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($Shortcut)
    $runas = ([IO.File]::ReadAllBytes($Shortcut)[0x15] -band 0x20) -ne 0
    Check 'I3.shortcut-target' ($lnk.TargetPath -eq $InstalledExe -and $lnk.Arguments -eq 'window' -and $lnk.WindowStyle -eq 7 -and $runas) `
        "target=$($lnk.TargetPath) args=$($lnk.Arguments) style=$($lnk.WindowStyle) runas=$runas"
}
Check 'I3.acl-state' (Acl-Exact $State) $State
Check 'I3.acl-install' (Acl-Exact $InstallDir) $InstallDir
$app = Get-ItemProperty -LiteralPath $AppKey -ErrorAction SilentlyContinue
Write-Host ($app | Format-List | Out-String)
Check 'I3.app' ($app -and $app.DisplayName -eq 'killswitch' -and $app.UninstallString -eq "`"$InstalledExe`" uninstall" -and
    $app.InstallLocation -eq $InstallDir -and $app.DisplayIcon -eq $InstalledExe -and $app.DisplayVersion -and $app.Publisher -and
    $app.NoModify -eq 1 -and $app.NoRepair -eq 1) 'запись в «Приложениях» с командой удаления'

# I4: повторная установка поверх своей — каталоги доверенные, отказа нет; другая копия заменяется запущенной.
Run-Ks $KsExe @('install')
Check 'I4.reinstall' ($KsCode -eq 0) "code=$KsCode"
Check 'I4.acl-state' (Acl-Exact $State) $State
Stop-Service killswitch -Force
Copy-Item "$env:SystemRoot\System32\whoami.exe" $InstalledExe -Force
Run-Ks $KsExe @('install')
Check 'I4.update' ($KsCode -eq 0 -and (Same-Hash $KsExe $InstalledExe)) "code=$KsCode"
Check 'I4.service-running' ((Get-Service killswitch -ErrorAction SilentlyContinue).Status -eq 'Running') 'служба запущена после обновления'
Run-Ks $InstalledExe @('install')
Check 'I4.self' ($KsCode -eq 0) "установленная копия ставит сама себя: code=$KsCode"

# I5: удаление командой из «Приложений» дословно (как её запускает Windows) — запущен сам установленный exe.
$uninstall = (Get-ItemProperty -LiteralPath $AppKey).UninstallString
$psi = New-Object Diagnostics.ProcessStartInfo 'cmd.exe', "/d /s /c `"$uninstall`""
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$p = [Diagnostics.Process]::Start($psi)
$out = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
$p.WaitForExit()
Write-Host "$uninstall`n$out"
Check 'I5.uninstall' ($p.ExitCode -eq 0) "code=$($p.ExitCode)"
Check 'I5.no-service' (-not (Service-Exists)) 'служба удалена'
Check 'I5.no-shortcut' (-not (Test-Path -LiteralPath $Shortcut)) 'ярлык удалён'
Check 'I5.no-app' (-not (App-Exists)) 'записи в «Приложениях» нет'
$s = Wait-For 30 { -not (Test-Path -LiteralPath $InstallDir) }
Check 'I5.no-files' ($s -ge 0) "каталог установки удалён через $s с"
Check 'I5.settings-kept' (Test-Path -LiteralPath $State) 'настройки и журнал остаются'
Finish
