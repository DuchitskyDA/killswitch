# killswitch для Windows: меню и ярлык поверх killswitch.exe. Вся логика — в exe; здесь только установка
# копии в каталог администратора, служба enforce и вызов команд.
#   menu.ps1                       — меню
#   menu.ps1 -Action install [-Source <путь к killswitch.exe>] [-Config <config.toml>]
#   menu.ps1 -Action on|off|repair|status|check|plan|uninstall|shortcut
param(
    [ValidateSet('menu', 'install', 'on', 'off', 'repair', 'status', 'check', 'plan', 'uninstall', 'shortcut')]
    [string]$Action = 'menu',
    [string]$Source = (Join-Path $PSScriptRoot 'killswitch.exe'),
    [string]$Config = ''
)
$ErrorActionPreference = 'Stop'

$ServiceName = 'killswitch'
$InstallDir = Join-Path $env:ProgramFiles 'killswitch'
$Exe = Join-Path $InstallDir 'killswitch.exe'
$StateDir = Join-Path $env:ProgramData 'killswitch'

function Assert-Admin {
    $id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Action', $Action)
    if ($Action -eq 'install') { $argList += @('-Source', "`"$Source`"") }
    if ($Config) { $argList += @('-Config', "`"$Config`"") }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit 0
}

function Invoke-Killswitch([string[]]$CmdArgs) {
    if (-not (Test-Path $Exe)) { throw "killswitch не установлен: нет $Exe (menu.ps1 -Action install)" }
    & $Exe @CmdArgs | Out-Host
    return $LASTEXITCODE
}

function Install-Killswitch {
    if (-not (Test-Path $Source)) { throw "нет исходного killswitch.exe: $Source" }
    New-Item -ItemType Directory -Force $InstallDir, $StateDir | Out-Null
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
    Copy-Item $Source $Exe -Force
    Copy-Item $PSCommandPath (Join-Path $InstallDir 'menu.ps1') -Force -ErrorAction SilentlyContinue
    if ($Config) { Copy-Item $Config (Join-Path $StateDir 'config.toml') -Force }
    # Каталоги — только администраторам и SYSTEM: копия бинарника для оффлайн-снятия и state.json не подменить.
    foreach ($dir in $InstallDir, $StateDir) {
        icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    }
    $code = Invoke-Killswitch @('on')
    if ($code -ne 0) { throw "killswitch on: код $code" }
    if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
        New-Service -Name $ServiceName -BinaryPathName "`"$Exe`" enforce" -DisplayName 'killswitch' `
            -Description 'killswitch: наблюдатель правил (enforce)' -StartupType Automatic | Out-Null
        sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    }
    Start-Service $ServiceName
    Write-Host "установлено: $Exe, служба $ServiceName запущена"
}

function Uninstall-Killswitch {
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
        sc.exe delete $ServiceName | Out-Null
    }
    $code = Invoke-Killswitch @('uninstall')
    if ($code -ne 0) { throw "killswitch uninstall: код $code" }
    Write-Host "правила сняты, служба удалена; копия $Exe оставлена для повторного снятия"
}

function New-Shortcut {
    $menu = Join-Path $InstallDir 'menu.ps1'
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'killswitch.lnk'
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = 'powershell.exe'
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$menu`""
    $s.IconLocation = $Exe
    $s.Save()
    Write-Host "ярлык: $lnk"
}

function Invoke-Action([string]$a) {
    switch ($a) {
        'install' { Install-Killswitch; return 0 }
        'uninstall' { Uninstall-Killswitch; return 0 }
        'shortcut' { New-Shortcut; return 0 }
        default { return (Invoke-Killswitch @($a)) }
    }
}

function Show-Menu {
    $items = [ordered]@{ '1' = 'on'; '2' = 'off'; '3' = 'repair'; '4' = 'status'; '5' = 'check'; '6' = 'install'
        '7' = 'uninstall'; '8' = 'shortcut' }
    while ($true) {
        Write-Host "`nkillswitch"
        $items.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key)) $($_.Value)" }
        Write-Host '  0) выход'
        $choice = Read-Host 'выбор'
        if ($choice -eq '0') { return }
        if (-not $items.Contains($choice)) { continue }
        try { $code = Invoke-Action $items[$choice]; Write-Host "код: $code" } catch { Write-Host "ошибка: $_" }
    }
}

Assert-Admin
if ($Action -eq 'menu') { Show-Menu; exit 0 }
$code = Invoke-Action $Action
exit $code
