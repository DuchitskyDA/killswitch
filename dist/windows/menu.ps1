# killswitch для Windows: установка и ярлык. Меню и все настройки — в самом killswitch.exe
# (запуск без аргументов); здесь только копия в каталог администратора, служба enforce и ярлык.
#   menu.ps1 [-Action install] [-Source <путь к killswitch.exe>] [-Config <config.toml>]
#   menu.ps1 -Action uninstall | shortcut
param(
    [ValidateSet('install', 'uninstall', 'shortcut')]
    [string]$Action = 'install',
    [string]$Source = (Join-Path $PSScriptRoot 'killswitch.exe'),
    [string]$Config = ''
)
$ErrorActionPreference = 'Stop'

$ServiceName = 'killswitch'
$InstallDir = Join-Path $env:ProgramFiles 'killswitch'
$Exe = Join-Path $InstallDir 'killswitch.exe'
$StateDir = Join-Path $env:ProgramData 'killswitch'
$StateConfig = Join-Path $StateDir 'config.toml'

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
    if ($Config) { Copy-Item $Config $StateConfig -Force }
    # Каталоги — только администраторам и SYSTEM: копия бинарника для оффлайн-снятия и state.json не подменить.
    foreach ($dir in $InstallDir, $StateDir) {
        icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    }
    # Настройки уже есть — защита включается сразу; иначе их задают в меню.
    if (Test-Path $StateConfig) {
        $code = Invoke-Killswitch @('on')
        if ($code -ne 0) { throw "killswitch on: код $code" }
    }
    if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
        New-Service -Name $ServiceName -BinaryPathName "`"$Exe`" enforce" -DisplayName 'killswitch' `
            -Description 'killswitch: наблюдатель правил (enforce)' -StartupType Automatic | Out-Null
        sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    }
    Start-Service $ServiceName
    New-Shortcut
    Write-Host "установлено: $Exe, служба $ServiceName запущена"
    if (-not (Test-Path $StateConfig)) { Write-Host 'настройки: откройте ярлык killswitch, пункт «Настройки»' }
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

# Ярлык открывает меню killswitch.exe сразу с правами администратора (флаг «Запуск от имени администратора»).
function New-Shortcut {
    if (-not (Test-Path $Exe)) { throw "killswitch не установлен: нет $Exe (menu.ps1 -Action install)" }
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'killswitch.lnk'
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = $Exe
    $s.Arguments = ''
    $s.WorkingDirectory = $InstallDir
    $s.IconLocation = $Exe
    $s.Save()
    $bytes = [IO.File]::ReadAllBytes($lnk)
    $bytes[0x15] = $bytes[0x15] -bor 0x20 # SLDF_RUNAS_USER
    [IO.File]::WriteAllBytes($lnk, $bytes)
    Write-Host "ярлык: $lnk"
}

Assert-Admin
switch ($Action) {
    'install' { Install-Killswitch }
    'uninstall' { Uninstall-Killswitch }
    'shortcut' { New-Shortcut }
}
exit 0
