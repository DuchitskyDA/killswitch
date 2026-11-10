# killswitch для Windows: установка и ярлык. Окно (killswitch window), меню в терминале (запуск без
# аргументов) и все настройки — в самом killswitch.exe; здесь только копия в каталог администратора,
# служба enforce и ярлык окна.
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

# Доверенные владельцы и получатели прав записи: администраторы, SYSTEM, TrustedInstaller.
$TrustedSids = 'S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

# Путь доверенный, если владелец — из $TrustedSids и никто другой не может в него писать или менять права.
function Test-TrustedPath([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    if ($TrustedSids -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
    $write = [int][Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $write = $write -bor 0x50000000 # GENERIC_ALL и GENERIC_WRITE в наследуемых записях
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $ace.IdentityReference.Value
        # «Создатель-владелец» даёт права только на созданное самим: создать может лишь тот, у кого уже есть запись.
        if ($ace.AccessControlType -ne 'Allow' -or $sid -eq 'S-1-3-0' -or $TrustedSids -contains $sid) { continue }
        if (([int]$ace.FileSystemRights) -band $write) { return $false }
    }
    return $true
}

# Каталог, который уже есть, принимается только доверенным: иначе его содержимое (config.toml, state.json,
# копия программы) мог подложить обычный пользователь, и служба с правами SYSTEM исполнила бы чужие настройки.
function Assert-TrustedDir([string]$Dir) {
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    if ((Get-Item -LiteralPath $Dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "небезопасный каталог: $Dir — ссылка, а не каталог. Удалите её и повторите установку"
    }
    $paths = @($Dir) + @(Get-ChildItem -LiteralPath $Dir -Force -Recurse | ForEach-Object FullName)
    foreach ($path in $paths) {
        # Ссылка (junction, symlink) увела бы запись настроек и прав в чужой каталог.
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "небезопасный каталог: $path — ссылка, а не каталог или файл. Удалите её и повторите установку"
        }
        if (-not (Test-TrustedPath $path)) {
            throw "небезопасный каталог: $path принадлежит не администраторам или открыт на запись другим. " +
                "Проверьте содержимое $Dir, удалите каталог и повторите установку (настройки — ключом -Config)"
        }
    }
}

# Точные права каталога: владелец — администраторы; полный доступ — администраторам и SYSTEM, чтение — пользователям;
# наследование от родителя снято, прежние записи не сохраняются. Вложенное получает только унаследованные права.
function Set-ExactAcl([string]$Dir) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($rule in @('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute')) {
        $sid = New-Object Security.Principal.SecurityIdentifier $rule[0]
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $rule[1], $inherit, 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Dir -AclObject $acl
    if (Get-ChildItem -LiteralPath $Dir -Force | Select-Object -First 1) {
        icacls (Join-Path $Dir '*') /setowner '*S-1-5-32-544' /T /L /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "владелец вложенного в $Dir не задан: icacls, код $LASTEXITCODE" }
        icacls (Join-Path $Dir '*') /reset /T /L /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "права вложенного в $Dir не заданы: icacls, код $LASTEXITCODE" }
    }
    if (-not (Test-TrustedPath $Dir)) { throw "права каталога $Dir не установились" }
}

function Install-Killswitch {
    if (-not (Test-Path $Source)) { throw "нет исходного killswitch.exe: $Source" }
    # Каталоги — только администраторам и SYSTEM: копия бинарника для оффлайн-снятия, config.toml и state.json не
    # подменить. Права ставятся до копирования и до чтения существующих настроек.
    foreach ($dir in $InstallDir, $StateDir) {
        Assert-TrustedDir $dir
        New-Item -ItemType Directory -Force $dir | Out-Null
        Set-ExactAcl $dir
    }
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
    Copy-Item $Source $Exe -Force
    Copy-Item $PSCommandPath (Join-Path $InstallDir 'menu.ps1') -Force -ErrorAction SilentlyContinue
    if ($Config) { Copy-Item $Config $StateConfig -Force }
    # Настройки уже есть — защита включается сразу; иначе их задают в окне.
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
    if (-not (Test-Path $StateConfig)) { Write-Host 'настройки: откройте ярлык killswitch — в окне задайте и сохраните настройки' }
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

# Ярлык открывает окно (killswitch window) сразу с правами администратора (флаг «Запуск от имени
# администратора»). Консоль ярлыка свёрнута: в ней работает локальный сервер окна, пока окно открыто.
function New-Shortcut {
    if (-not (Test-Path $Exe)) { throw "killswitch не установлен: нет $Exe (menu.ps1 -Action install)" }
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'killswitch.lnk'
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = $Exe
    $s.Arguments = 'window'
    $s.WindowStyle = 7 # свёрнутое окно консоли
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
