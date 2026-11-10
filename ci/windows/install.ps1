# Установщик dist/windows/menu.ps1 на одноразовом раннере windows-2025 (ci.yml, live-windows): отказ на каталоге
# настроек, в который может писать не администратор, и на ссылке вместо каталога; чистая установка без настроек
# (служба, ярлык, точные права каталогов), повторная установка и снятие.
. "$PSScriptRoot\lib.ps1"
$Menu = (Resolve-Path "$PSScriptRoot\..\..\dist\windows\menu.ps1").Path
$State = "$env:ProgramData\killswitch"
$Admins = 'S-1-5-32-544'

function Run-Menu([string[]]$MenuArgs) {
    $script:MenuOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Menu @MenuArgs 2>&1 | Out-String
    $script:MenuCode = $LASTEXITCODE
    Write-Host $script:MenuOut
}
function Service-Exists { [bool](Get-Service killswitch -ErrorAction SilentlyContinue) }
function Reset-State {
    if (Service-Exists) { Stop-Service killswitch -Force -ErrorAction SilentlyContinue; sc.exe delete killswitch | Out-Null }
    if (Test-Path -LiteralPath $State) { cmd /c rmdir /s /q "$State" }
}
# Права каталога точные: владелец — администраторы, наследование снято, записи только трёх групп.
function Acl-Exact($dir) {
    $acl = Get-Acl -LiteralPath $dir
    $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    Write-Host "acl $dir owner=$owner protected=$($acl.AreAccessRulesProtected) sids=$($sids -join ',')"
    return ($owner -eq $Admins) -and $acl.AreAccessRulesProtected -and (($sids -join ',') -eq 'S-1-5-18,S-1-5-32-544,S-1-5-32-545')
}

# I1: каталог настроек создан заранее с правами ProgramData (пользователи могут создавать в нём файлы) и с настройками.
Reset-State
New-Item -ItemType Directory -Force $State | Out-Null
Set-Content (Join-Path $State 'config.toml') "profile = 'wireguard'"
Run-Menu @('-Action', 'install', '-Source', $KsExe)
Check 'I1.refused' ($MenuCode -ne 0 -and $MenuOut.Contains('небезопасный каталог')) "code=$MenuCode"
Check 'I1.no-service' (-not (Service-Exists)) 'служба не создана'

# I2: вместо каталога настроек — ссылка на чужой каталог.
Reset-State
$target = "$env:KS\junction-target"
New-Item -ItemType Directory -Force $target | Out-Null
New-Item -ItemType Junction -Path $State -Target $target | Out-Null
Run-Menu @('-Action', 'install', '-Source', $KsExe)
Check 'I2.refused' ($MenuCode -ne 0 -and $MenuOut.Contains('ссылка')) "code=$MenuCode"
Check 'I2.target-untouched' (-not (Get-ChildItem -LiteralPath $target -Force)) 'в каталог по ссылке ничего не записано'
Check 'I2.no-service' (-not (Service-Exists)) 'служба не создана'
cmd /c rmdir "$State"

# I3: чистая установка без настроек.
Run-Menu @('-Action', 'install', '-Source', $KsExe)
Check 'I3.installed' ($MenuCode -eq 0) "code=$MenuCode"
Check 'I3.service-running' ((Get-Service killswitch -ErrorAction SilentlyContinue).Status -eq 'Running') 'служба killswitch запущена'
Check 'I3.exe' (Test-Path $InstalledExe) $InstalledExe
Check 'I3.shortcut' (Test-Path (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'killswitch.lnk')) 'ярлык на общем рабочем столе'
Check 'I3.acl-state' (Acl-Exact $State) $State
Check 'I3.acl-install' (Acl-Exact "$env:ProgramFiles\killswitch") "$env:ProgramFiles\killswitch"

# I4: повторная установка поверх своей — каталоги доверенные, отказа нет.
Run-Menu @('-Action', 'install', '-Source', $KsExe)
Check 'I4.reinstall' ($MenuCode -eq 0) "code=$MenuCode"
Check 'I4.acl-state' (Acl-Exact $State) $State

# I5: снятие.
Run-Menu @('-Action', 'uninstall')
Check 'I5.uninstall' ($MenuCode -eq 0) "code=$MenuCode"
Check 'I5.no-service' (-not (Service-Exists)) 'служба удалена'
Finish
