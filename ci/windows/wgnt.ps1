# Драйверный туннель WireGuardNT на одноразовом раннере windows-2025 (ci.yml, live-windows): режет ли наш block
# его транспорт без доверия и помогает ли доверие по app-id wireguard.exe. Сервера нет: endpoint 203.0.113.20:51820
# недостижим, свидетель — события отброса WFP к нему (wfptool drops) с app-id отправителя.
. "$PSScriptRoot\lib.ps1"
$Wg = "$env:ProgramFiles\WireGuard"
$Ep = '203.0.113.20'

function Not-Tested($why) { Result 'WG.transport' 'NOT_TESTED' $why; $global:LASTEXITCODE = 0; exit 0 }

$msi = "$env:KS\wireguard.msi"
try { Invoke-WebRequest "https://download.wireguard.com/windows-client/wireguard-amd64-$env:WG_VERSION.msi" -OutFile $msi }
catch { Not-Tested "MSI не скачан: $_" }
$h = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
$sig = Get-AuthenticodeSignature $msi
Write-Host "wireguard-amd64-$env:WG_VERSION.msi sha256=$h подпись=$($sig.Status) $($sig.SignerCertificate.Subject)"
if ($env:WG_SHA256 -and $h -ne $env:WG_SHA256) { throw "sha256 mismatch: $h" }
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') { throw "подпись MSI: $($sig.Status)" }
$p = Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn', 'DO_NOT_LAUNCH=1' -Wait -PassThru
if ($p.ExitCode -ne 0 -or -not (Test-Path "$Wg\wireguard.exe")) { Not-Tested "установка MSI: код $($p.ExitCode)" }

$priv = (& "$Wg\wg.exe" genkey).Trim()
$peer = ((& "$Wg\wg.exe" genkey) | & "$Wg\wg.exe" pubkey).Trim()
@"
[Interface]
PrivateKey = $priv
Address = 10.99.0.1/24

[Peer]
PublicKey = $peer
Endpoint = ${Ep}:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 5
"@ | Set-Content "$env:KS\wgks.conf"

# $true — наш block отбросил транспорт WireGuardNT к недостижимому endpoint.
function Wg-Dropped {
    $t0 = (Get-Date).ToUniversalTime().ToString('o')
    & "$Wg\wireguard.exe" /installtunnelservice "$env:KS\wgks.conf" 2>&1 | Write-Host
    $s = Wait-For 30 { (Get-NetAdapter -Name 'wgks' -ErrorAction SilentlyContinue).Status -eq 'Up' }
    Write-Host "адаптер wgks через $s с"
    ping -n 4 10.99.0.2 | Out-Null # данные в туннель — повод для рукопожатия
    Start-Sleep 8
    & "$env:KS\wfptool.exe" drops $Ep $t0 2>&1 | Write-Host
    $dropped = $LASTEXITCODE -eq 0
    & "$Wg\wireguard.exe" /uninstalltunnelservice wgks 2>&1 | Write-Host
    Start-Sleep 3
    return $dropped
}

& "$env:KS\wfptool.exe" collect
Write-Config
Expect-Code 'WG.on' 0 { & $KsExe on }
$d = Wg-Dropped
Check 'WG.untrusted-dropped' $d "WireGuardNT без доверия: транспорт к ${Ep}:51820 отброшен нашим block = $d"

"[[trust]]`nkind = 'program'`nvalue = '$Wg\wireguard.exe'`n" | Add-Content "$env:KS\trust.toml"
Write-Config
Expect-Code 'WG.on-trusted' 0 { & $KsExe on }
$d = Wg-Dropped
Result 'WG.appid-trust' 'INFO' "доверие по app-id wireguard.exe: транспорт отброшен нашим block = $d (app-id отправителя — в строках «отброс» лога)"
Expect-Code 'WG.uninstall' 0 { & $KsExe uninstall }
Result 'DCO.transport' 'NOT_TESTED' 'ovpn-dco: нужен сервер OpenVPN и драйвер DCO на раннере — не ставились'
Finish
