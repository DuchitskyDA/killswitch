#!/usr/bin/env bash
# Прогон спайка лаборатории на удалённом Linux-хосте. Запускать с машины разработчика (Git Bash / Linux), не на самом хосте.
#   KSL_HOST=root@<host> bash lab/run-remote.sh              — все туннели, потом /opt/killswitch-lab удаляется
#   KSL_HOST=root@<host> TUNNELS=wireguard KEEP=1 bash lab/run-remote.sh
#   GO=<путь к go>, если go нет в PATH.
# Хост не меняется: всё в netns ksl-*, под systemd-run --scope с лимитами; снимок хоста до/после — в .lab-tmp/.
set -euo pipefail
HOST=${KSL_HOST:?задай KSL_HOST=root@<host> — сервер, где разрешено ставить лабораторию}
TUNNELS=${TUNNELS:-wireguard,sing-box,xray}
REMOTE=/opt/killswitch-lab
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(dirname "$HERE")/.lab-tmp
GO=${GO:-go}
# shellcheck source=pins.env
. "$HERE/pins.env"
mkdir -p "$TMP/bin" "$TMP/dl"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 "$HOST")

echo "== сборка kslab"
(cd "$HERE" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$GO" build -trimpath -o "$TMP/bin/kslab" ./cmd/kslab)

fetch() { # url sha256 файл
	if ! echo "$2  $3" | sha256sum -c --status 2>/dev/null; then curl -fsSL -o "$3" "$1"; fi
	echo "$2  $3" | sha256sum -c -
}
echo "== закреплённые релизы"
fetch "$SINGBOX_URL" "$SINGBOX_ARCHIVE_SHA256" "$TMP/dl/sing-box.tar.gz"
fetch "$XRAY_URL" "$XRAY_ARCHIVE_SHA256" "$TMP/dl/xray.zip"
tar -xzf "$TMP/dl/sing-box.tar.gz" -C "$TMP/dl" "sing-box-$SINGBOX_VERSION-linux-amd64/sing-box"
cp "$TMP/dl/sing-box-$SINGBOX_VERSION-linux-amd64/sing-box" "$TMP/bin/sing-box"
unzip -o -q "$TMP/dl/xray.zip" xray -d "$TMP/dl" && cp "$TMP/dl/xray" "$TMP/bin/xray"
(cd "$TMP/bin" && printf '%s  sing-box\n%s  xray\n' "$SINGBOX_BIN_SHA256" "$XRAY_BIN_SHA256" | sha256sum -c -)
(cd "$TMP/bin" && sha256sum kslab sing-box xray > SHA256SUMS)

echo "== копирование на хост"
"${SSH[@]}" "mkdir -p $REMOTE/bin && chmod 700 $REMOTE"
scp -q -o BatchMode=yes "$TMP/bin/kslab" "$TMP/bin/sing-box" "$TMP/bin/xray" "$TMP/bin/SHA256SUMS" "$HOST:$REMOTE/bin/"
scp -q -o BatchMode=yes "$HERE/hostcheck.sh" "$HOST:$REMOTE/"
"${SSH[@]}" "cd $REMOTE/bin && chmod 755 kslab sing-box xray && sha256sum -c SHA256SUMS && du -sh $REMOTE"

echo "== хост до"
"${SSH[@]}" "KSL_SERVICES='${KSL_SERVICES:-}' sh $REMOTE/hostcheck.sh; free -m | sed -n 2p" | tee "$TMP/host-pre.txt"
"${SSH[@]}" "nft -s list ruleset 2>/dev/null" > "$TMP/nft-pre.txt"

# Всё, что меняет состояние хоста, — под scope с лимитами и таймаутом; только чтение (hostcheck, sha256sum) — снаружи.
SCOPE="-p MemoryMax=256M -p CPUQuota=50% -p TasksMax=256"
cleanup() {
	echo "== уборка"
	"${SSH[@]}" "timeout 70 systemd-run --scope --quiet --unit=ksl-lab-clean $SCOPE -p RuntimeMaxSec=65 $REMOTE/bin/kslab cleanup; systemctl stop ksl-lab.scope 2>/dev/null; true" || true
}
trap cleanup EXIT

echo "== защита: цель — корневой ns"
"${SSH[@]}" "timeout 60 systemd-run --scope --quiet --unit=ksl-lab-guard $SCOPE -p RuntimeMaxSec=55 $REMOTE/bin/kslab nsexec --ns-path /proc/1/ns/net -- ip link add ksl-must-not type dummy; echo \"код выхода \$?\"; ip link show ksl-must-not >/dev/null 2>&1 && echo 'ИНТЕРФЕЙС СОЗДАН' || echo 'интерфейс в корневом ns не создан'"
echo "== защита изнутри: подкоманда в корневом ns отказывает до сетевой операции"
"${SSH[@]}" "timeout 60 systemd-run --scope --quiet --unit=ksl-lab-guard2 $SCOPE -p RuntimeMaxSec=55 $REMOTE/bin/kslab probe --expect-ino 1 --dst 203.0.113.130; echo \"код выхода \$?\""

echo "== прогон ($TUNNELS)"
set +e
"${SSH[@]}" "timeout 900 systemd-run --scope --quiet --unit=ksl-lab $SCOPE -p RuntimeMaxSec=870 \
	$REMOTE/bin/kslab run --dir $REMOTE --tunnels $TUNNELS --timeout 13m" | tee "$TMP/run.log"
rc=${PIPESTATUS[0]}
set -e
echo "код прогона: $rc"
cleanup
trap - EXIT

echo "== хост после"
"${SSH[@]}" "KSL_SERVICES='${KSL_SERVICES:-}' sh $REMOTE/hostcheck.sh; free -m | sed -n 2p" | tee "$TMP/host-post.txt"
"${SSH[@]}" "nft -s list ruleset 2>/dev/null" > "$TMP/nft-post.txt"
echo "== сверка (без строки free)"
if diff <(grep -v '^Mem:' "$TMP/host-pre.txt" | grep -v '^nft-raw') <(grep -v '^Mem:' "$TMP/host-post.txt" | grep -v '^nft-raw'); then
	echo "хост совпал"
else
	echo "ХОСТ РАЗОШЁЛСЯ"; diff "$TMP/nft-pre.txt" "$TMP/nft-post.txt" || true; rc=3
fi

rm -rf "$TMP/remote-run" && scp -q -r -o BatchMode=yes "$HOST:$REMOTE/run" "$TMP/remote-run" || true
if [ "${KEEP:-0}" = 1 ]; then
	"${SSH[@]}" "du -sh $REMOTE"; echo "$REMOTE оставлен (KEEP=1)"
else
	"${SSH[@]}" "rm -rf $REMOTE && echo '$REMOTE удалён'"
fi
exit "$rc"
