#!/usr/bin/env bash
# Живая приёмка Linux-backend на удалённом хосте. Запускать с машины разработчика (Git Bash / Linux), не на самом хосте.
#   KSL_HOST=root@<host> KSL_SERVICES="a.service b.service" bash lab/run-accept.sh
#   CLIENTS=wireguard,xray OUT=<каталог логов> KEEP=1 GO=<путь к go> bash lab/run-accept.sh
# Каждый клиент — свой вызов под systemd-run --scope с лимитами (своя свежая топология, 870 с). killswitch работает только
# в netns ksl-client и в своём mount ns (tmpfs поверх /var/lib, /run, /etc/systemd/system; systemctl — заглушка).
# Снимок хоста до и после сверяется; при любом исходе — уборка.
set -euo pipefail
HOST=${KSL_HOST:?задай KSL_HOST=root@<host> — сервер, где разрешено ставить лабораторию}
CLIENTS=${CLIENTS:-wireguard,sing-box,sing-box-ar,xray}
REMOTE=/opt/killswitch-lab
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
TMP=$ROOT/.lab-tmp
OUT=${OUT:-$TMP/accept}
GO=${GO:-go}
# shellcheck source=pins.env
. "$HERE/pins.env"
mkdir -p "$TMP/bin" "$TMP/dl" "$OUT"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 "$HOST")
SCOPE="-p MemoryMax=256M -p CPUQuota=50% -p TasksMax=256"

echo "== сборка kslab и killswitch (linux/amd64)"
(cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$GO" build -trimpath -o "$TMP/bin/kslab" ./lab/cmd/kslab)
(cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 "$GO" build -trimpath -o "$TMP/bin/killswitch" ./cmd/killswitch)
echo "killswitch из $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet HEAD -- . || echo '+правки')"

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
(cd "$TMP/bin" && sha256sum kslab killswitch sing-box xray > SHA256SUMS)

echo "== хост до"
"${SSH[@]}" "test ! -e $REMOTE || { echo '$REMOTE уже есть — сначала уборка'; exit 1; }"
cleanup() {
	echo "== уборка"
	"${SSH[@]}" "timeout 70 systemd-run --scope --quiet --unit=ksl-lab-clean $SCOPE -p RuntimeMaxSec=65 $REMOTE/bin/kslab cleanup; \
		for u in \$(systemctl list-units --plain --no-legend 'ksl-lab*' | awk '{print \$1}'); do systemctl stop \"\$u\"; done; \
		systemctl reset-failed 'ksl-lab*' 2>/dev/null; true" || true
}
rc=0 LOGS_LEFT=0
remove_remote() {
	if [ "${KEEP:-0}" = 1 ] || [ "$LOGS_LEFT" = 1 ]; then
		"${SSH[@]}" "du -sh $REMOTE" || true
		echo "$REMOTE оставлен (KEEP=1 или невыгруженные журналы)"
	else
		"${SSH[@]}" "rm -rf $REMOTE && echo '$REMOTE удалён'; test ! -e $REMOTE" || { echo "$REMOTE НЕ УДАЛЁН"; [ "$rc" != 0 ] || rc=1; }
	fi
}
# Любой выход после создания каталога на хосте: уборка ns и scope, затем удаление каталога (кроме KEEP=1).
on_exit() {
	local code=$?
	cleanup
	remove_remote
	exit "$code"
}
trap on_exit EXIT
"${SSH[@]}" "mkdir -p $REMOTE/bin $REMOTE/stub $REMOTE/stub-kill && chmod 700 $REMOTE"
scp -q -o BatchMode=yes "$TMP/bin/kslab" "$TMP/bin/killswitch" "$TMP/bin/sing-box" "$TMP/bin/xray" "$TMP/bin/SHA256SUMS" "$HOST:$REMOTE/bin/"
scp -q -o BatchMode=yes "$HERE/stub/systemctl" "$HOST:$REMOTE/stub/"
scp -q -o BatchMode=yes "$HERE/stub-kill/nft" "$HOST:$REMOTE/stub-kill/"
scp -q -o BatchMode=yes "$HERE/hostcheck.sh" "$HOST:$REMOTE/"
"${SSH[@]}" "cd $REMOTE && chmod 755 bin/* stub/systemctl stub-kill/nft && cd bin && sha256sum -c SHA256SUMS && du -sh $REMOTE"
"${SSH[@]}" "KSL_SERVICES='${KSL_SERVICES:-}' sh $REMOTE/hostcheck.sh; free -m | sed -n 2p" | tee "$OUT/host-pre.txt"
"${SSH[@]}" "nft -s list ruleset 2>/dev/null" > "$OUT/nft-pre.txt"


echo "== защита: цель — корневой ns"
"${SSH[@]}" "timeout 60 systemd-run --scope --quiet --unit=ksl-lab-guard $SCOPE -p RuntimeMaxSec=55 $REMOTE/bin/kslab nsexec --ns-path /proc/1/ns/net -- ip link add ksl-must-not type dummy; echo \"код выхода \$?\"; ip link show ksl-must-not >/dev/null 2>&1 && echo 'ИНТЕРФЕЙС СОЗДАН' || echo 'интерфейс в корневом ns не создан'"

for c in ${CLIENTS//,/ }; do
	echo "== приёмка: $c"
	set +e
	"${SSH[@]}" "timeout 900 systemd-run --scope --quiet --unit=ksl-lab-$c -p Delegate=yes $SCOPE -p RuntimeMaxSec=870 \
		$REMOTE/bin/kslab accept --client $c --dir $REMOTE --timeout 13m" > "$OUT/$c.console.txt" 2>&1
	crc=$?
	set -e
	echo "код $c: $crc"; tail -n 3 "$OUT/$c.console.txt"
	[ "$crc" = 0 ] || rc=1
	cleanup
	# Журналы — доказательство приёмки: без копии клиент не принят, удалённый каталог не трогается (KEEP=1 его сохранит).
	if rm -rf "${OUT:?}/$c" && scp -q -r -o BatchMode=yes "$HOST:$REMOTE/run-$c" "$OUT/$c" && [ -s "$OUT/$c/results.json" ]; then
		"${SSH[@]}" "rm -rf $REMOTE/run-$c"
	else
		echo "журналы $c не скопированы: клиент не принят, $REMOTE останется"
		rc=1 LOGS_LEFT=1
	fi
done

echo "== хост после"
"${SSH[@]}" "KSL_SERVICES='${KSL_SERVICES:-}' sh $REMOTE/hostcheck.sh; free -m | sed -n 2p" | tee "$OUT/host-post.txt"
"${SSH[@]}" "nft -s list ruleset 2>/dev/null" > "$OUT/nft-post.txt"
echo "== сверка (без Mem и nft-raw: сырой листинг плавает из-за счётчиков ufw/fail2ban)"
if diff <(grep -vE '^(Mem:|nft-raw)' "$OUT/host-pre.txt") <(grep -vE '^(Mem:|nft-raw)' "$OUT/host-post.txt"); then
	echo "хост совпал"
else
	echo "ХОСТ РАЗОШЁЛСЯ"; diff "$OUT/nft-pre.txt" "$OUT/nft-post.txt" || true; rc=3
fi
trap - EXIT
remove_remote
exit "$rc"
