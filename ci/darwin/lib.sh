# Общее для живых сценариев pf-backend на одноразовом раннере macOS (ci.yml, live-darwin). Только под root на ВМ раннера.
KS=/private/tmp/ks-ci
OUT="$KS/out"
RES="$OUT/results.txt"
DIR="/Library/Application Support/killswitch"
BIN="$KS/killswitch"
ANCHOR="com.apple/000.killswitch"
LABEL="io.github.duchitskyda.killswitch"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
PROBE_USER=ksprobe
PROBE_UID=6001
WD_LABEL="ks.ci.watchdog"
WD_PLIST="/Library/LaunchDaemons/$WD_LABEL.plist"
mkdir -p "$OUT"

log() { printf '\n== %s\n' "$*"; }
result() { id=$1; cls=$2; shift 2; printf 'RESULT %s %s %s\n' "$id" "$cls" "$*" | tee -a "$RES"; }
check() { # id условие(0 — да) деталь
  id=$1; ok=$2; shift 2
  if [ "$ok" -eq 0 ]; then result "$id" PASS "$*"; else result "$id" FAIL "$*"; fi
}
# expect id код команда… — PASS, если код совпал.
expect() {
  id=$1; want=$2; shift 2
  printf '$ %s\n' "$*"
  "$@" 2>&1; rc=$?
  if [ "$rc" -eq "$want" ]; then result "$id" PASS "код $rc"; else result "$id" FAIL "код $rc, ждали $want"; fi
}

pf_status() { pfctl -s info 2>/dev/null | awk '/^Status/{print $2}'; }
anchor_rules() { pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -c . | tr -d ' '; }
our_tokens() { pfctl -s References 2>/dev/null | awk '$2=="killswitchd"{print $3}'; }
anchor_has() { pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -q "$1"; }

# HTTP от пробного пользователя: код 0 — сервер ответил.
http_ok() { sudo -u "$PROBE_USER" /usr/bin/curl -s -o /dev/null -m 5 "${1:-http://1.1.1.1/}" >/dev/null 2>&1; }
# ksprobe от пробного пользователя: <проба> <ip> [интерфейс]; код 0 — сервер ответил.
probe_ok() { sudo -u "$PROBE_USER" "$KS/ksprobe" "$@"; }
# Закрыто: ksprobe не получил ответа (код 1); ошибка привязки или аргументов (2) — не «закрыто».
probe_blocked() { probe_ok "$@"; [ $? -eq 1 ]; }

# Ждать до $1 с, пока команда не станет успешной; печатает секунды или FAIL.
wait_for() {
  limit=$1; shift; s=0
  while [ "$s" -le "$limit" ]; do
    if "$@" >/dev/null 2>&1; then echo "$s"; return 0; fi
    sleep 1; s=$((s + 1))
  done
  echo FAIL; return 1
}
not() { ! "$@"; }

# Ушёл ли UDP-пакет пробного пользователя к $1:$2 через feth0 (tcpdump-свидетель): SEEN|NOTSEEN.
seen() {
  cap="$OUT/cap.$1.$2.txt"
  tcpdump -n -l -i feth0 "dst host $1 and udp dst port $2" > "$cap" 2>/dev/null &
  tp=$!; sleep 1
  for k in 1 2 3; do printf x | sudo -u "$PROBE_USER" nc -u -w 1 "$1" "$2" >/dev/null 2>&1; done
  sleep 1; kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
  grep -q "$1" "$cap" && echo SEEN || echo NOTSEEN
}
is_seen() { [ "$(seen "$1" "$2")" = SEEN ]; }

# Конфиг стенда: доверены пользователь раннера, root (sing-box) и _mdnsresponder; $1 — lan, $2 — режим DNS.
write_config() {
  health=
  [ "$2" = tunnel-up ] && health='health = "http://203.0.113.10:80/"'
  cat > "$DIR/config.toml" <<EOF
lan = $1

[tunnel]
interfaces = ["utun9*"]

[dns]
mode = "$2"
$health

[check]
targets = ["203.0.113.10"]

[[trust]]
kind = "user"
value = "$RUNNER_UID"

[[trust]]
kind = "user"
value = "0"

[[trust]]
kind = "user"
value = "_mdnsresponder"
EOF
}

# Туннель стенда — sing-box TUN без strict_route: 1.1.1.1 — настоящий выход через туннель (sing-box под доверенным
# root), 203.0.113.10 → цели check и dns.health на 127.0.0.2.
start_tunnel() {
  cat > "$KS/sb-$1.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{ "type": "tun", "tag": "tun-in", "interface_name": "$1", "address": ["172.19.0.1/30"],
    "auto_route": true, "route_address": ["1.1.1.1/32", "203.0.113.10/32"], "stack": "gvisor" }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "rules": [{ "ip_cidr": ["203.0.113.10/32"], "action": "route-options", "override_address": "127.0.0.2" }],
    "final": "direct", "auto_detect_interface": true }
}
EOF
  "$KS/sing-box" run -c "$KS/sb-$1.json" > "$OUT/sing-box-$1.log" 2>&1 &
  echo $! > "$KS/sb.pid"
  s=$(wait_for 20 ifconfig "$1"); echo "туннель $1 поднят через $s с"
}
stop_tunnel() {
  [ -f "$KS/sb.pid" ] && kill "$(cat "$KS/sb.pid")" 2>/dev/null
  rm -f "$KS/sb.pid"; sleep 2
}

# Демон наблюдателя: bootout асинхронный — ждать выгрузки и выхода enforce; bootstrap сразу после bootout может
# вернуть «5: Input/output error» — повторять.
daemon_down() {
  launchctl bootout "system/$LABEL" 2>&1
  s=$(wait_for 20 sh -c "! launchctl print system/$LABEL >/dev/null 2>&1 && ! pgrep -f 'killswitch enforce'")
  echo "демон выгружен, enforce завершён через $s с"
}
daemon_up() { wait_for 20 launchctl bootstrap system "$PLIST"; }

# Сброс всего нашего: штатный uninstall, затем вручную (на случай сломанного бинарника); pfctl -d — только
# если pf был выключен до прогона (одноразовая ВМ, в продукт не переносится).
reset_all() {
  "$BIN" uninstall >/dev/null 2>&1
  launchctl bootout "system/$LABEL" >/dev/null 2>&1
  rm -f "$PLIST"
  pfctl -q -a "$ANCHOR" -F all >/dev/null 2>&1
  for t in $(our_tokens); do pfctl -X "$t" >/dev/null 2>&1; done
  pfctl -q -f /etc/pf.conf >/dev/null 2>&1
  if [ "$(cat "$KS/pf_initial" 2>/dev/null)" = Disabled ] && [ "$(pf_status)" = Enabled ]; then pfctl -d >/dev/null 2>&1; fi
  for i in 0 1; do ifconfig "feth$i" destroy >/dev/null 2>&1; done
  pkill -f "$KS/sing-box" >/dev/null 2>&1; pkill -f "$KS/targets.py" >/dev/null 2>&1
  ifconfig lo0 -alias 127.0.0.2 >/dev/null 2>&1
  echo "reset($1) $(date +%T) pf=$(pf_status) anchor_rules=$(anchor_rules)"
}

arm_watchdog() { # $1 секунд
  launchctl bootout "system/$WD_LABEL" >/dev/null 2>&1
  cat > "$WD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$WD_LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
    <string>sleep $1; . $KS/lib.sh; echo "watchdog FIRED \$(date +%T)"; reset_all watchdog</string></array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$OUT/watchdog.log</string>
  <key>StandardErrorPath</key><string>$OUT/watchdog.log</string>
</dict></plist>
EOF
  chown root:wheel "$WD_PLIST"; chmod 644 "$WD_PLIST"
  launchctl bootstrap system "$WD_PLIST"
}
disarm_watchdog() { launchctl bootout "system/$WD_LABEL" >/dev/null 2>&1; rm -f "$WD_PLIST"; return 0; }
