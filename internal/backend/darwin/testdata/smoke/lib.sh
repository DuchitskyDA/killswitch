# Общее для дыма pf-backend на одноразовом раннере macOS (smoke-darwin.yml). Только под root на ВМ раннера.
KS=/private/tmp/ks-smoke
OUT="$KS/out"
RES="$OUT/results.txt"
DIR="/Library/Application Support/killswitch"
BIN="$KS/killswitch"
ANCHOR="com.apple/000.killswitch"
LABEL="io.github.duchitskyda.killswitch"
PROBE_USER=ksprobe
PROBE_UID=6001
WD_LABEL="ks.smoke.watchdog"
WD_PLIST="/Library/LaunchDaemons/$WD_LABEL.plist"
mkdir -p "$OUT"

log() { printf '\n== %s\n' "$*"; }
result() { id=$1; cls=$2; shift 2; printf 'RESULT %s %s %s\n' "$id" "$cls" "$*" | tee -a "$RES"; }
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

# Интернет-проба от пробного пользователя: OK <код> или FAIL.
probe_http() {
  code=$(sudo -u "$PROBE_USER" /usr/bin/curl -sS -o /dev/null -m 5 -w '%{http_code}' "${1:-http://1.1.1.1/}" 2>/dev/null)
  case "$code" in [1-5][0-9][0-9]) echo "OK $code" ;; *) echo "FAIL $code" ;; esac
}

# Ждать до $1 с, пока команда не станет успешной; печатает секунды или FAIL.
wait_for() {
  limit=$1; shift; s=0
  while [ "$s" -le "$limit" ]; do
    if "$@" >/dev/null 2>&1; then echo "$s"; return 0; fi
    sleep 1; s=$((s + 1))
  done
  echo FAIL; return 1
}

# Сброс всего нашего: штатный uninstall, затем вручную (на случай сломанного бинарника); pfctl -d — только
# если pf был выключен до дыма (одноразовая ВМ, в продукт не переносится).
reset_all() {
  "$BIN" uninstall >/dev/null 2>&1
  launchctl bootout "system/$LABEL" >/dev/null 2>&1
  rm -f "/Library/LaunchDaemons/$LABEL.plist"
  pfctl -q -a "$ANCHOR" -F all >/dev/null 2>&1
  for t in $(our_tokens); do pfctl -X "$t" >/dev/null 2>&1; done
  pfctl -q -f /etc/pf.conf >/dev/null 2>&1
  if [ "$(cat "$KS/pf_initial" 2>/dev/null)" = Disabled ] && [ "$(pf_status)" = Enabled ]; then pfctl -d >/dev/null 2>&1; fi
  for i in 0 1 2 3; do ifconfig "feth$i" destroy >/dev/null 2>&1; done
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
