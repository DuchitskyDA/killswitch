#!/bin/sh
# Дымовой прогон pf-backend: on → пробы → check → чужие вмешательства → off → uninstall без конфига.
# Только под root на одноразовом раннере macOS (ci.yml, live-darwin). Итог — строки RESULT; любой FAIL — код 1.
. /private/tmp/ks-smoke/lib.sh
RUNNER_UID=$(cat "$KS/runner_uid")

log "Инвентаризация"
sw_vers; uname -m
pf_status > "$KS/pf_initial"
echo "pf до дыма: $(cat "$KS/pf_initial")"; pfctl -s References 2>/dev/null
networksetup -listallhardwareports 2>/dev/null | head -20

log "Пробный пользователь и сторож"
if ! id "$PROBE_USER" >/dev/null 2>&1; then
  dscl . -create "/Users/$PROBE_USER"
  dscl . -create "/Users/$PROBE_USER" UniqueID "$PROBE_UID"
  dscl . -create "/Users/$PROBE_USER" PrimaryGroupID 20
  dscl . -create "/Users/$PROBE_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$PROBE_USER" NFSHomeDirectory /var/empty
fi
id "$PROBE_USER"
arm_watchdog 1200
trap 'reset_all trap; disarm_watchdog' EXIT
trap 'exit 130' INT TERM

mkdir -p "$DIR"
cat > "$DIR/config.toml" <<EOF
[tunnel]
interfaces = ["feth2"]

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
cat "$DIR/config.toml"

log "Baseline"
base=$(probe_http); echo "ksprobe http без правил: $base"
case "$base" in OK*) ;; *) result 0.baseline INCONCLUSIVE "ksprobe без правил не вышел в сеть: $base" ;; esac

log "on"
expect 1.on 0 "$BIN" on
expect 1.status 0 "$BIN" status
pfctl -a "$ANCHOR" -sr | grep -v killswitch-probe; echo "правил в якоре: $(anchor_rules)"
pfctl -s References; launchctl print "system/$LABEL" 2>&1 | grep -E 'state|program|run interval' | head -5

log "Прямая проба отброшена"
r=$(probe_http)
case "$r" in OK*) result 2.direct LEAK "ksprobe вышел мимо туннеля: $r" ;; *) result 2.direct PASS "ksprobe http 1.1.1.1: $r" ;; esac
printf '$ live.test\n'
if env KS_PROBE_USER="$PROBE_USER" "$KS/live.test" -test.run "^TestLive" -test.v 2>&1; then result 2.evidence PASS "свидетельство, BindControl, Status"; else result 2.evidence FAIL "живой тест"; fi

log "lo0 проходит"
/usr/bin/python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!; sleep 2
r=$(probe_http http://127.0.0.1:18080/); kill "$srv" 2>/dev/null
case "$r" in OK*) result 3.lo0 PASS "ksprobe → 127.0.0.1:18080: $r" ;; *) result 3.lo0 FAIL "$r" ;; esac

log "Туннель: feth2 создан после on, наблюдатель перепланировал"
for n in 0 2; do
  ifconfig "feth$n" create && ifconfig "feth$((n + 1))" create
  ifconfig "feth$n" peer "feth$((n + 1))"
  ifconfig "feth$n" inet "198.$((18 + n / 2)).0.1/24" up; ifconfig "feth$((n + 1))" up
  arp -s "198.$((18 + n / 2)).0.2" 02:00:00:00:00:02
done
s=$(wait_for 40 sh -c "pfctl -a '$ANCHOR' -sr | grep -q 'on feth2'")
case "$s" in FAIL) result 4.replan FAIL "правило для feth2 не появилось за 40 с" ;; *) result 4.replan PASS "правило on feth2 за $s с" ;; esac
seen() { # $1 интерфейс $2 адрес → SEEN|NOTSEEN
  cap="$OUT/cap.$1.txt"
  tcpdump -n -l -i "$1" "dst host $2 and udp dst port 9" > "$cap" 2>/dev/null &
  tp=$!; sleep 1
  for k in 1 2 3; do printf x | sudo -u "$PROBE_USER" nc -u -w 1 "$2" 9 >/dev/null 2>&1; done
  sleep 1; kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
  grep -q "$2" "$cap" && echo SEEN || echo NOTSEEN
}
r=$(seen feth2 198.19.0.2)
[ "$r" = SEEN ] && result 4.tunnel PASS "ksprobe udp через feth2 (туннель по точному имени) ушёл" || result 4.tunnel FAIL "$r"
r=$(seen feth0 198.18.0.2)
[ "$r" = NOTSEEN ] && result 4.other-iface PASS "feth0 не туннель: пакет не ушёл" || result 4.other-iface FAIL "$r"
result 4.utun NOT_TESTED "utun на раннере не поднимался; туннель проверен на feth2 по точному имени"

log "check"
expect 5.check-no-targets 5 "$BIN" check

log "check с целями: туннель sing-box (utun99), root доверен → BLOCKED со свидетельством"
# Цель 203.0.113.10 (TEST-NET-3) напрямую уходит через en0 и упирается в правило пробы; через туннель sing-box
# переадресует её на локальные сервисы 127.0.0.2 — так baseline через туннель живой без внешнего сервера.
ifconfig lo0 alias 127.0.0.2
/usr/bin/python3 "$KS/targets.py" 127.0.0.2 300 > "$OUT/targets.log" 2>&1 &
tg=$!
cat > "$KS/sing-box.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{ "type": "tun", "tag": "tun-in", "interface_name": "utun99", "address": ["172.19.0.1/30"],
    "auto_route": true, "route_address": ["203.0.113.10/32"], "stack": "gvisor" }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "rules": [{ "ip_cidr": ["203.0.113.10/32"], "action": "route-options", "override_address": "127.0.0.2" }],
    "final": "direct" }
}
EOF
"$KS/sing-box" run -c "$KS/sing-box.json" > "$OUT/sing-box.log" 2>&1 &
sb=$!
s=$(wait_for 20 ifconfig utun99); echo "utun99 через $s с"; cat "$OUT/targets.log"
route -n get 203.0.113.10 2>&1 | grep -E 'interface|flags'
printf '$ curl --interface utun99 (baseline через туннель)\n'; /usr/bin/curl -sS -m 3 -o /dev/null -w '%{http_code}\n' --interface utun99 http://203.0.113.10/ 2>&1
cp "$DIR/config.toml" "$KS/config.toml.base"
sed 's/interfaces = \["feth2"\]/interfaces = ["utun99"]/' "$KS/config.toml.base" > "$DIR/config.toml"
printf '\n[check]\ntargets = ["203.0.113.10"]\n' >> "$DIR/config.toml"
s=$(wait_for 40 sh -c "pfctl -a '$ANCHOR' -sr | grep -q 'on utun99'"); echo "правило on utun99 через $s с"
expect 5.check-targets 0 "$BIN" check
cp "$KS/config.toml.base" "$DIR/config.toml"
kill "$sb" "$tg" 2>/dev/null
cat "$OUT/sing-box.log" | tail -5

log "Чужое quick-правило выше якоря: только LEAK, основной набор не перезаписывается"
printf 'pass out quick proto tcp to any port 443\nanchor "com.apple/*"\n' | pfctl -q -f - 2>&1
expect 6.status-quick 4 "$BIN" status
expect 6.check-quick 4 "$BIN" check
sleep 15
first=$(pfctl -sr 2>/dev/null | head -1)
case "$first" in pass*) result 6.no-overwrite PASS "через 15 с первое правило всё ещё чужое: $first" ;;
  *) result 6.no-overwrite FAIL "основной набор перезаписан: $first" ;; esac
pfctl -q -f /etc/pf.conf 2>&1
expect 6.status-pfconf 0 "$BIN" status
r=$(probe_http)
case "$r" in OK*) result 6.pfconf-protect FAIL "после pfctl -f /etc/pf.conf проба вышла: $r" ;;
  *) result 6.pfconf-protect PASS "после pfctl -f /etc/pf.conf защита на месте ($(anchor_rules) правил)" ;; esac

log "Наблюдатель: чужой flush якоря"
pfctl -q -a "$ANCHOR" -F all
s=$(wait_for 40 sh -c "[ \$(pfctl -a '$ANCHOR' -sr 2>/dev/null | grep -c .) -gt 0 ] && '$BIN' status")
case "$s" in FAIL) result 7.restore-flush FAIL "якорь не восстановлен за 40 с" ;; *) result 7.restore-flush PASS "якорь восстановлен за $s с" ;; esac

log "Наблюдатель: чужой pfctl -d (имитация на одноразовой ВМ)"
pfctl -d 2>&1
s=$(wait_for 40 sh -c "pfctl -s info | grep -q 'Status: Enabled' && '$BIN' status")
case "$s" in FAIL) result 7.restore-disable FAIL "pf не включён за 40 с" ;; *) result 7.restore-disable PASS "pf включён своим токеном за $s с" ;; esac
r=$(probe_http)
case "$r" in OK*) result 7.after-restore LEAK "$r" ;; *) result 7.after-restore PASS "проба снова отброшена" ;; esac

log "off"
expect 8.off 0 "$BIN" off
sleep 15
r=$(probe_http)
case "$r" in OK*) result 8.off-open PASS "off: ksprobe вышел, правил в якоре $(anchor_rules)" ;; *) result 8.off-open FAIL "$r" ;; esac
expect 8.status-off 0 "$BIN" status

log "uninstall без конфига"
expect 9.on-again 0 "$BIN" on
mv "$DIR/config.toml" "$KS/config.toml.saved"
expect 9.uninstall 0 "$BIN" uninstall
n=$(anchor_rules); t=$(our_tokens)
launchctl print "system/$LABEL" >/dev/null 2>&1 && d=loaded || d=absent
[ "$n" = 0 ] && [ -z "$t" ] && [ "$d" = absent ] && [ ! -e "/Library/LaunchDaemons/$LABEL.plist" ] \
  && result 9.removed PASS "якорь пуст, токенов killswitchd нет, LaunchDaemon снят" \
  || result 9.removed FAIL "правил $n, токены '$t', демон $d"
r=$(probe_http)
case "$r" in OK*) result 9.open PASS "после uninstall ksprobe вышел: $r" ;; *) result 9.open FAIL "$r" ;; esac
ls -la "$DIR" 2>&1

log "Журнал наблюдателя"
cat /var/log/killswitch.log 2>/dev/null | tail -40

log "Итог"
cat "$RES"
! grep -Eq "^RESULT [^ ]+ (FAIL|LEAK|INCONCLUSIVE) " "$RES"
