#!/bin/sh
# Живые сценарии pf-backend (эпик, «Живые сценарии» 1–9 и 10) на одноразовом раннере macOS (ci.yml, live-darwin).
# Только под root на ВМ раннера. Итог — строки RESULT S<n>.<id>; любой FAIL — код 1.
. /private/tmp/ks-ci/lib.sh
RUNNER_UID=$(cat "$KS/runner_uid")

log "Инвентаризация"
sw_vers; uname -m
pf_status > "$KS/pf_initial"
echo "pf до прогона: $(cat "$KS/pf_initial")"; pfctl -s References 2>/dev/null
NIC=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
echo "физический интерфейс по умолчанию: $NIC"

log "Пробный пользователь, сторож, стенд"
if ! id "$PROBE_USER" >/dev/null 2>&1; then
  dscl . -create "/Users/$PROBE_USER"
  dscl . -create "/Users/$PROBE_USER" UniqueID "$PROBE_UID"
  dscl . -create "/Users/$PROBE_USER" PrimaryGroupID 20
  dscl . -create "/Users/$PROBE_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$PROBE_USER" NFSHomeDirectory /var/empty
fi
id "$PROBE_USER"
arm_watchdog 1500
trap 'reset_all trap; disarm_watchdog' EXIT
trap 'exit 130' INT TERM
mkdir -p "$DIR"
ifconfig lo0 alias 127.0.0.2
/usr/bin/python3 "$KS/targets.py" 127.0.0.2 1500 > "$OUT/targets.log" 2>&1 &
# LAN-свидетель: feth0 192.168.77.1/24 (пара feth1), статический ARP соседа 192.168.77.2.
ifconfig feth0 create && ifconfig feth1 create && ifconfig feth0 peer feth1
ifconfig feth0 inet 192.168.77.1/24 up; ifconfig feth1 up
arp -s 192.168.77.2 02:00:00:00:00:02
write_config true open
cat "$DIR/config.toml"

log "S2: on, туннель опущен"
base=$(http_ok && echo OK || echo FAIL); echo "ksprobe без правил: $base"
[ "$base" = OK ] || result S0.baseline FAIL "ksprobe без правил не вышел в сеть"
expect S2.on 0 "$BIN" on
expect S2.status 0 "$BIN" status
not http_ok; check S2.untrusted-blocked $? "ksprobe curl → 1.1.1.1 закрыт"
sudo -u "#$RUNNER_UID" /usr/bin/curl -s -o /dev/null -m 5 http://1.1.1.1/; check S2.trusted-passes $? "пользователь раннера (доверен) → 1.1.1.1"
printf '$ live.test\n'
env KS_PROBE_USER="$PROBE_USER" "$KS/live.test" -test.run "^TestLive" -test.v 2>&1
check S2.evidence $? "live.test: отброс правилом пробы, BindControl, Status"
/usr/bin/python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!; wait_for 15 /usr/bin/curl -s -o /dev/null http://127.0.0.1:18080/ >/dev/null
http_ok http://127.0.0.1:18080/; check S1.lo0 $? "ksprobe → 127.0.0.1:18080"
kill "$srv" 2>/dev/null

log "S1: on, туннель поднят (utun99 появился после on — перепланирует наблюдатель)"
start_tunnel utun99
s=$(wait_for 40 anchor_has 'on utun99'); echo "правило on utun99 через $s с"
s=$(wait_for 30 http_ok http://1.1.1.1/); [ "$s" != FAIL ]; check S1.tunnel-exit $? "ksprobe curl → 1.1.1.1 через utun99: $s с"
not http_ok http://1.0.0.1/; check S1.direct-blocked $? "ksprobe curl → 1.0.0.1 (мимо туннеля) закрыт"
probe_blocked http 1.1.1.1 "$NIC"; check S1.direct-bound-blocked $? "ksprobe http 1.1.1.1 с привязкой к $NIC закрыт"
if route -n get -inet6 default >/dev/null 2>&1; then
  not sudo -u "$PROBE_USER" /usr/bin/curl -6 -s -o /dev/null -m 5 'http://[2606:4700:4700::1111]/'
  check S1.direct-v6-blocked $? "ksprobe curl v6 → 2606:4700:4700::1111 закрыт"
else
  result S1.direct-v6-blocked NOT_TESTED "на раннере нет маршрута v6 по умолчанию"
fi
expect S9.check-tunnel-up 0 "$BIN" check

log "S3: LAN и DNS (свидетель — tcpdump на feth0)"
is_seen 192.168.77.2 9; check S3.lan-open $? "LAN=true: UDP к 192.168.77.2 ушёл"
write_config false open
expect S3.on-lan-false 0 "$BIN" on
not is_seen 192.168.77.2 9; check S3.lan-closed $? "LAN=false: UDP к 192.168.77.2 не ушёл"
is_seen 192.168.77.2 53; check S3.dns-lan-open $? "open: DNS к LAN 192.168.77.2:53 ушёл и при LAN=false"
write_config true tunnel-up
expect S3.on-tunnel-up 0 "$BIN" on
launchctl kickstart -k "system/$LABEL" # свежий шаг enforce с политикой tunnel-up: проверка здоровья раз в 5 с
s=$(wait_for 60 not is_seen 192.168.77.2 53); [ "$s" != FAIL ]; check S3.dns-up-closed $? "tunnel-up, туннель здоров: DNS к LAN закрыт через $s с"
stop_tunnel
s=$(wait_for 60 is_seen 192.168.77.2 53); [ "$s" != FAIL ]; check S3.dns-down-open $? "tunnel-up, туннель снят: DNS к LAN снова открыт через $s с"
write_config true open
expect S3.on-open 0 "$BIN" on

log "S4: переподключение с новым интерфейсом"
start_tunnel utun97
s=$(wait_for 40 http_ok http://1.1.1.1/); [ "$s" != FAIL ]; check S4.first $? "выход через utun97: $s с"
stop_tunnel
start_tunnel utun98
t=0; leaks=0; back=FAIL
while [ "$t" -le 60 ]; do
  http_ok http://1.0.0.1/ && leaks=$((leaks + 1))
  probe_blocked http 1.1.1.1 "$NIC" >/dev/null 2>&1 || leaks=$((leaks + 1))
  if http_ok http://1.1.1.1/; then back=$t; break; fi
  sleep 1; t=$((t + 1))
done
[ "$back" != FAIL ]; check S4.reconnect $? "выход через новый utun98 вернулся через ~$back с"
[ "$leaks" -eq 0 ]; check S4.no-leak-window $? "прямых проб в окне: утечек $leaks"
stop_tunnel

log "S5: repair — unsupported на macOS"
expect S5.repair-unsupported 2 "$BIN" repair

log "S6: off"
expect S6.off 0 "$BIN" off
sleep 12
http_ok; check S6.untrusted-passes $? "off: ksprobe вышел, правил в якоре $(anchor_rules)"
expect S6.status-off 0 "$BIN" status
expect S6.on-again 0 "$BIN" on
not http_ok; check S6.on-again-blocked $? "on снова закрыл"

log "S7: перезапуск демона до старта клиента"
launchctl kickstart -k "system/$LABEL"
not http_ok; check S7.kickstart-blocked $? "сразу после kickstart -k проба закрыта"
daemon_down
not http_ok; check S7.daemon-stopped-blocked $? "демон снят — правила якоря на месте ($(anchor_rules))"
s=$(daemon_up); [ "$s" != FAIL ]; check S7.daemon-back $? "демон загружен через $s с"
not http_ok; check S7.daemon-started-blocked $? "проба закрыта"

log "S9, S10: правила сняты вручную"
daemon_down
pfctl -q -a "$ANCHOR" -F all
http_ok; check S9.leak-real $? "без правил ksprobe выходит — утечка настоящая (правил в якоре $(anchor_rules))"
expect S9.check-stripped 4 "$BIN" check
expect S9.status-stripped 4 "$BIN" status
daemon_up >/dev/null
s=$(wait_for 60 sh -c "[ \$(pfctl -a '$ANCHOR' -sr 2>/dev/null | grep -c .) -gt 0 ] && '$BIN' status"); [ "$s" != FAIL ]
check S10.restored-flush $? "демон восстановил якорь через $s с"
pfctl -d 2>&1
s=$(wait_for 40 sh -c "pfctl -s info | grep -q 'Status: Enabled' && '$BIN' status"); [ "$s" != FAIL ]
check S10.restored-disable $? "после чужого pfctl -d pf включён своим токеном через $s с"
not http_ok; check S10.after-restore-blocked $? "проба снова закрыта"

log "S9: чужое quick-правило выше якоря — только LEAK, основной набор не перезаписывается"
printf 'pass out quick proto tcp to any port 443\nanchor "com.apple/*"\n' | pfctl -q -f - 2>&1
expect S9.quick-status 4 "$BIN" status
expect S9.quick-check 4 "$BIN" check
sleep 15
first=$(pfctl -sr 2>/dev/null | head -1)
case "$first" in pass*) check S9.quick-no-overwrite 0 "через 15 с первое правило всё ещё чужое: $first" ;;
  *) check S9.quick-no-overwrite 1 "основной набор перезаписан: $first" ;; esac
pfctl -q -f /etc/pf.conf 2>&1
expect S9.quick-gone-status 0 "$BIN" status

log "S8: сломанное состояние и uninstall без конфига"
expect S8.off 0 "$BIN" off
printf '{"gen": 7, "mode": "off", broken' > "$DIR/state.json"
launchctl kickstart -k "system/$LABEL"
s=$(wait_for 60 not http_ok); [ "$s" != FAIL ]; check S8.corrupt-failclosed $? "state.json испорчен в off: демон вернул on через $s с"
daemon_down
for v in on off on off on; do
  "$BIN" "$v" >/dev/null 2>&1 &
  p=$!; sleep "$(awk 'BEGIN{srand(); printf "%.2f", 0.02 + rand() * 0.4}')"; kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
done
"$BIN" status 2>&1
printf 'not json' > "$DIR/state.json"
mv "$DIR/config.toml" "$KS/config.toml.saved"
expect S8.uninstall 0 "$BIN" uninstall
n=$(anchor_rules); t=$(our_tokens)
launchctl print "system/$LABEL" >/dev/null 2>&1 && d=loaded || d=absent
[ "$n" = 0 ] && [ -z "$t" ] && [ "$d" = absent ] && [ ! -e "$PLIST" ]
check S8.removed $? "якорь: правил $n, токены '$t', демон $d"
http_ok; check S8.untrusted-passes $? "после uninstall ksprobe вышел"
ls -la "$DIR" 2>&1

log "Журнал наблюдателя"
tail -40 /var/log/killswitch.log 2>/dev/null

log "Итог"
cat "$RES"
! grep -Eq "^RESULT [^ ]+ FAIL " "$RES"
