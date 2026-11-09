#!/bin/sh
# Разбор двух аномалий прогона 2: (а) v6 UDP не виден в захвате и без правил; (б) v6-endpoint доверенного пропущен
# правилом pf (счётчик растёт), но на feth0 не виден. Захват сразу на нескольких интерфейсах, маршрут и NDP.
. /private/tmp/ks/lib.sh
begin_segment 240

# $1 uid $2 tcp|udp $3 адрес $4 порт → "имя_интерфейса:SEEN/NOTSEEN ..."
cap_multi() {
  uid=$1; proto=$2; dst=$3; port=$4; pids=""
  for i in feth0 en0 utun0 utun1 utun2 utun3 lo0; do
    tcpdump -n -l -i "$i" "dst host $dst and $proto dst port $port" > "$OUT/cm.$i" 2>/dev/null &
    pids="$pids $!"
  done
  sleep 1
  if [ "$proto" = tcp ]; then sudo -u "#$uid" nc -z -G 2 -w 2 "$dst" "$port" >/dev/null 2>&1
  else for k in 1 2 3; do printf x | sudo -u "#$uid" nc -u -w 1 "$dst" "$port" >/dev/null 2>&1; done; fi
  sleep 1
  kill $pids 2>/dev/null; wait 2>/dev/null
  r=""; for i in feth0 en0 utun0 utun1 utun2 utun3 lo0; do n=$(grep -c "$dst" "$OUT/cm.$i"); [ "$n" -gt 0 ] && r="$r $i:$n"; done
  echo "seen[${r:- none}]"
}
diag() {
  run route -n get -inet6 2001:db8:1::2
  run sh -c "ndp -an | grep -i 2001:db8"
  run sh -c "ifconfig feth0 | grep inet6"
}

log "A. pf выключен, feth0 есть"
pfctl -d >/dev/null 2>&1
feth_up 0 >/dev/null; diag
echo "A udp6 probe: $(cap_multi "$PROBE_UID" udp 2001:db8:1::2 5000)"
echo "A tcp6 trust 443: $(cap_multi "$TRUST_UID" tcp 2001:db8:1::2 443)"
echo "A udp6 probe again: $(cap_multi "$PROBE_UID" udp 2001:db8:1::2 5000)"
result 3b.udp6-pf-off INFO "$(cap_multi "$PROBE_UID" udp 2001:db8:1::2 5000)"

log "B. pf включён, якорь пуст"
pf_enable_token >/dev/null
echo "B udp6 probe: $(cap_multi "$PROBE_UID" udp 2001:db8:1::2 5000)"
echo "B udp4 probe: $(cap_multi "$PROBE_UID" udp 198.18.0.2 5000)"
result 3b.udp6-pf-on INFO "$(cap_multi "$PROBE_UID" udp 2001:db8:1::2 5000)"
run sh -c "pfctl -vsr 2>/dev/null; pfctl -s info 2>/dev/null | grep -E 'match|normalize|fragment|short|bad'"

log "C. strict, feth0 существовал до загрузки"
{ policy strict keep; } | sed 's/^block return out quick all$/pass out quick inet proto tcp to 198.18.0.2 port 443 user '"$TRUST_UID"'\nblock return out quick all/' | load_anchor "$ANCHOR"
run pfctl -a "$ANCHOR" -sr
diag
c1=$(cap_multi "$TRUST_UID" tcp 2001:db8:1::2 443); echo "C trust tcp6 443: $c1"
c2=$(cap_multi "$TRUST_UID" tcp 198.18.0.2 443); echo "C trust tcp4 443 (endpoint v4 на feth0): $c2"
run sh -c "pfctl -a '$ANCHOR' -vsr 2>/dev/null | grep -A1 -E '6002'"
run sh -c "pfctl -ss 2>/dev/null | grep -E '2001:db8|198\.18'"
result 3b.endpoint6-oldif INFO "trust tcp6 [2001:db8:1::2]:443: $c1; trust tcp4 198.18.0.2:443: $c2"

log "D. strict, feth0 пересоздан под правилами"
feth_down; feth_up 0 >/dev/null; diag
d1=$(cap_multi "$TRUST_UID" tcp 2001:db8:1::2 443); d2=$(cap_multi "$TRUST_UID" tcp 198.18.0.2 443)
run sh -c "pfctl -ss 2>/dev/null | grep -E '2001:db8|198\.18'"
result 3b.endpoint6-newif INFO "trust tcp6: $d1; trust tcp4: $d2"

log "E. только user=6002 (без адреса), v6 tcp 80"
{ safety_rules; echo "pass out quick proto tcp user $TRUST_UID"; echo "block return out quick all"; } | load_anchor "$ANCHOR"
e1=$(cap_multi "$TRUST_UID" tcp 2001:db8:1::2 80); e2=$(cap_multi "$TRUST_UID" tcp 198.18.0.2 80)
run sh -c "pfctl -a '$ANCHOR' -vsr 2>/dev/null | grep -A1 -E '6002'"
result 3b.user6 INFO "user-only: tcp6 :80 $e1; tcp4 :80 $e2"

log "F. endpoint v6 без user (любой процесс к адресу:порту)"
{ safety_rules; echo "pass out quick inet6 proto tcp to 2001:db8:1::2 port 443"; echo "block return out quick all"; } | load_anchor "$ANCHOR"
f1=$(cap_multi "$PROBE_UID" tcp 2001:db8:1::2 443)
result 3b.endpoint6-nouser INFO "без user: tcp6 :443 от ksprobe $f1"
