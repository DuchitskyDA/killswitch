#!/bin/sh
# Пункт 3: политика «блок на всех интерфейсах, кроме lo0 и туннельного feth2; доверен kstrust».
# Свидетели: ответ сервера в интернете (en0) и захват tcpdump на feth, созданных ПОСЛЕ загрузки правил.
. /private/tmp/ks/lib.sh
begin_segment 420
pf_enable_token >/dev/null
RU=$(runner_uid)

has_v6() { route -n get -inet6 default >/dev/null 2>&1; }
inet_set() { # $1 uid → строки "имя результат"
  echo "tcp80 $(tcp_probe "$1" http://1.1.1.1/)"
  echo "tcp443 $(tcp_probe "$1" https://1.1.1.1/)"
  echo "tcp443-other $(tcp_probe "$1" https://1.0.0.1/)"
  echo "udp53 $(udp_probe "$1" 8.8.8.8)"
  echo "icmp $(icmp_probe "$1" 1.1.1.1)"
  if has_v6; then echo "v6tcp443 $(tcp_probe "$1" 'https://[2606:4700:4700::1111]/')"; else echo "v6tcp443 FAIL no-v6-route"; fi
}
cap_set() { # $1 uid $2 интерфейс(0|2) [$3 полный|trust] → строки
  n=$1; i=$2; v4=$(feth_v4 "$i").2; v6=$(feth_v6 "$i")::2
  if [ "${3:-full}" = full ]; then
    echo "v4tcp80 $(cap_probe "$n" "feth$i" tcp "$v4" 80)"
    echo "v4udp5000 $(cap_probe "$n" "feth$i" udp "$v4" 5000)"
    echo "v6udp5000 $(cap_probe "$n" "feth$i" udp "$v6" 5000)"
  fi
  echo "v6tcp80 $(cap_probe "$n" "feth$i" tcp "$v6" 80)"
  echo "v6tcp443 $(cap_probe "$n" "feth$i" tcp "$v6" 443)"
}
caps() { # $1 префикс файла
  for i in 0 2; do cap_set "$PROBE_UID" "$i" > "$OUT/$1.cap.$PROBE_UID.$i"; done
  cap_set "$TRUST_UID" 0 trust > "$OUT/$1.cap.$TRUST_UID.0"
}
get() { awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print; exit}' "$2"; }

log "Baseline без правил"
for u in "$PROBE_UID" "$TRUST_UID"; do inet_set "$u" > "$OUT/base.inet.$u"; cat "$OUT/base.inet.$u"; done
feth_up 0 >/dev/null; feth_up 2 >/dev/null
caps base; head -50 "$OUT"/base.cap.*
feth_down
base_runner=$(sudo -u "#$RU" /usr/bin/curl -sS -o /dev/null -m 8 -w '%{http_code}' https://api.github.com/ 2>&1)

for st in keep no; do
  log "strict ($st state), feth создаются после загрузки правил"
  policy strict "$st" | load_anchor "$ANCHOR"
  run pfctl -a "$ANCHOR" -sr
  feth_up 0 >/dev/null; feth_up 2 >/dev/null
  for u in "$PROBE_UID" "$TRUST_UID"; do inet_set "$u" > "$OUT/rules.inet.$u"; done
  caps rules
  rr=$(sudo -u "#$RU" /usr/bin/curl -sS -o /dev/null -m 8 -w '%{http_code}' https://api.github.com/ 2>&1)
  run pfctl -a "$ANCHOR" -vsr
  feth_down
  sfx="strict-$st"
  P=$PROBE_UID; T=$TRUST_UID
  for k in tcp80 tcp443 tcp443-other udp53 icmp v6tcp443; do
    classify_block "3.$sfx.probe.inet.$k" "$(get $k "$OUT/base.inet.$P")" "$(get $k "$OUT/rules.inet.$P")" "ksprobe en0"
  done
  for k in v4tcp80 v4udp5000 v6tcp80 v6udp5000 v6tcp443; do
    classify_block "3.$sfx.probe.newif.$k" "$(get $k "$OUT/base.cap.$P.0")" "$(get $k "$OUT/rules.cap.$P.0")" "ksprobe feth0 (новый, чужой)"
    classify_pass "3.$sfx.probe.tunif.$k" "$(get $k "$OUT/base.cap.$P.2")" "$(get $k "$OUT/rules.cap.$P.2")" "ksprobe feth2 (новый, туннельный)"
  done
  classify_pass "3.$sfx.trust.endpoint4" "$(get tcp443 "$OUT/base.inet.$T")" "$(get tcp443 "$OUT/rules.inet.$T")" "kstrust tcp 1.1.1.1:443 (endpoint)"
  classify_block "3.$sfx.trust.sameip-otherport" "$(get tcp80 "$OUT/base.inet.$T")" "$(get tcp80 "$OUT/rules.inet.$T")" "kstrust tcp 1.1.1.1:80"
  classify_block "3.$sfx.trust.otherip" "$(get tcp443-other "$OUT/base.inet.$T")" "$(get tcp443-other "$OUT/rules.inet.$T")" "kstrust tcp 1.0.0.1:443"
  classify_block "3.$sfx.trust.udp53" "$(get udp53 "$OUT/base.inet.$T")" "$(get udp53 "$OUT/rules.inet.$T")" "kstrust dig @8.8.8.8"
  classify_pass "3.$sfx.trust.endpoint6" "$(get v6tcp443 "$OUT/base.cap.$T.0")" "$(get v6tcp443 "$OUT/rules.cap.$T.0")" "kstrust tcp [2001:db8:1::2]:443 на feth0 (endpoint)"
  classify_block "3.$sfx.trust.v6-otherport" "$(get v6tcp80 "$OUT/base.cap.$T.0")" "$(get v6tcp80 "$OUT/rules.cap.$T.0")" "kstrust tcp [2001:db8:1::2]:80 на feth0"
  case "$rr" in [1-5][0-9][0-9]) result "3.$sfx.runner" WORKS "агент-пользователь $(runner_user) https://api.github.com http=$rr (base $base_runner)" ;;
    *) result "3.$sfx.runner" FAILS "runner curl=$rr base=$base_runner" ;; esac
done

log "compat (keep state)"
policy compat keep | load_anchor "$ANCHOR"
for k in tcp80 tcp443-other udp53; do
  case $k in tcp80) r=$(tcp_probe "$TRUST_UID" http://1.1.1.1/) ;; tcp443-other) r=$(tcp_probe "$TRUST_UID" https://1.0.0.1/) ;; udp53) r=$(udp_probe "$TRUST_UID" 8.8.8.8) ;; esac
  classify_pass "3.compat.trust.$k" "$(get $k "$OUT/base.inet.$TRUST_UID")" "$r" "kstrust куда угодно"
  case $k in tcp80) r=$(tcp_probe "$PROBE_UID" http://1.1.1.1/) ;; tcp443-other) r=$(tcp_probe "$PROBE_UID" https://1.0.0.1/) ;; udp53) r=$(udp_probe "$PROBE_UID" 8.8.8.8) ;; esac
  classify_block "3.compat.probe.$k" "$(get $k "$OUT/base.inet.$PROBE_UID")" "$r" "ksprobe"
done
r=$(icmp_probe "$TRUST_UID" 1.1.1.1)
result 3.compat.trust.icmp INFO "kstrust ping 1.1.1.1 под compat: $r (user матчит только tcp/udp)"
