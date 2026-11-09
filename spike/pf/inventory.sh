#!/bin/sh
# Инвентаризация раннера: ничего не меняет в pf. Под root.
. /private/tmp/ks/lib.sh

log "ОС и SIP"
run sw_vers
run uname -a
run csrutil status
echo "ImageOS=${ImageOS:-} ImageVersion=${ImageVersion:-}"

log "Агент раннера и его пользователь"
run sh -c "ps -axo user=,uid=,pid=,command= | grep -E -i 'Runner\.(Listener|Worker)|provjobd|actions' | grep -v grep"
ru=$(ps -axo user=,command= | awk '/Runner\.Listener/ && !/awk/ {print $1; exit}')
[ -n "$ru" ] || ru=${SUDO_USER:-runner}
echo "$ru" > "$KS/runner_user"
echo "runner_user=$ru uid=$(id -u "$ru")"
run sh -c "ps -axo user= | sort | uniq -c | sort -rn"

log "/dev/pf и pfctl"
run ls -l /dev/pf
run pfctl -s info
st=$(pfctl -s info 2>/dev/null | awk '/^Status/{print $2}')
echo "${st:-Unknown}" > "$KS/pf_initial"
result 1.dev "$( [ -c /dev/pf ] && [ -n "$st" ] && echo WORKS || echo FAILS)" "/dev/pf char device, pfctl -s info под sudo: Status=$st"
result 1.default INFO "pf по умолчанию: $st"
run pfctl -s References
run pfctl -sr
run pfctl -sn
run pfctl -s Anchors
run pfctl -a com.apple -s Anchors
run pfctl -a com.apple -sr
for a in $(pfctl -a com.apple -s Anchors 2>/dev/null); do
  run pfctl -a "$a" -sr
  run pfctl -a "$a" -s Anchors
done

log "/etc/pf.conf и якоря Apple"
run cat /etc/pf.conf
run ls -l /etc/pf.anchors
run cat /etc/pf.anchors/com.apple

log "Справка pfctl"
man pfctl 2>/dev/null | col -b > "$OUT/man-pfctl.txt"
run sh -c "grep -n -E '^ +-[kKXEedis]' '$OUT/man-pfctl.txt'"
run sh -c "awk '/^ +-k /,/^ +-[l-z] /' '$OUT/man-pfctl.txt' | head -60"
run sh -c "pfctl -h 2>&1 | head -20"

log "Сеть"
run ifconfig -l
run networksetup -listallhardwareports
run netstat -rn
run route -n get default
run route -n get -inet6 default
run ifconfig
run sh -c "scutil --dns | head -30"

log "Клонируемые интерфейсы"
run ifconfig -C
if feth_up 0; then
  run ifconfig feth0
  run ifconfig feth1
  run netstat -rn -f inet6
  for p in "tcp 198.18.0.2 80" "udp 198.18.0.2 5000" "tcp 2001:db8:1::2 80" "udp 2001:db8:1::2 5000"; do
    set -- $p
    r=$(cap_probe "$PROBE_UID" feth0 "$1" "$2" "$3" 2>/dev/null || true)
    echo "baseline feth0 $p -> $r (uid $PROBE_UID; пользователь может ещё не существовать)"
  done
else
  echo "feth не создаётся"
fi
feth_down
run ifconfig -l
