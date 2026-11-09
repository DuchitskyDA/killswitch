#!/bin/sh
# Пункт 2: достижимость якоря под com.apple/*, канарейка на счётчиках, конфликтующие quick-правила, порядок соседей.
. /private/tmp/ks/lib.sh
begin_segment 180
pf_enable_token >/dev/null

CANARY='pass out quick on lo0 proto udp to 127.0.0.1 port 9 no state label "ks-canary"'
# Пакеты канарейки: счётчик из pfctl -vsr нашего якоря.
canary_pkts() { pfctl -a "$ANCHOR" -vsr 2>/dev/null | awk '/ks-canary/{f=1;next} f&&/Packets:/{for(i=1;i<=NF;i++) if($i=="Packets:") {print $(i+1); exit}}'; }
canary_hit() { # печатает HIT или MISS
  p0=$(canary_pkts); printf x | nc -u -w 1 127.0.0.1 9 >/dev/null 2>&1; sleep 0.5; p1=$(canary_pkts)
  [ "${p1:-0}" -gt "${p0:-0}" ] && echo "HIT($p0->$p1)" || echo "MISS($p0->$p1)"
}
# Блок-набор с канарейкой: ksprobe закрыт, страховка раннера открыта.
load_block() { { echo "$CANARY"; policy strict keep; } | load_anchor "$ANCHOR"; }
main_first_rule() { pfctl -sr 2>/dev/null | head -1; }
main_ok() { main_first_rule | grep -q '^anchor "com.apple/\*"'; }

log "Baseline ksprobe без правил"
base=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
echo "base=$base"

log "Штатный основной набор + наш якорь"
load_block
run pfctl -a "$ANCHOR" -sr
run pfctl -sr
c=$(canary_hit); p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
run pfctl -a "$ANCHOR" -vsr
case "$c" in HIT*) result 2.reach WORKS "канарейка на lo0 считается в pfctl -a $ANCHOR -vsr: $c; ksprobe https=$p" ;;
  *) result 2.reach FAILS "канарейка $c; ksprobe https=$p" ;; esac
classify_block 2.block-default "$base" "$p" "ksprobe tcp/443 под штатным pf.conf"

log "Основной набор без anchor com.apple/*"
touch "$KS/main_dirty"
echo 'pass all' | pfctl -q -f - 2>&1
run pfctl -sr
n=$(anchor_rules | wc -l | tr -d ' ')
c=$(canary_hit); p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
main_ok && m=ok || m=bad
result 2.no-anchor INFO "правил в нашем якоре осталось $n (живы, но не вызываются); канарейка $c; структурная проверка main=$m; ksprobe https=$p"

log "Широкое quick-правило выше якоря"
printf 'pass out quick all\nanchor "com.apple/*"\n' | pfctl -q -f - 2>&1
run pfctl -sr
c=$(canary_hit); p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
main_ok && m=ok || m=bad
result 2.quick-wide INFO "pass out quick all выше якоря: канарейка $c, main=$m, ksprobe https=$p"

log "Узкое quick-правило выше якоря (канарейка его не видит)"
printf 'pass out quick proto tcp to any port 443\nanchor "com.apple/*"\n' | pfctl -q -f - 2>&1
run pfctl -sr
c=$(canary_hit); p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
main_ok && m=ok || m=bad
result 2.quick-narrow INFO "pass quick tcp/443 выше якоря: канарейка $c, main=$m (первое правило: $(main_first_rule)), ksprobe https=$p"

log "quick в якоре окончателен: pass out quick all ПОСЛЕ anchor"
{ cat /etc/pf.conf; echo 'pass out quick all'; } | pfctl -q -f - 2>&1
run pfctl -sr
p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
classify_block 2.quick-final "$base" "$p" "основной набор: anchor com.apple/* затем pass out quick all"

log "Возврат /etc/pf.conf: якорь снова достижим без перезагрузки якоря"
pfctl -q -f /etc/pf.conf 2>&1; rm -f "$KS/main_dirty"
run pfctl -sr
n=$(anchor_rules | wc -l | tr -d ' ')
c=$(canary_hit); p=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
result 2.reload-conf INFO "после pfctl -f /etc/pf.conf: правил в якоре $n, канарейка $c, ksprobe https=$p"

log "Соседние якоря: 400 (раньше нашего 500) и 600 (позже) с pass quick для ksprobe"
echo "pass out quick proto tcp user $PROBE_UID" | load_anchor com.apple/600.ks-sibling
run pfctl -a com.apple -s Anchors
p6=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
pfctl -q -a com.apple/600.ks-sibling -F all
echo "pass out quick proto tcp user $PROBE_UID" | load_anchor com.apple/400.ks-sibling
p4=$(tcp_probe "$PROBE_UID" https://1.1.1.1/)
run pfctl -a com.apple -s Anchors
pfctl -q -a com.apple/400.ks-sibling -F all
classify_block 2.sibling-after "$base" "$p6" "сосед 600 позже нашего 500"
result 2.sibling-before INFO "сосед 400 раньше нашего 500 с pass quick: ksprobe https=$p4 (OK = сосед перебил)"

log "Перезагрузка родителя com.apple из файла"
pfctl -q -a com.apple -f /etc/pf.anchors/com.apple 2>&1
n=$(anchor_rules | wc -l | tr -d ' ')
c=$(canary_hit)
result 2.reload-parent INFO "pfctl -a com.apple -f /etc/pf.anchors/com.apple: правил в нашем якоре $n, канарейка $c"
run pfctl -a com.apple -s Anchors
