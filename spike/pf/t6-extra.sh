#!/bin/sh
# Добор к рекомендации «правила якоря без состояния»: compat без состояния, UDP-endpoint (keep/no),
# UDP-поток, открытый до включения pf, и имя процесса в pfctl -s References для токена из переименованной копии pfctl.
. /private/tmp/ks/lib.sh
begin_segment 240
F="$KS/flow.py"; PYB=${PY:-/usr/bin/python3}

flow() { f="$OUT/flow.$1.txt"; : > "$f"; chmod 666 "$f"; sudo -u "#$2" "$PYB" "$F" "$3" "$4" "$5" 30 "$f" ${6:-} >/dev/null 2>&1 & }
oks() { awk -v a="$2" -v b="$3" '$1>=a && $1<=b && $2=="ok"' "$OUT/flow.$1.txt" | wc -l | tr -d ' '; }
now() { "$PYB" -c 'import time; print(f"{time.time():.2f}")'; }
plus() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", a+b}'; }
alive() { n=$(oks "$1" "$2" "$3"); [ "$n" -gt 0 ] && echo "ALIVE($n)" || echo "DEAD"; }
udp_strict() { # $1 keep|no
  if [ "$1" = no ]; then st="no state"; else st="keep state"; fi
  safety_rules "$st"
  echo "pass out quick inet proto udp to 1.1.1.1 port 53 user $TRUST_UID $st"
  echo "block return out quick all"
}

log "Baseline"
b_t80=$(tcp_probe "$TRUST_UID" http://1.1.1.1/); b_t443o=$(tcp_probe "$TRUST_UID" https://1.0.0.1/)
b_tu8=$(udp_probe "$TRUST_UID" 8.8.8.8); b_tu1=$(udp_probe "$TRUST_UID" 1.1.1.1)
b_p80=$(tcp_probe "$PROBE_UID" http://1.1.1.1/); b_pu1=$(udp_probe "$PROBE_UID" 1.1.1.1)
echo "t80=$b_t80 t443o=$b_t443o tu8=$b_tu8 tu1=$b_tu1 p80=$b_p80 pu1=$b_pu1"

log "C. UDP-поток kstrust→1.1.1.1:53 открыт при выключенном pf, затем strict-udp без состояния"
flow cu "$TRUST_UID" udp 1.1.1.1 53 40061
flow cp "$PROBE_UID" udp 1.1.1.1 53 40062
sleep 3; t0=$(now)
pf_enable_token >/dev/null
udp_strict no | load_anchor "$ANCHOR"
sleep 5; t1=$(now)
pre=$(alive cu "$(plus "$t0" -3)" "$t0"); post=$(alive cu "$(plus "$t0" 2)" "$t1")
case "$pre" in ALIVE*) case "$post" in ALIVE*) result 6.udpflow.trust.nostate WORKS "kstrust udp 1.1.1.1:53 (endpoint), поток до включения pf: до=$pre после=$post" ;;
  *) result 6.udpflow.trust.nostate FAILS "до=$pre после=$post" ;; esac ;; *) result 6.udpflow.trust.nostate INCONCLUSIVE "до=$pre" ;; esac
pre=$(alive cp "$(plus "$t0" -3)" "$t0"); post=$(alive cp "$(plus "$t0" 2)" "$t1")
case "$pre" in ALIVE*) case "$post" in DEAD) result 6.udpflow.probe.nostate BLOCKED "ksprobe udp 1.1.1.1:53: до=$pre после=$post" ;;
  *) result 6.udpflow.probe.nostate LEAK "до=$pre после=$post" ;; esac ;; *) result 6.udpflow.probe.nostate INCONCLUSIVE "до=$pre" ;; esac
stop_flows

for st in keep no; do
  log "B. strict с UDP-endpoint 1.1.1.1:53 ($st state)"
  udp_strict "$st" | load_anchor "$ANCHOR"
  classify_pass "6.strict-udp-$st.trust.endpoint" "$b_tu1" "$(udp_probe "$TRUST_UID" 1.1.1.1)" "kstrust dig @1.1.1.1 (endpoint udp)"
  classify_block "6.strict-udp-$st.trust.other" "$b_tu8" "$(udp_probe "$TRUST_UID" 8.8.8.8)" "kstrust dig @8.8.8.8"
  classify_block "6.strict-udp-$st.trust.tcp-same-ip" "$b_t80" "$(tcp_probe "$TRUST_UID" http://1.1.1.1/)" "kstrust tcp 1.1.1.1:80"
  classify_block "6.strict-udp-$st.probe.endpoint" "$b_pu1" "$(udp_probe "$PROBE_UID" 1.1.1.1)" "ksprobe dig @1.1.1.1"
done

log "A. compat без состояния"
policy compat no | load_anchor "$ANCHOR"
run pfctl -a "$ANCHOR" -sr
classify_pass 6.compat-no.trust.tcp80 "$b_t80" "$(tcp_probe "$TRUST_UID" http://1.1.1.1/)" "kstrust"
classify_pass 6.compat-no.trust.tcp443-other "$b_t443o" "$(tcp_probe "$TRUST_UID" https://1.0.0.1/)" "kstrust"
classify_pass 6.compat-no.trust.udp53 "$b_tu8" "$(udp_probe "$TRUST_UID" 8.8.8.8)" "kstrust"
classify_block 6.compat-no.probe.tcp80 "$b_p80" "$(tcp_probe "$PROBE_UID" http://1.1.1.1/)" "ksprobe"
classify_block 6.compat-no.probe.udp53 "$b_pu1" "$(udp_probe "$PROBE_UID" 1.1.1.1)" "ksprobe"

log "D. Имя процесса в References для токена из переименованной копии pfctl"
cp /sbin/pfctl "$KS/killswitchd"; chmod 755 "$KS/killswitchd"
t=$("$KS/killswitchd" -E 2>&1 | awk '/^Token/{print $3}'); echo "$t" >> "$TOKENS"
run pfctl -s References
name=$(pfctl -s References 2>/dev/null | awk -v t="$t" '$3==t{print $2}')
result 6.token-name INFO "токен из копии pfctl под именем killswitchd: имя в References='$name' (token $t)"
