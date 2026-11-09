#!/bin/sh
# Пункт 4: отзыв состояний. Потоки, открытые до ужесточения, — живут ли; pfctl -k по хосту; свидетели к тому же и к другому хосту.
. /private/tmp/ks/lib.sh
begin_segment 240
RU=$(runner_uid)
F="$KS/flow.py"
PYB=${PY:-/usr/bin/python3}
DUR=40

# $1 метка $2 uid $3 tcp|udp $4 хост $5 порт [$6 sport]
flow() {
  f="$OUT/flow.$1.txt"; : > "$f"; chmod 666 "$f"
  sudo -u "#$2" "$PYB" "$F" "$3" "$4" "$5" "$DUR" "$f" ${6:-} >/dev/null 2>&1 &
}
# ok-строки потока в окне [$2, $3] (epoch)
oks() { awk -v a="$2" -v b="$3" '$1>=a && $1<=b && $2=="ok"' "$OUT/flow.$1.txt" | wc -l | tr -d ' '; }
now() { "$PYB" -c 'import time; print(f"{time.time():.2f}")'; }
alive() { # $1 метка $2 от $3 до → ALIVE(n) | DEAD
  n=$(oks "$1" "$2" "$3"); [ "$n" -gt 0 ] && echo "ALIVE($n)" || echo "DEAD"
}
plus() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", a+b}'; }

for fl in default any nostate; do
  log "4.0-$fl: потоки открыты при выключенном pf, затем pf -E и strict (tcp-правило доверенного: flags $fl)"
  flow p0$fl "$PROBE_UID" tcp 1.0.0.1 80
  flow e0$fl "$TRUST_UID" tls 1.1.1.1 443
  sleep 3
  t0=$(now)
  pf_enable_token >/dev/null
  case $fl in any) FLAGS="flags any" policy strict keep ;; nostate) policy strict no ;; *) policy strict keep ;; esac | load_anchor "$ANCHOR"
  run pfctl -a "$ANCHOR" -sr
  sleep 5; t1=$(now)
  pre=$(alive p0$fl "$(plus "$t0" -3)" "$t0"); post=$(alive p0$fl "$(plus "$t0" 2)" "$t1")
  case "$pre" in ALIVE*) case "$post" in DEAD) result "4.pf-off-flow.probe.$fl" BLOCKED "ksprobe tcp 1.0.0.1:80, открыт до включения pf: до=$pre после=$post" ;;
    *) result "4.pf-off-flow.probe.$fl" LEAK "до=$pre после=$post" ;; esac ;; *) result "4.pf-off-flow.probe.$fl" INCONCLUSIVE "до=$pre" ;; esac
  pre=$(alive e0$fl "$(plus "$t0" -3)" "$t0"); post=$(alive e0$fl "$(plus "$t0" 2)" "$t1")
  case "$pre" in ALIVE*) case "$post" in ALIVE*) result "4.pf-off-flow.trust-endpoint.$fl" WORKS "kstrust tls 1.1.1.1:443 (endpoint), открыт до включения pf: до=$pre после=$post" ;;
    *) result "4.pf-off-flow.trust-endpoint.$fl" FAILS "разрешённый поток оборван: до=$pre после=$post" ;; esac ;; *) result "4.pf-off-flow.trust-endpoint.$fl" INCONCLUSIVE "до=$pre" ;; esac
  stop_flows; tail -3 "$OUT/flow.e0$fl.txt"
  pfctl -q -a "$ANCHOR" -F all; release_tokens; pfctl -d >/dev/null 2>&1; sleep 1
done
pf_enable_token >/dev/null

for st in keep no; do
  log "4.$st: permissive ($st state) → потоки → strict ($st state) → pfctl -k"
  policy open "$st" | load_anchor "$ANCHOR"
  pfctl -F states >/dev/null 2>&1
  flow P$st "$PROBE_UID" tcp 1.0.0.1 80
  flow T$st "$TRUST_UID" tcp 1.0.0.1 80
  flow U$st "$TRUST_UID" udp 8.8.8.8 53 4005$([ $st = keep ] && echo 3 || echo 4)
  flow B$st "$RU" tcp 1.1.1.1 80
  flow S$st "$RU" tcp 1.0.0.1 80
  sleep 4
  t0=$(now)
  policy strict "$st" | load_anchor "$ANCHOR"
  sleep 5; t1=$(now)
  run sh -c "pfctl -ss 2>/dev/null | grep -E '1\.0\.0\.1|1\.1\.1\.1|8\.8\.8\.8'"
  run pfctl -s info
  for m in P T U B S; do eval "pre_$m=\$(alive $m$st \$(plus $t0 -3) $t0)"; eval "mid_$m=\$(alive $m$st \$(plus $t0 2) $t1)"; done
  echo "до strict: P=$pre_P T=$pre_T U=$pre_U B=$pre_B S=$pre_S; после strict: P=$mid_P T=$mid_T U=$mid_U B=$mid_B S=$mid_S"
  for m in P T U; do
    eval "a=\$pre_$m b=\$mid_$m"
    case "$a" in ALIVE*) case "$b" in DEAD) result "4.$st.strict.$m" BLOCKED "после strict без kill: до=$a после=$b" ;;
      *) result "4.$st.strict.$m" LEAK "после strict без kill поток жив: до=$a после=$b" ;; esac ;; *) result "4.$st.strict.$m" INCONCLUSIVE "до=$a" ;; esac
  done
  for m in B S; do eval "b=\$mid_$m"; result "4.$st.strict.bystander.$m" INFO "свидетель runner после strict: $b"; done

  log "pfctl -k 0.0.0.0/0 -k 1.0.0.1 и -k 0.0.0.0/0 -k 8.8.8.8"
  run pfctl -k 0.0.0.0/0 -k 1.0.0.1
  run pfctl -k 0.0.0.0/0 -k 8.8.8.8
  t2=$(now); sleep 5; t3=$(now)
  for m in P T U B S; do eval "k_$m=\$(alive $m$st \$(plus $t2 2) $t3)"; done
  echo "после -k: P=$k_P T=$k_T U=$k_U B=$k_B S=$k_S"
  result "4.$st.kill" INFO "после pfctl -k по хосту: P(ksprobe→1.0.0.1)=$k_P T(kstrust→1.0.0.1)=$k_T U(kstrust udp→8.8.8.8:53)=$k_U B(runner→1.1.1.1, другой хост)=$k_B S(runner→1.0.0.1, тот же хост)=$k_S"
  stop_flows; sleep 1
  for m in P T U B S; do echo "-- flow $m$st"; tail -4 "$OUT/flow.$m$st.txt"; done
done

log "Отзыв по метке/интерфейсу: поддерживает ли pfctl"
run pfctl -k label -k ks
run pfctl -K 0.0.0.0/0 -K 1.0.0.1
