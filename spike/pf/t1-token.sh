#!/bin/sh
# Пункт 1: токены pfctl -E / -X, потерянный токен, pfctl -d и -e. Блокирующих правил нет.
. /private/tmp/ks/lib.sh
begin_segment 120

init=$(cat "$KS/pf_initial")
status() { pfctl -s info 2>/dev/null | awk '/^Status/{print $2}'; }
refs() { pfctl -s References 2>/dev/null; }
has_ref() { refs | grep -q -w "$1"; }

if [ "$init" != Disabled ]; then
  result 1.token INCONCLUSIVE "pf исходно $init — сценарий рассчитан на выключенный pf"
  exit 0
fi

log "Два своих токена"
a=$(pf_enable_token); b=$(pf_enable_token)
run pfctl -s References
echo "a=$a b=$b status=$(status)"
pfctl -X "$a" >/dev/null 2>&1
s1=$(status)
run pfctl -X "$a"; rc_again=$?
echo "после -X a: status=$s1; повторный -X a rc=$rc_again"
[ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] && [ "$s1" = Enabled ] && [ "$rc_again" -ne 0 ] \
  && result 1.token WORKS "pfctl -E дал разные токены $a/$b; -X одного оставил pf Enabled (держит второй); повторный -X rc=$rc_again" \
  || result 1.token FAILS "a=$a b=$b status_after_X=$s1 rc_again=$rc_again"

log "Потерянный токен: ищем в pfctl -s References"
run pfctl -s References
found=$(refs | awk -v t="$b" '{for(i=1;i<=NF;i++) if($i==t) print $i}' | head -1)
pfctl -X "$found" >/dev/null 2>&1
s2=$(status)
echo "found=$found status=$s2"
[ "$found" = "$b" ] && [ "$s2" = Disabled ] \
  && result 1.lost WORKS "токен виден в pfctl -s References (pid/имя процесса/время); -X найденного выключил pf" \
  || result 1.lost FAILS "found=$found status=$s2"
: > "$TOKENS"

log "pfctl -d при чужом токене"
c=$(pf_enable_token)
run pfctl -s References
run pfctl -d
s3=$(status)
has_ref "$c"; still=$?
run pfctl -X "$c"; rc_c=$?
echo "status=$s3 token_still_listed=$([ $still -eq 0 ] && echo yes || echo no) -X rc=$rc_c"
result 1.disable INFO "pfctl -d при токене чужого: status=$s3, токен в References=$([ $still -eq 0 ] && echo да || echo нет), -X после -d rc=$rc_c"
: > "$TOKENS"

log "pfctl -e без токена, затем свой -E/-X"
run pfctl -e
d=$(pf_enable_token)
run pfctl -s References
pfctl -X "$d" >/dev/null 2>&1
s4=$(status)
echo "после -e, -E, -X: status=$s4"
result 1.legacy INFO "после pfctl -e + свой -E/-X статус=$s4 (Enabled — -X не снимает чужой -e)"
: > "$TOKENS"
pfctl -d >/dev/null 2>&1

log "Токен после смерти процесса: pfctl -E из sh, который сразу завершился"
e=$(sh -c 'pfctl -E 2>&1' | awk '/^Token/{print $3}'); echo "$e" >> "$TOKENS"
sleep 1
has_ref "$e" && alive=yes || alive=no
run pfctl -s References
result 1.process INFO "токен $e пережил процесс pfctl: $alive; pf=$(status)"
