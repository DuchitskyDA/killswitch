#!/bin/sh
# Самопроверка сторожа: безвредное правило в якоре + свой токен, сторож на 10 с из launchd, проверка сброса.
. /private/tmp/ks/lib.sh

t=$(pf_enable_token)
echo "token=$t"
echo 'pass out quick on lo0 proto udp to 127.0.0.1 port 9 no state' | load_anchor "$ANCHOR"
run pfctl -a "$ANCHOR" -sr
run pfctl -s References
arm_watchdog 10
run launchctl print "system/$WD_LABEL"
sleep 20
run cat "$OUT/watchdog.log"
n=$(anchor_rules | wc -l | tr -d ' ')
refs=$(pfctl -s References 2>/dev/null | grep -c "$t")
st=$(pfctl -s info | awk '/^Status/{print $2}')
echo "after: anchor_rules=$n our_token_in_refs=$refs status=$st"
if grep -q FIRED "$OUT/watchdog.log" && [ "$n" -eq 0 ] && [ "$refs" -eq 0 ]; then
  result 6.watchdog WORKS "LaunchDaemon-сторож сработал через 10 с: якорь пуст, токен отпущен, pf=$st"
else
  result 6.watchdog FAILS "fired=$(grep -c FIRED "$OUT/watchdog.log") anchor_rules=$n token_refs=$refs pf=$st"
fi
disarm_watchdog
: > "$TOKENS"
