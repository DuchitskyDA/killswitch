#!/bin/sh
# Независимый сторож: запускается LaunchDaemon'ом, через $1 секунд сбрасывает всё, что поставил спайк.
. /private/tmp/ks/lib.sh
echo "watchdog armed $(date +%T) for $1 s, pid $$"
sleep "$1"
echo "watchdog FIRED $(date +%T)"
reset_all watchdog
