#!/bin/sh
# Пробные пользователи: ksprobe (не доверен) и kstrust (доверен в политике). Под root.
. /private/tmp/ks/lib.sh

mkuser() { # $1 имя $2 uid
  if ! id "$1" >/dev/null 2>&1; then
    dscl . -create "/Users/$1"
    dscl . -create "/Users/$1" UniqueID "$2"
    dscl . -create "/Users/$1" PrimaryGroupID 20
    dscl . -create "/Users/$1" UserShell /usr/bin/false
    dscl . -create "/Users/$1" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$1" RealName "ks spike $1"
  fi
  run id "$1"
}
mkuser ksprobe "$PROBE_UID"
mkuser kstrust "$TRUST_UID"
: > "$TOKENS"
run sudo -u "#$PROBE_UID" /usr/bin/curl -sS -o /dev/null -m 5 -w 'probe-user curl http=%{http_code}\n' http://1.1.1.1/
