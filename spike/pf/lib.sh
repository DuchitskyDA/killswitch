# Общие функции спайка pf. Подключается через `. lib.sh`; всё запускается под root на одноразовом раннере.
# Ничего здесь не предназначено для запуска на рабочей машине.

KS=/private/tmp/ks
OUT="$KS/out"
RES="$OUT/results.txt"
ANCHOR="com.apple/500.ks-spike"
EXTRA_ANCHORS="com.apple/400.ks-sibling com.apple/600.ks-sibling"
TOKENS="$KS/tokens.txt"
PROBE_UID=6001
TRUST_UID=6002
WD_LABEL="ks.spike.watchdog"
WD_PLIST="/Library/LaunchDaemons/$WD_LABEL.plist"
EN_LABEL="ks.spike.enforce"
EN_PLIST="/Library/LaunchDaemons/$EN_LABEL.plist"

mkdir -p "$OUT"

log() { printf '\n== %s\n' "$*"; }

# Выполнить и показать команду с кодом возврата; не прерывает скрипт.
run() {
  printf '$ %s\n' "$*"
  "$@" 2>&1
  rc=$?
  printf '[rc=%s]\n' "$rc"
  return "$rc"
}

result() {
  id=$1; cls=$2; shift 2
  printf 'RESULT %s %s %s\n' "$id" "$cls" "$*" | tee -a "$RES"
}

runner_user() { cat "$KS/runner_user" 2>/dev/null || echo runner; }
runner_uid() { id -u "$(runner_user)"; }
mdns_uid() { id -u _mdnsresponder 2>/dev/null || echo 65; }

pf_enabled() { pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; }

pf_enable_token() {
  t=$(pfctl -E 2>&1 | awk '/^Token/{print $3}')
  [ -n "$t" ] && echo "$t" >> "$TOKENS"
  echo "$t"
}

release_tokens() {
  [ -s "$TOKENS" ] || return 0
  while read -r t; do
    [ -n "$t" ] && pfctl -X "$t" >/dev/null 2>&1
  done < "$TOKENS"
  : > "$TOKENS"
}

load_anchor() { # $1 якорь, правила со stdin
  pfctl -q -a "$1" -f - 2>&1
}

anchor_rules() { pfctl -a "${1:-$ANCHOR}" -sr 2>/dev/null; }

# Страховка раннера в каждом наборе: агент раннера (uid runner), root и DNS системного резолвера не блокируем.
# flags any: уже открытые соединения агента (без состояния pf) не получают RST при первой загрузке блока.
safety_rules() {
  st=${1:-keep state}
  cat <<EOF
pass out quick on lo0 all no state
pass out quick proto tcp user { 0 $(runner_uid) } flags any $st
pass out quick proto udp user { 0 $(runner_uid) } $st
pass out quick proto { tcp udp } to port 53 user $(mdns_uid) $st
pass out quick inet proto udp from port 68 to port 67 no state
pass out quick inet6 proto udp from port 546 to port 547 no state
pass out quick inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol } no state
EOF
}

# Политика спайка: блок на всех интерфейсах, кроме lo0 и туннельного feth2;
# доверенный kstrust — куда угодно (compat) или только к endpoint (strict).
TUN_IF=feth2
policy() { # $1 compat|strict|open  $2 keep|no; FLAGS="flags any" — для tcp-правил доверенного в strict
  mode=$1
  if [ "${2:-keep}" = no ]; then st="no state"; else st="keep state"; fi
  safety_rules "$st"
  echo "pass out quick on $TUN_IF all $st"
  case "$mode" in
    compat) echo "pass out quick proto { tcp udp } user $TRUST_UID $st" ;;
    strict)
      echo "pass out quick inet proto tcp to 1.1.1.1 port 443 user $TRUST_UID ${FLAGS:-} $st"
      echo "pass out quick inet6 proto tcp to 2001:db8:1::2 port 443 user $TRUST_UID ${FLAGS:-} $st"
      ;;
    open) echo "pass out quick all $st" ;;
  esac
  [ "$mode" = open ] || echo "block return out quick all"
}

# feth-пара: $1 номер «нашего» конца (0 или 2), подсеть 198.18+N/2.0.0/24 и 2001:db8:(N/2+1)::/64.
# Статические ARP/NDP, чтобы в захвате был сам IP-пакет, а не запрос разрешения адреса.
feth_v4() { echo "198.$((18 + $1 / 2)).0"; }
feth_v6() { echo "2001:db8:$(($1 / 2 + 1))"; }
feth_up() {
  a=$1; b=$(($1 + 1)); v4=$(feth_v4 "$a"); v6=$(feth_v6 "$a")
  ifconfig "feth$a" create 2>&1 || return 1
  ifconfig "feth$b" create 2>&1 || return 1
  ifconfig "feth$a" peer "feth$b" 2>&1
  ifconfig "feth$a" inet "$v4.1/24" up 2>&1
  ifconfig "feth$b" up 2>&1
  ifconfig "feth$a" inet6 "$v6::1" prefixlen 64 2>&1
  arp -s "$v4.2" 02:00:00:00:00:02 2>&1
  w=0   # DAD: TCP по v6 с адреса tentative не уходит
  while ifconfig "feth$a" | grep "$v6::1 " | grep -q tentative && [ "$w" -lt 20 ]; do sleep 0.5; w=$((w + 1)); done
  sleep 1
  ndp -s "$v6::2" 02:00:00:00:00:02 2>&1
  return 0
}
feth_down() {
  for i in 0 1 2 3; do ifconfig "feth$i" destroy >/dev/null 2>&1; done
  return 0
}

# Отправить один пакет от uid и посмотреть захватом, ушёл ли он с интерфейса.
# $1 uid  $2 интерфейс  $3 tcp|udp  $4 адрес  $5 порт.  Печатает SEEN или NOTSEEN.
cap_probe() {
  uid=$1; ifc=$2; proto=$3; dst=$4; port=$5
  cap="$OUT/cap.$$.txt"
  tcpdump -n -l -i "$ifc" "dst host $dst and $proto dst port $port" > "$cap" 2>/dev/null &
  tp=$!
  sleep 1
  if [ "$proto" = tcp ]; then
    err=$(sudo -u "#$uid" nc -z -G 2 -w 2 "$dst" "$port" 2>&1 | tr '\n' ' ')
  else
    err=$(printf x | sudo -u "#$uid" nc -u -w 1 "$dst" "$port" 2>&1 | tr '\n' ' ')
  fi
  sleep 1
  kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
  if grep -q "$dst" "$cap"; then echo SEEN; else echo "NOTSEEN ${err:-}" | cut -c1-80; fi
  rm -f "$cap"
}

# Интернет-пробы от uid. Печатают OK <деталь> или FAIL <деталь>.
tcp_probe() { # $1 uid $2 url
  code=$(sudo -u "#$1" /usr/bin/curl -sS -o /dev/null -m 5 -w '%{http_code}' "$2" 2>&1)
  case "$code" in [1-5][0-9][0-9]) echo "OK http=$code" ;; *) echo "FAIL $code" | tr '\n' ' '; echo ;; esac
}
udp_probe() { # $1 uid $2 сервер
  a=$(sudo -u "#$1" /usr/bin/dig +time=2 +tries=1 +short "@$2" example.com A 2>&1 | head -1)
  case "$a" in *.*.*.*) case "$a" in *';;'*) echo "FAIL $a" ;; *) echo "OK $a" ;; esac ;; *) echo "FAIL $a" ;; esac
}
icmp_probe() { # $1 uid $2 адрес
  if sudo -u "#$1" /sbin/ping -c 1 -t 2 "$2" >/dev/null 2>&1; then echo OK; else echo FAIL; fi
}

# Классификация пары baseline/под правилами для пробы, которая под правилами должна быть заблокирована.
classify_block() { # $1 id $2 baseline(OK|SEEN...) $3 под правилами $4 деталь
  case "$2" in
    OK*|SEEN) case "$3" in OK*|SEEN) result "$1" LEAK "base=$2 rules=$3 $4" ;; *) result "$1" BLOCKED "base=$2 rules=$3 $4" ;; esac ;;
    *) result "$1" INCONCLUSIVE "base=$2 rules=$3 $4" ;;
  esac
}
# ...которая под правилами должна пройти.
classify_pass() {
  case "$2" in
    OK*|SEEN) case "$3" in OK*|SEEN) result "$1" WORKS "base=$2 rules=$3 $4" ;; *) result "$1" FAILS "base=$2 rules=$3 $4" ;; esac ;;
    *) result "$1" INCONCLUSIVE "base=$2 rules=$3 $4" ;;
  esac
}

stop_flows() { pkill -f "$KS/flow.py" >/dev/null 2>&1; return 0; }

# Полный сброс: наши якоря, основной набор, наши токены, потоки, feth; pfctl -d — только если pf исходно был выключен
# (одноразовая ВМ; в продукт не переносится).
reset_all() {
  why=${1:-manual}
  stop_flows
  launchctl bootout "system/$EN_LABEL" >/dev/null 2>&1
  for a in $ANCHOR $EXTRA_ANCHORS; do pfctl -q -a "$a" -F all >/dev/null 2>&1; done
  if [ -f "$KS/main_dirty" ]; then pfctl -q -f /etc/pf.conf >/dev/null 2>&1; rm -f "$KS/main_dirty"; fi
  release_tokens
  if [ "$(cat "$KS/pf_initial" 2>/dev/null)" = Disabled ] && pf_enabled; then pfctl -d >/dev/null 2>&1; fi
  feth_down
  echo "reset($why) $(date +%T) pf=$(pfctl -s info 2>/dev/null | awk '/^Status/{print $2}') anchor_rules=$(anchor_rules | wc -l | tr -d ' ')"
}

arm_watchdog() { # $1 секунд
  launchctl bootout "system/$WD_LABEL" >/dev/null 2>&1
  cat > "$WD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$WD_LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>$KS/watchdog.sh</string><string>$1</string></array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$OUT/watchdog.log</string>
  <key>StandardErrorPath</key><string>$OUT/watchdog.log</string>
</dict></plist>
EOF
  chown root:wheel "$WD_PLIST"; chmod 644 "$WD_PLIST"
  launchctl bootstrap system "$WD_PLIST"
}
disarm_watchdog() { launchctl bootout "system/$WD_LABEL" >/dev/null 2>&1; rm -f "$WD_PLIST"; return 0; }

# Сегмент с правилами: сторож на $1 секунд, сброс при любом выходе.
begin_segment() {
  arm_watchdog "${1:-180}"
  trap 'reset_all trap; disarm_watchdog' EXIT
  trap 'exit 130' INT TERM
}
