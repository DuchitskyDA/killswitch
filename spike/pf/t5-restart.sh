#!/bin/sh
# Пункт 5: переживают ли правила якоря pfctl -d/-e и перезагрузку /etc/pf.conf; LaunchDaemon RunAtLoad и StartInterval.
. /private/tmp/ks/lib.sh
begin_segment 240
status() { pfctl -s info 2>/dev/null | awk '/^Status/{print $2}'; }
nrules() { anchor_rules | grep -c block; }
pr() { tcp_probe "$PROBE_UID" https://1.1.1.1/; }

base=$(pr)
pf_enable_token >/dev/null
policy strict keep | load_anchor "$ANCHOR"
on=$(pr)
classify_block 5.loaded "$base" "$on" "strict загружен"

log "pfctl -d / pfctl -e"
run pfctl -d
dis=$(pr); n_d=$(nrules); refs_d=$(pfctl -s References 2>/dev/null | tail -n +3 | grep -c .)
run pfctl -e
en=$(pr); n_e=$(nrules)
result 5.disable-enable INFO "после -d: pf=Disabled ksprobe=$dis block-правил=$n_d токенов=$refs_d; после -e: ksprobe=$en block-правил=$n_e"
classify_block 5.rules-survive-d-e "$base" "$en" "правила якоря после -d/-e"
pfctl -d >/dev/null 2>&1; : > "$TOKENS"
pf_enable_token >/dev/null

log "pfctl -f /etc/pf.conf"
pfctl -q -f /etc/pf.conf 2>&1
n_f=$(nrules); r_f=$(pr)
classify_block 5.rules-survive-pfconf "$base" "$r_f" "после pfctl -f /etc/pf.conf, block-правил в якоре $n_f"
run pfctl -a com.apple -s Anchors

log "LaunchDaemon enforce: RunAtLoad + StartInterval 10"
policy strict keep > "$KS/policy.conf"
cat > "$KS/enforce.sh" <<EOF
#!/bin/sh
. $KS/lib.sh
echo "enforce \$(date +%T) pf=\$(pfctl -s info 2>/dev/null | awk '/^Status/{print \$2}') block=\$(anchor_rules | grep -c block)"
pf_enabled || { pf_enable_token >/dev/null; echo "  enabled, new token"; }
anchor_rules | grep -q block || { pfctl -q -a "$ANCHOR" -f "$KS/policy.conf" 2>&1; echo "  anchor reloaded"; }
EOF
cat > "$EN_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$EN_LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>$KS/enforce.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$OUT/enforce.log</string>
  <key>StandardErrorPath</key><string>$OUT/enforce.log</string>
</dict></plist>
EOF
chown root:wheel "$EN_PLIST"; chmod 644 "$EN_PLIST"

# Чистое состояние: якорь пуст, pf выключен, токенов нет.
pfctl -q -a "$ANCHOR" -F all; release_tokens; pfctl -d >/dev/null 2>&1
echo "до bootstrap: pf=$(status) block=$(nrules)"
run launchctl bootstrap system "$EN_PLIST"
sleep 3
s1=$(status); n1=$(nrules); r1=$(pr)
[ "$s1" = Enabled ] && [ "$n1" -gt 0 ] && result 5.runatload WORKS "bootstrap → RunAtLoad: pf=$s1 block=$n1 ksprobe=$r1" || result 5.runatload FAILS "pf=$s1 block=$n1"

pfctl -q -a "$ANCHOR" -F all
echo "якорь сброшен вручную: block=$(nrules)"
sleep 13
n2=$(nrules)
[ "$n2" -gt 0 ] && result 5.interval WORKS "StartInterval 10 вернул якорь за ≤13 с (block=$n2)" || result 5.interval FAILS "block=$n2"

pfctl -d >/dev/null 2>&1
echo "pf выключен вручную: $(status)"
sleep 13
s3=$(status)
[ "$s3" = Enabled ] && result 5.reenable WORKS "pfctl -d чужим → демон включил pf новым токеном за ≤13 с" || result 5.reenable FAILS "pf=$s3"
run pfctl -s References

run launchctl bootout "system/$EN_LABEL"
s4=$(status); n4=$(nrules)
result 5.bootout INFO "после bootout: pf=$s4 block=$n4 (правила и токен остаются; bootout их не снимает)"
run cat "$OUT/enforce.log"
# Токен, взятый демоном, — в $TOKENS (lib.sh), его отпустит reset_all.
result 5.coldboot NOT_TESTED "холодная загрузка на раннере не проверяется: гарантия = RunAtLoad + проверка bootstrap выше"
