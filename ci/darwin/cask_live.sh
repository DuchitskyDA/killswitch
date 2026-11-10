#!/bin/sh
# Живая проверка cask на одноразовом раннере macOS (ci.yml, live-darwin): локальный tap duchitskyda/tap с url file://
# на zip из job release; установка, карантин, запуск, защита из .app, режим при brew reinstall и brew upgrade,
# снятие brew uninstall --cask и brew install после него — как первая установка.
# От пользователя раннера (brew под root не работает), шаги с правами — sudo; итог — строки RESULT C<n>.<id> в общем
# results.txt (lib.sh). Окно с паролем (osascript) здесь не проверяется: на раннере его некому заполнить.
# cask_live.sh <каталог с killswitch-darwin-*.zip и SHA256SUMS>
set -u
here=$(cd "$(dirname "$0")" && pwd)
zips=$(cd "$1" && pwd)
LIB=/private/tmp/ks-ci/lib.sh
CASK=duchitskyda/tap/killswitch
APP=/Applications/killswitch.app
EXE="$APP/Contents/MacOS/killswitch"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1

log() { printf '\n== %s\n' "$*"; }
# rec id код деталь — строка RESULT (check из lib.sh, под root: results.txt принадлежит root).
rec() { sudo sh -c '. "$0"; check "$@"' "$LIB" "$@"; }
# asroot 'команды' — команды под root с функциями и переменными lib.sh.
asroot() { sudo sh -c '. "$0"; eval "$1"' "$LIB" "$1"; }
sum() { awk -v f="$1" '$2 == f {print $1}' "$zips/SHA256SUMS"; }
# cask версии $1 в локальный tap.
write_cask() { sh "$here/cask.sh" "$1" "$(sum killswitch-darwin-arm64.zip)" "$(sum killswitch-darwin-amd64.zip)" "file://$zips" > "$tap/Casks/killswitch.rb"; }
# Записанный режим из state.json (json.MarshalIndent: строка «  "mode": "on",»); нет файла — пусто.
state_mode() { asroot 'sed -n "s/^  \"mode\": \"\([a-z]*\)\",\$/\1/p" "$DIR/state.json" 2>/dev/null'; }
daemon() { asroot 'launchctl print "system/$LABEL" >/dev/null 2>&1 && echo loaded || echo absent'; }

trap 'asroot "reset_all cask; disarm_watchdog" >/dev/null 2>&1' EXIT
case "$(uname -m)" in arm64) arch=arm64 ;; *) arch=amd64 ;; esac
zip="$zips/killswitch-darwin-$arch.zip"

log "C1: zip выпуска ($arch)"
[ -n "$(sum "killswitch-darwin-$arch.zip")" ] && [ "$(shasum -a 256 "$zip" | awk '{print $1}')" = "$(sum "killswitch-darwin-$arch.zip")" ]
rec C1.sha256 $? "$zip совпадает с SHA256SUMS"
x=$(mktemp -d)
ditto -x -k "$zip" "$x"
[ -x "$x/killswitch.app/Contents/MacOS/killswitch" ]; rec C1.exec-bit $? "killswitch.app в корне zip, бит запуска сохранён"
codesign -dv "$x/killswitch.app" 2>&1 | sed -n '1,6p'
codesign --verify --strict "$x/killswitch.app"; rec C1.codesign $? "ad-hoc подпись бандла проходит проверку"
[ "$(plutil -extract LSUIElement raw "$x/killswitch.app/Contents/Info.plist")" = true ]; rec C1.lsuielement $? "LSUIElement = true"

log "C2: локальный tap и установка"
brew tap-new --no-git duchitskyda/tap >/dev/null
tap=$(brew --repository duchitskyda/tap)
mkdir -p "$tap/Casks"
write_cask 0.0.0
cat "$tap/Casks/killswitch.rb"
brew install --cask "$CASK"; rec C2.install $? "brew install --cask $CASK"
cache=$(brew --cache --cask "$CASK")
xattr -p com.apple.quarantine "$cache" >/dev/null 2>&1
rec C2.download-quarantined $? "загрузка $cache с пометкой карантина (иначе C2.app-not-quarantined ничего не доказывает)"
[ -d "$APP" ] && [ "$(xattr -lr "$APP" | grep -c com.apple.quarantine)" = 0 ]
rec C2.app-not-quarantined $? "в $APP пометки карантина нет"

log "C3: запуск и защита из .app"
sudo "$EXE" detect; rec C3.detect $? "sudo $EXE detect"
asroot 'RUNNER_UID=$(cat "$KS/runner_uid"); mkdir -p "$DIR"; write_config true open; arm_watchdog 600'
sudo "$EXE" on; rec C3.on $? "sudo $EXE on"
out=$(asroot 'n=$(anchor_rules); echo "правил в якоре $n"; [ "$n" -gt 0 ] && launchctl print "system/$LABEL" >/dev/null')
rec C3.armed $? "$out, LaunchDaemon загружен"

log "C4: обновление режим не меняет — brew reinstall при off, brew upgrade при on"
sudo "$EXE" off; rec C4.off $? "sudo $EXE off"
brew reinstall --cask "$CASK"; rec C4.reinstall $? "brew reinstall --cask $CASK"
m=$(state_mode) d=$(daemon)
[ "$m" = off ] && [ "$d" = loaded ]; rec C4.reinstall-mode $? "после reinstall режим '$m' (ждали off), демон $d"
sudo "$EXE" on; rec C4.on $? "sudo $EXE on"
write_cask 0.0.1
brew upgrade --cask "$CASK"; rec C4.upgrade $? "brew upgrade --cask $CASK"
v=$(brew list --cask --versions killswitch) # по имени в Caskroom: полное имя с tap list не находит
m=$(state_mode)
out=$(asroot 'n=$(anchor_rules); echo "правил в якоре $n"; [ "$n" -gt 0 ] && launchctl print "system/$LABEL" >/dev/null')
rc=$?
[ "$rc" = 0 ] && [ "$m" = on ] && [ "${v##* }" = 0.0.1 ]
rec C4.upgrade-mode $? "после upgrade ($v) режим '$m' (ждали on), $out, LaunchDaemon загружен"

log "C5: brew uninstall --cask"
brew uninstall --cask "$CASK"; rec C5.uninstall $? "brew uninstall --cask $CASK"
out=$(asroot 'n=$(anchor_rules); t=$(our_tokens); launchctl print "system/$LABEL" >/dev/null 2>&1 && d=loaded || d=absent
  echo "якорь: правил $n, токены [$t], демон $d"
  [ "$n" = 0 ] && [ -z "$t" ] && [ "$d" = absent ] && [ ! -e "$PLIST" ] && [ ! -e "$DIR/killswitch" ]')
rec C5.removed $? "$out; plist и копия в Application Support удалены"
[ ! -e "$APP" ]; rec C5.app-removed $? "$APP удалена"

log "C6: brew install после brew uninstall — как первая установка (config.toml на месте, режим не возвращается)"
brew install --cask "$CASK"; rec C6.install $? "brew install --cask $CASK"
out=$(asroot 'n=$(anchor_rules); launchctl print "system/$LABEL" >/dev/null 2>&1 && d=loaded || d=absent
  echo "state.json $([ -e "$DIR/state.json" ] && echo есть || echo нет), правил в якоре $n, демон $d"
  [ -e "$DIR/config.toml" ] && [ ! -e "$DIR/state.json" ] && [ "$n" = 0 ] && [ "$d" = absent ]')
rec C6.first-install $? "$out"
brew uninstall --cask "$CASK"; rec C6.uninstall $? "brew uninstall --cask $CASK"

! sudo grep -Eq '^RESULT C[0-9]+\.[^ ]+ FAIL ' /private/tmp/ks-ci/out/results.txt
