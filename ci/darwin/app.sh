#!/bin/sh
# killswitch.app из бинарника darwin и zip для выпуска (ci.yml, release). Только macOS: plutil, codesign, ditto.
# app.sh <бинарник> <версия> <zip>
set -eu
bin=$1 version=$2 zip=$3
root=$(cd "$(dirname "$0")/../.." && pwd)
case "$version" in *[!0-9A-Za-z.-]* | '') echo "версия: только цифры, буквы, точка и дефис: '$version'" >&2; exit 2 ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app="$work/killswitch.app"
mkdir -p "$app/Contents/MacOS"
install -m 0755 "$bin" "$app/Contents/MacOS/killswitch"
# Значок (CFBundleIconFile): до codesign — Resources входит в печать подписи.
mkdir -p "$app/Contents/Resources"
install -m 0644 "$root/dist/icon/killswitch.icns" "$app/Contents/Resources/killswitch.icns"
sed "s/@VERSION@/$version/g" "$root/dist/macos/Info.plist" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
# Подпись линкера Go не связывает Info.plist с исполняемым файлом: ad-hoc подпись всего бандла (без сертификата).
codesign --force --sign - --identifier io.github.duchitskyda.killswitch "$app"
codesign --verify --strict --verbose=2 "$app"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
