#!/bin/sh
# PNG иконки из SVG: resvg 0.45.1 (Debian 13: apt-get install resvg). Дальше упаковка: cd gen && go run .
# render.sh — из каталога dist/icon или откуда угодно. Пишет png/win-<N>.png и png/mac-<N>.png.
#   Windows: плитка во весь холст — тот же icon.svg с viewBox по плитке; 16 и 20 — свои упрощённые svg.
#   macOS: icon.svg как есть (сетка macOS: плитка 824 с отступом 100 на холсте 1024).
# Без resvg: docker run --rm -v "$PWD:/w" -w /w debian:13 sh -c 'apt-get update && apt-get install -y resvg && sh render.sh'
set -eu
cd "$(dirname "$0")"
resvg=${RESVG:-resvg}
"$resvg" --version
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed 's/width="1024" height="1024" viewBox="0 0 1024 1024"/width="824" height="824" viewBox="100 100 824 824"/' icon.svg > "$work/win.svg"
grep -q 'viewBox="100 100 824 824"' "$work/win.svg" || { echo "icon.svg: не нашёл холст 1024 для обрезки" >&2; exit 1; }
mkdir -p png
"$resvg" -w 16 -h 16 icon-16.svg png/win-16.png
"$resvg" -w 20 -h 20 icon-20.svg png/win-20.png
for n in 24 32 40 48 64 256; do "$resvg" -w "$n" -h "$n" "$work/win.svg" "png/win-$n.png"; done
for n in 16 32 64 128 256 512 1024; do "$resvg" -w "$n" -h "$n" icon.svg "png/mac-$n.png"; done
