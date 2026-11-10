#!/bin/sh
# Cask killswitch из шаблона dist/homebrew/killswitch.rb — в stdout. База url по умолчанию — выпуск на GitHub;
# CI передаёт file:// на собранные zip (ci/darwin/cask_live.sh).
# cask.sh <версия> <sha256 arm64> <sha256 amd64> [база url]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
version=$1 arm=$2 intel=$3
base=${4:-"https://github.com/DuchitskyDA/killswitch/releases/download/v#{version}"}
case "$version" in *[!0-9A-Za-z.-]* | '') echo "версия: только цифры, буквы, точка и дефис: '$version'" >&2; exit 2 ;; esac
for h in "$arm" "$intel"; do
  [ "$(printf %s "$h" | grep -cE '^[0-9a-f]{64}$')" = 1 ] || { echo "sha256: ждали 64 hex: '$h'" >&2; exit 2; }
done
case "$base" in *'|'* | *'"'* | *'&'* | *'\'*) echo "база url с недопустимым символом: '$base'" >&2; exit 2 ;; esac
sed -e "s|@VERSION@|$version|" -e "s|@SHA256_ARM64@|$arm|" -e "s|@SHA256_AMD64@|$intel|" -e "s|@URL_BASE@|$base|" \
  "$root/dist/homebrew/killswitch.rb"
