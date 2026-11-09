# Происхождение

Копия `github.com/tailscale/wf` на коммите `6fbb0a674ee6` (v0.0.0-20240214030419-6fbb0a674ee6), лицензия BSD-3 — `LICENSE`,
авторы — `AUTHORS`. Заголовки лицензии в файлах сохранены. Взяты только файлы пакета (без `cmd/`, `generators/`, тестов).

## Правки killswitch (помечены комментарием `killswitch:`)
- Все файлы: `//go:build windows` — пакет собирается только под Windows.
- `malloc.go`: выделения арены выровнены до 8 байт (без выравнивания `toFilter0` падал под GC — спайк WFP).
- `types.go`, `zfilterenumflags_strings.go`: верные значения `FWP_FILTER_ENUM_FLAG_*` (0x1…0x10 вместо 1…5), строка флагов — руками.
- `compose.go`, `parse.go`: без `go4.org/netipx`; диапазон адресов — `Range{netip.Addr, netip.Addr}`.
- `parse.go`: `Rule.Weight` — заданный вес фильтра, эффективный — только запасной.
- `firewall.go`: перечисление событий отброса не обрывается на странице без отбросов.
- `killswitch.go` (новый): экспорт транзакций (`Begin/Commit/Abort`), `RulesOf` с boot-time и выключенными,
  опция движка «сбор событий» (`CollectNetEvents/SetCollectNetEvents`), `DropEventsSince` с окном времени.
- `zguids.go`: литералы `windows.GUID` с именами полей (go vet).
- `types.go`: раскладка `FWPM_FILTER0` — объединение rawContext/providerContextKey одним полем 16 байт (было 24: `FilterID` читался со сдвигом).
- `malloc.go`: выделение больше слаба (4096 байт) — отдельным блоком LocalAlloc вместо паники (массив условий на 100+ app-id).
