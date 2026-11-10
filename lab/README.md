# lab — стенд приёмки киллсвитча в Linux network namespace

Раннер `kslab` поднимает в network namespace `ksl-*` маленький «интернет», туннели WireGuard, sing-box и xray и проверяет
пробы утечки. Каждая проба получает вердикт BLOCKED, LEAK или INCONCLUSIVE. Хост не меняется: всё живёт в своих ns, а каждая сетевая
операция идёт через дескриптор ns со сверенным inode.

## Топология

```
ksl-client ── c0 ═══ wc ── ksl-wan ── wv ═══ v0 ── ksl-peer  (серверы туннелей)
198.51.100.2         (маршрутизатор,   └─ wi ═══ i0 ── ksl-inet  («интернет»-хост и получатель)
2001:db8:c::2         захват на wc)                  203.0.113.130, 2001:db8:b::2
```

- Все адреса лежат вне LAN-диапазонов Policy: TEST-NET-2/3, 2001:db8::/32, внутренние адреса туннелей — 198.18.0.0/15 и
  2001:db8:ffff::/48.
- `ksl-inet` держит HTTP/80 (отвечает адресом источника), эхо на UDP/443 и DNS на 53 по UDP и TCP. Каждое соединение и каждая датаграмма
  пишутся в журнал получателя. Порты 81/TCP и 444/UDP без сервера.
- Захват идёт через AF_PACKET на `ksl-wan/wc`: tcpdump на хосте может не быть. В каждом окне пробы `ksl-wan` шлёт метку `KSLMARK:<n>`.
  Если захват её не увидел, окно недействительно.
- Туннели поднимаются по очереди. WireGuard: модуль ядра, `wg0` создаётся внутри `ksl-client`, поэтому его UDP-сокет тоже живёт в этом
  ns. Ключи ставятся через wgctrl. sing-box: TUN `ksb0` и shadowsocks 2022 до своего сервера. xray: собственный TUN-inbound `kxr0`
  и shadowsocks 2022. Исходящий клиента привязан к `c0`, у default через туннель metric 10.

## Пробы и вердикты

- **direct.** Проба с SO_BINDTODEVICE=`c0` идёт мимо туннеля. Набор: tcp/80, udp/443, DNS udp и tcp/53 по v4 и v6, плюс контроль
  tcp/81 и udp/444.
- **tunnel.** Те же сервисы по маршруту в туннель. Успех засчитывается по содержимому ответа, а не по connect: TUN-стеки отвечают
  SYN-ACK сами.
- **INCONCLUSIVE.** Baseline этой пробы без правил не прошёл: нет правильного ответа, нет пакета в захвате или нет записи получателя.
  Сюда же попадает окно, в котором захват не подтвердил метку.
- **LEAK.** Под правилами есть ответ, пакет с физического адреса клиента к цели на WAN или запись получателя.
- **BLOCKED.** Baseline прошёл, а под правилами нет ни одного из этих свидетелей.

Этапы на каждый туннель:
1. `baseline` — правил нет.
2. `P1` — буквальная политика: drop всего в output, кроме `lo` и интерфейса туннеля.
3. `P2` — P1 плюс доступ к endpoint сервера (адрес, порт, протокол).
4. `снято` — таблица удалена. Обязан быть LEAK; заодно это повторный baseline после правил.

Политики живут только в `ksl-client`, в `table inet ksl_probe`, hook output, priority filter - 10.

## Запуск

```
KSL_HOST=root@<host> KSL_SERVICES="my.service" bash lab/run-remote.sh                          # все туннели, затем /opt/killswitch-lab удаляется
KSL_HOST=root@<host> TUNNELS=wireguard KEEP=1 bash lab/run-remote.sh
```

Если `go` нет в PATH, задай `GO=<путь к go>`.

Скрипт работает так:
1. Собирает `kslab` (GOOS=linux, CGO_ENABLED=0) в `.lab-tmp/`.
2. Скачивает релизы из `pins.env` и сверяет sha256 архивов и бинарников.
3. Копирует всё в `/opt/killswitch-lab`.
4. Снимает хост до прогона: `hostcheck.sh`.
5. Показывает отказ для корневого ns.
6. Запускает прогон: `systemd-run --scope --unit=ksl-lab -p MemoryMax=256M -p CPUQuota=50% -p TasksMax=256 -p RuntimeMaxSec=870`
   под `timeout 900`.
7. Убирает за собой: `kslab cleanup` под своим scope и остановку scope прогона. Уборка идёт при любом исходе прогона.
   Демонстрация отказа тоже идёт под scope; снаружи выполняется только чтение (`hostcheck.sh`, `sha256sum -c`).
8. Снимает хост после прогона и сравнивает с первым снимком.

В сравнении участвует `nft -s` без счётчиков: сырой `nft list ruleset` на живом хосте плавает сам из-за счётчиков ufw и fail2ban.

Коды выхода `kslab`: 0 — критерий выполнен, 1 — не выполнен или ошибка, 2 — защита хоста отказала. Выход 2 бывает, например, когда
цель — корневой ns: `kslab nsexec --ns-path /proc/1/ns/net -- …`.

Тесты без root и Linux: `go test ./lab/...` из корня (lab — часть корневого модуля). На Windows с антивирусом запуск `lab.test.exe`
из временного каталога Go бывает запрещён («Access is denied»); тогда `go test -c -o <свой каталог>/lab.test.exe ./lab/internal/lab`
и запуск этого файла. Тест `lab/internal/probe` слушает только loopback.

## Приёмка против настоящего killswitch

```
KSL_HOST=root@<host> KSL_SERVICES="a.service b.service" bash lab/run-accept.sh               # wireguard, sing-box, sing-box-ar, xray
KSL_HOST=root@<host> CLIENTS=xray OUT=<каталог логов> KEEP=1 bash lab/run-accept.sh
```

`kslab accept --client <c>` прогоняет живые сценарии 1–9, 10 (enforce возвращает снятую таблицу), два дополнительных сценария
(прямой маршрут клиента в strict, «зомби-туннель» для `dns.mode = tunnel-up`) и проверки (а)–(г) backend Linux. Каждый клиент —
свой вызов под scope (`-p Delegate=yes`: доверенный cgroup xray — дочерний cgroup своего scope) со свежей топологией.

- `killswitch` (linux/amd64 из корня) работает только в `ksl-client` и в mount ns держателя (`ksl-mnt`): tmpfs поверх `/var/lib`,
  `/run`, `/etc/systemd/system`, свой `/run/systemd/resolve/resolv.conf` (резолвер — LAN-хост) и свой boot id (bind-mount поверх
  `/proc/sys/kernel/random/boot_id`). Каждый запуск идёт через `kslab ksexec`: сверка inode обоих ns, statfs трёх каталогов и
  заглушка `systemctl` в PATH (`stub/systemctl` пишет вызовы и меняет ссылки только в tmpfs) — иначе выход 2.
- LAN: 192.168.77.0/24 и fd77::/64 на линии c0 ↔ wc, HTTP и DNS «LAN-хоста» слушает ksl-wan.
- Пробы «программы» идут от uid 65534 (профили доверяют root); сверка ns — от root до понижения прав.
- Сценарий 7 — перезапуск ns: ksl-client пересоздаётся, boot id меняется, выполняется ExecStart раннего юнита из tmpfs, затем
  enforce из копии бинарника. Сценарий 8: `stub-kill/nft` убивает killswitch на загрузке таблицы (после `nft -c`).
- Итог — `run-<c>/results.json` и `report.txt`; `kslab summary */results.json` сводит таблицу сценарий × клиент × v4/v6.

## Что показал первый прогон стенда (наивная политика `kslab run`)

- Буквальная политика P1 рвёт транспорт всех трёх туннелей. Encap WireGuard и исходящий прокси-клиента уходят через output с oif `c0`.
  Нужно исключение: endpoint, fwmark, cgroup или uid.
- Под nft drop TCP получает таймаут, а не EPERM; UDP получает EPERM. Поэтому `check` не должен судить по виду ошибки.
- Порт без сервера всегда даёт INCONCLUSIVE, даже если пакет реально ушёл на WAN (`wan=1` на этапе «снято»). Так требует определение,
  но реальная утечка на такой порт не станет LEAK — матрица `check` должна опираться на порты с живым получателем.
- freedom в xray 26.x для shadowsocks, vless и подобных входов по умолчанию блокирует geoip:private, а туда входит TEST-NET-3.
  Серверу лаборатории нужен `finalRules: allow` на подсеть «интернета».

## Что показала приёмка (2026-11-09, ядро 6.17, nft 1.0.9, sing-box 1.14.4, xray 26.10.21)

- WireGuard (fwmark 0xca6c, профиль wireguard) и sing-box (TUN tun0, профиль sing-box) — все сценарии PASS по v4 и v6.
  xray (свой TUN, доверие cgroup) — PASS, кроме вопроса (а).
- (а) Метка доверенного cgroup живёт на записи conntrack: чужой процесс с тем же 5-кортежем UDP проходит к endpoint, пока запись
  жива. Кандидат правки, проверенный вставкой в таблицу внутри ns: в output на метку — переход в цепочку
  `socket cgroupv2 level N "<путь>" return; meta skuid >= 0 drop`. Сравнение `socket cgroupv2 … != "<путь>"` не годится: для сокета
  в cgroup мельче уровня N выражение не вычисляется и правило не срабатывает.
- (б) sing-box auto_redirect: TCP через сокет, привязанный к TUN, не проходит. check даёт INCONCLUSIVE (код 5), проверка здоровья
  не поднимается, и `tunnel-up` не закрывает DNS к LAN. Прямые TCP-пробы redirect перехватывает даже с привязкой к c0, поэтому
  прямые пробы стенда для sing-box-ar идут от uid 65533 из `exclude_uid` клиента. DNS по TCP через sing-box с auto_redirect не
  отвечает и без killswitch.
- WireGuard без fwmark в strict не подключается (серверы туннеля открыты только доверенным); с fwmark — подключается.
- OpenVPN на стенде нет — не проверен.
