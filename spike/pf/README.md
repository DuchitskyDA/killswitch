# Спайк pf (macOS)

Проверка допущений pf-бэкенда на одноразовых раннерах GitHub (`macos-15` arm64, `macos-15-intel` x64, `macos-26` arm64).
Workflow — `.github/workflows/spike-pf.yml`, запускается push'ем в ветку спайка. **Не запускать на рабочей машине**: скрипты
включают pf, создают пользователей и LaunchDaemon'ы.

| Скрипт | Что проверяет |
|---|---|
| `inventory.sh` | ОС, SIP, пользователь агента раннера, состояние pf, якоря Apple, справка `pfctl`, интерфейсы, создание `feth` |
| `setup.sh` | пробные пользователи `ksprobe` (uid 6001, не доверен) и `kstrust` (uid 6002, доверен) |
| `wdtest.sh` | сторож-LaunchDaemon сбрасывает якорь и отпускает токен |
| `t1-token.sh` | `pfctl -E`/`-X`, потерянный токен, `pfctl -d`/`-e` |
| `t2-anchor.sh` | достижимость `com.apple/500.ks-spike` (канарейка на счётчиках), основной набор без якоря, quick-правила выше якоря и в соседних якорях |
| `t3-policy.sh` | политика «блок везде, кроме lo0 и туннельного `feth2`»; strict/compat для доверенного; интерфейсы, созданные после загрузки |
| `t3b-v6.sh` | IPv6 на `feth`: захват на нескольких интерфейсах, NDP |
| `t4-states.sh` | живут ли потоки после ужесточения (keep state / no state), `pfctl -k` по хосту, свидетели |
| `t5-restart.sh` | правила после `-d`/`-e` и `pfctl -f /etc/pf.conf`; LaunchDaemon RunAtLoad/StartInterval, bootout |
| `flow.py` | долгий TCP/TLS/UDP-поток от заданного пользователя |

Каждая проба печатает `RESULT <id> <класс> <деталь>`: WORKS / FAILS (должно пройти), BLOCKED / LEAK (должно быть закрыто),
INCONCLUSIVE (baseline без правил не прошёл), INFO, NOT_TESTED. Итоги — в summary джоба и артефакте `spike-pf-<образ>`.

Защита раннера: в каждом наборе pass для uid агента (`runner`), root и DNS `_mdnsresponder`; каждый сегмент — под сторожем
(LaunchDaemon без KeepAlive, через N секунд сбрасывает якоря, возвращает `/etc/pf.conf`, отпускает токены, на одноразовой ВМ
выключает pf, если тот был выключен исходно), `trap` со сбросом и `timeout-minutes` на шаг и джоб.
