# fast_ping.c — многопоточный ICMP-сканер на C

Один процесс, N потоков. Проверка доступности десятков IP/доменов **параллельно**,
с честным RTT per-пакет. Без `popen("ping ...")`, без парсинга вывода, без
зависимости от бинарника `ping` вообще.

| | fast-ping (popen) | fast_ping (этот) |
|---|---|---|
| 50 хостов | ~N запусков ping, минуты | 1 процесс, N потоков, секунды |
| RTT | агрегат из вывода ping | per-пакет, min/avg/max/mdev |
| Локаль/формат вывода | ломает парсер | не зависит |
| Права | нужен `ping` в PATH | только ICMP-сокеты (см. ниже) |

## Сборка

```bash
gcc -O2 -Wall -Wextra -o fast_ping fast_ping.c -pthread -lm
```

## Использование

```bash
./fast_ping -c <packets> <host1> [host2 ...]
./fast_ping -l 1 -c 3 127.0.0.1 8.8.8.8 192.168.1.1
```

- `-c <count>` — пакетов на хост (обязательно, ≤ 1000000)
- `-l 0|1` — язык вывода: 0 = English (по умолчанию), 1 = Русский
- Ctrl+C — корректное прерывание

```
STATUS        IP ADDRESS          | TIME (min/avg/max/mdev)
------------------------------------------------------------
[ ONLINE  ] 127.0.0.1       | RTT (ms): 0.002/0.004/0.007/0.002
[ ONLINE  ] 8.8.8.8         | RTT (ms): 78.012/80.496/86.790/4.492
------------------------------------------------------------

SUMMARY:
Hosts: 2 | Up: 2 | Down: 0 | Failure: 0%
Packets: sent 6 | received 6 | loss 0%
```

---

# Как избавиться от sudo

## Проблема

По умолчанию ядро Linux пускает ICMP-сокеты (`SOCK_DGRAM, IPPROTO_ICMP`)
**только** root'у или процессу с `CAP_NET_RAW`. Обычный пользователь получает
`Permission denied` — отсюда «нужен sudo».

## Решение: `net.ipv4.ping_group_range` (без root, без capabilities)

Это штатный механизм ядра: список GID, которым разрешено открывать
unprivileged ping-сокеты. Включён в ядре по умолчанию, но на многих
дистрибутивах диапазон пустой (проверь: `sysctl net.ipv4.ping_group_range`).

### 1. Разово (до ребута), нужен sudo один раз:

```bash
sudo sysctl -w net.ipv4.ping_group_range="1000 65535"
```

### 2. Постоянно (переживёт ребут):

```bash
sudo tee /etc/sysctl.d/99-ping-group-range.conf >/dev/null <<'EOF'
# Разрешаем обычным пользователям ICMP dgram-сокеты без sudo
net.ipv4.ping_group_range = "1000 65535"
EOF
sudo sysctl --system
```

Конф уже лежит в репозитории: `99-ping-group-range.conf` — скопируй его
в `/etc/sysctl.d/` и запусти `sudo sysctl --system`.

### 3. Проверка

```bash
sysctl net.ipv4.ping_group_range
# должно быть: net.ipv4.ping_group_range = 1000 65535

id -G   # один из твоих GID должен попасть в диапазон (обычно 1000)
```

Теперь `./fast_ping -c 2 8.8.8.8` работает **без sudo**.

### Дистр-специфика

| Дистрибутив | Примечание |
|---|---|
| Ubuntu/Debian | по умолчанию `1 0` (пусто) — ставь как выше |
| Fedora/Arch/RHEL | значения разные, часто уже открыты — проверь `sysctl net.ipv4.ping_group_range`, если диапазон не `1 0` — sudo уже не нужен |

### Безопасность

`ping_group_range` даёт **только** отправлять/получать ICMP echo — ни
raw-сокетов, ни sniffing, ни спуфинга. Это ровно то, что умеет `ping`
как не-root-пользователь. Ограничь диапазон конкретным GID, если хочешь
ужесточить: создай группу `pingers`, добавь туда нужных пользователей,
`net.ipv4.ping_group_range = "<gid pingers> <gid pingers>"`.

## Почему raw-сокет — только fallback

fast_ping умеет два пути:

1. **dgram** (`SOCK_DGRAM, IPPROTO_ICMP`) — предпочтительный. Ядро само
   доставляет в сокет только ответы твоему дестинейшену — фильтрация
   бесплатная, конкурентные пинги на машине друг друга не мешают.
2. **raw** (`SOCK_RAW, IPPROTO_ICMP`) — только если dgram не открылся.
   Видит **все** ICMP на машине, поэтому в коде есть своя фильтрация
   (src-IP + уникальный per-thread ICMP id). Работает с `CAP_NET_RAW`
   (root/sudo) или на машинах, где dgram запрещён, а raw разрешён.

Если настроил `ping_group_range` — путь 2 никогда не сработает, и это
хорошо. `FAST_PING_FORCE_RAW=1 ./fast_ping ...` форсирует raw-путь —
только для тестов/отладки.

## IPv6

ICMPv6 echo через dgram-сокет — то же самое, ядро проверяет
`net.ipv6`-аналог через тот же механизм. Если `socket(AF_INET6, SOCK_DGRAM,
IPPROTO_ICMPV6)` даёт `Permission denied` на твоей машине — проверь
`ping_group_range` и что на машине вообще включён IPv6.

## Устранение неполадок

| Симптом | Причина | Лечение |
|---|---|---|
| `Socket error: dgram: Permission denied; raw: Operation not permitted` | нет прав ни на dgram ни на raw | `ping_group_range` (выше) или sudo |
| dgram работает, но хост OFFLINE | хост реально не отвечает / firewall | проверь `ping` системным |
| `[ ERROR ] DNS resolution failed` | имя не резолвится | проверь DNS |
| высокий RTT на loopback | — | норма: dgram v4 loopback ~0.005 ms |
