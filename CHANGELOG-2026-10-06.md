# fast_ping.c — исправления 2026-10-06

## Round 2 — внешний код-ревью (6 пунктов) построчно

Проверено: **4/6 — мифы** (interleaved-«критический баг» — код всегда был
sequential; buffer overflow — гвард `if (off+len > sizeof(tmp))` уже стоял;
connect() на dgram ICMP — стандартный способ (как в ping(8)); «утечка при
Ctrl+C» — free есть, строки main). 2/6 — косметика (strict aliasing —
сетевой идиом, не ломается; пер-тредовый id — принято).

Плюс ревью пропустило 2 реальных (узких) бага — исправлены:

### 1. Raw ICMPv6 без фильтра источника
В `run_raw_ping` блок «src-IP + id» был завязан на `if (family == AF_INET)`.
Raw-сокет v6 видел ВСЕ echo-ответы на машине — принимал ответ ЛЮБОГО хоста с
совпавшим seq (u v4-пути src-IP это отсекал, у v6 — ничего).
Фикс: `if (id != task->want_id) continue;` вынесен из if-блока — v4 и v6.

### 2. Общий ICMP id у всех потоков (getpid)
Все треды шарили один id = pid. Raw-сокет видит все ICMP на машине:
дубль-хост в аргументах или concurrent-процессы — взаимные ответы.
Фикс: пер-тредовый уникальный id `next_icmp_id() = (pid & 0xFFFF) + counter`.
`PingTask.want_id`; build-функции принимают id аргументом; recv-фильтр —
`task->want_id`. ponytail: 2^16 пространство, upgrade path — random id.

### 3. Мелкое
- Комментарий «Interleaved ping» → «Sequential ping» (враньё: код всегда был
  sequential: send seq → ждём ответ именно на seq).
- Тестовый хук `FAST_PING_FORCE_RAW=1` — форсирует raw-путь (env в проде не
  задан).
- .gitignore: +fast_ping

### Результаты round 2 (docker ubuntu:22.04, CAP_NET_RAW, net=host)
- dgram: 127.0.0.1 0.002/0.004/0.007 ms; 8.8.8.8 78/80/83 ms — 0% loss
- raw (forced): 3 хоста параллельно (127.0.0.1 + 9.9.9.9 + 1.1.1.1) — 0% loss
- два конкурентных экземпляра (dgram + raw), тот же хост — оба 0% loss
- IPv6 ::1 в этом окружении не пингуется (socket v6 dgram: Permission denied
  даже без raw) — не баг кода: старый бинарник даёт тот же OFFLINE.
- Сборка `gcc -O2 -Wall -Wextra -Werror` — чисто.

Бэкап исходника: fast_ping.c.bak.20261006_052422

## Round 1 — три бага (docker, NET_RAW, статический бинарник)

## 1. 100% loss — байтовый порядок ICMP checksum (root cause)
- `build_icmpv4_packet`: `hdr->checksum = in_cksum(...)` — host-order uint16_t
  на little-endian записывался low-byte-first. Проводной формат требует
  high-byte-first (network order). Ядро drop-ило запрос по плохому чексуму,
  ответ вообще не генерировался.
- Фикс: `hdr->checksum = htons(in_cksum(...))`
- То же в `build_icmp6_packet`: `htons(icmpv6_checksum(...))`.
- Доказательство: идентичный raw-код в контейнере NO_REPLY с buggy checksum,
  GOT_REPLY в обоих режимах (connected и unconnected) после фикса.

## 2. id-mismatch в recv-фильтре (побочный эффект ложного «фикса»)
- id в пакете = htons(pid) на проводе; чтение `(buf[4]<<8)|buf[5]` даёт ровно
  host-порядковый `pid & 0xFFFF` — БЕЗ htons.
- Фикс: `if (id != (uint16_t)(getpid() & 0xFFFF)) continue;`

## 3. Завышенный RTT (10/15/20 мс на loopback вместо 0.003)
- Архитектура «все sends (пауза 10 мс) → потом recv-цикл»: ответы лежали в
  буфере сокета, RTT мерялся от момента приёма. Значения с шагом ровно 10 мс.
- Фикс: interleaved ping (как системный ping) — send seq, ждём ответ именно на
  этот seq (select с per-seq deadline 2 c), RTT = rx - tx конкретного пакета,
  затем следующий seq. Переделано в `run_raw_ping` и `run_dgram_ping`.

## Результаты (после всех фиксов)
Контейнер (docker NET_RAW):
- 127.0.0.1: 0.001/0.001/0.003 ms, loss 0%
- 8.8.8.8: 78/84/96 ms, loss 0%

Машина пользователя (sudo ./fp -c 2 127.0.0.1 google.com 192.168.10.105):
- 127.0.0.1: 0.003/0.004/0.006 ms
- 142.250.217.14 (google.com): 178.2/178.6/179.0 ms
- 192.168.10.105: 1.6/1.7/1.8 ms
- loss 0%, все 3 хоста ONLINE

## Условия работы
- Только с sudo: у юзера нет CAP_NET_RAW, dgram-сокет на хосте EACCES даже
  с sudo (bounding set), raw-ветка работает.
- Raw-сокет не connect()нут: sendto() + фильтр по dst-IP и ICMP id
  (unconnected raw видит все ICMP на машине).
- Fallback без root — fast-ping.c через системный ping.

Бэкап исходника: fast_ping.c.bak.20261006_041242
