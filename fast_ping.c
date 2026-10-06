#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct icmp6_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

typedef struct {
    const char *input;
    char ip[INET6_ADDRSTRLEN];
    int family;
    int count;

    int resolved;
    int reachable;
    int parsed_rtt;

    uint16_t want_id; /* наш ICMP id (пер-тредовый, unique) */

    unsigned long sent;
    unsigned long received;
    char rtt[128];

    int error;
    char err[320];
} PingTask;

static volatile sig_atomic_t g_cancelled = 0;
static int g_color = 0;

/* Пер-тредовый ICMP id: pid + атомарный счётчик. Один и тот же pid у всех
 * потоков — без уникальности raw-сокеты (видят ВСЕ ICMP на машине)
 * принимали бы ответы чужих пингов. ponytail: 2^16 id, коллизия с
 * чужими пингами на машине маловероятна; upgrade path — random id. */
static unsigned g_icmp_id_next = 0;

static uint16_t next_icmp_id(void)
{
    return (uint16_t)(getpid() & 0xFFFF) + (uint16_t)(__atomic_fetch_add(&g_icmp_id_next, 1, __ATOMIC_RELAXED) % 65535u);
}

#define ERR_NONE      0
#define ERR_RESOLVE   1
#define ERR_SOCKET    2
#define ERR_SEND      3
#define ERR_RECV      4

static const char *lang_usage[] = {
    "Usage: %s [-l 0|1] -c <packets> <host1> [host2 ...]",
    "Использование: %s [-l 0|1] -c <кол-во> <host1> [host2 ...]"
};

static const char *lang_options[] = {
    "Options:",
    "Опции:"
};

static const char *lang_opt_c[] = {
    "  -c <count>   Number of packets to send",
    "  -c <count>   Количество пакетов"
};

static const char *lang_opt_l[] = {
    "  -l <0|1>     Language: 0=English, 1=Russian",
    "  -l <0|1>     Язык: 0=English, 1=Русский"
};

static const char *lang_hosts[] = {
    "Hosts: IPv4/IPv6 addresses or hostnames",
    "Хосты: IPv4/IPv6 адреса или доменные имена"
};

static const char *lang_header[] = {
    "STATUS        IP ADDRESS          | TIME (min/avg/max/mdev)",
    "СТАТУС        IP АДРЕС            | ВРЕМЯ (min/avg/max/mdev)"
};

static const char *lang_online[] = {
    "[ ONLINE  ]",
    "[ ONLINE  ]"
};

static const char *lang_offline[] = {
    "[ OFFLINE ]",
    "[ OFFLINE ]"
};

static const char *lang_error[] = {
    "[ ERROR   ]",
    "[ ERROR   ]"
};

static const char *lang_dns[] = {
    "DNS resolution failed",
    "Ошибка разрешения имени"
};

static const char *lang_socket[] = {
    "Socket error",
    "Ошибка сокета"
};

static const char *lang_send[] = {
    "Send error",
    "Ошибка отправки"
};

static const char *lang_recv[] = {
    "Receive error",
    "Ошибка приёма"
};

static const char *lang_unavailable[] = {
    "unavailable",
    "недоступен"
};

static const char *lang_rtt[] = {
    "RTT (ms): ",
    "RTT (ms): "
};

static const char *lang_summary[] = {
    "SUMMARY",
    "СВОДКА"
};

static const char *lang_stats_hosts[] = {
    "Hosts: %zu | Up: %zu | Down: %zu | Failure: %zu%%",
    "Хостов: %zu | Работает: %zu | Не работает: %zu | Сбой: %zu%%"
};

static const char *lang_stats_pkts[] = {
    "Packets: sent %lu | received %lu | loss %lu%%",
    "Пакеты: отправлено %lu | получено %lu | потеря %lu%%"
};

static const char *lang_interrupted[] = {
    "\nInterrupted by user\n",
    "\nПрервано пользователем\n"
};

static void signal_handler(int sig)
{
    (void)sig;
    g_cancelled = 1;
}

static void usage(const char *prog, int lang)
{
    if (lang != 0 && lang != 1)
        lang = 0;

    printf(lang_usage[lang], prog);
    printf("\n");
    printf("%s\n", lang_options[lang]);
    printf("%s\n", lang_opt_c[lang]);
    printf("%s\n", lang_opt_l[lang]);
    printf("%s\n", lang_hosts[lang]);
}

static int64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static uint16_t in_cksum(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < len) {
        sum += ((uint32_t)p[i] << 8) | p[i + 1];
        i += 2;
    }

    if (i < len)
        sum += (uint32_t)p[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

static uint16_t icmpv6_checksum(const struct in6_addr *src,
                                const struct in6_addr *dst,
                                const unsigned char *pkt,
                                size_t len)
{
    unsigned char tmp[512];
    size_t off = 0;
    uint32_t sum = 0;
    size_t i;

    if (off + sizeof(*src) > sizeof(tmp))
        return 0;
    memcpy(tmp + off, src, sizeof(*src));
    off += sizeof(*src);

    if (off + sizeof(*dst) > sizeof(tmp))
        return 0;
    memcpy(tmp + off, dst, sizeof(*dst));
    off += sizeof(*dst);

    uint32_t icmp_len = (uint32_t)len;
    if (off + 4 > sizeof(tmp))
        return 0;
    memcpy(tmp + off, &icmp_len, 4);
    off += 4;

    uint8_t zero[3] = {0, 0, 0};
    uint8_t nh = 58; /* ICMPv6 */

    if (off + 4 > sizeof(tmp))
        return 0;
    memcpy(tmp + off, zero, 3);
    tmp[off + 3] = nh;
    off += 4;

    if (off + len > sizeof(tmp))
        return 0;
    memcpy(tmp + off, pkt, len);
    off += len;

    for (i = 0; i + 1 < off; i += 2)
        sum += ((uint32_t)tmp[i] << 8) | tmp[i + 1];

    if (i < off)
        sum += (uint32_t)tmp[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

static int host_to_ip(const char *input, char *out_ip, size_t out_size, int *out_family)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (inet_pton(AF_INET, input, &v4) == 1) {
        if (!inet_ntop(AF_INET, &v4, out_ip, out_size))
            return -1;
        *out_family = AF_INET;
        return 0;
    }

    if (inet_pton(AF_INET6, input, &v6) == 1) {
        if (!inet_ntop(AF_INET6, &v6, out_ip, out_size))
            return -1;
        *out_family = AF_INET6;
        return 0;
    }

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *chosen = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    rc = getaddrinfo(input, NULL, &hints, &res);
    if (rc != 0)
        return -1;

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            chosen = ai;
            break;
        }
    }

    if (!chosen)
        chosen = res;

    if (!chosen) {
        freeaddrinfo(res);
        return -1;
    }

    if (chosen->ai_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)chosen->ai_addr;
        if (!inet_ntop(AF_INET, &sa->sin_addr, out_ip, out_size)) {
            freeaddrinfo(res);
            return -1;
        }
        *out_family = AF_INET;
    } else if (chosen->ai_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)chosen->ai_addr;
        if (!inet_ntop(AF_INET6, &sa->sin6_addr, out_ip, out_size)) {
            freeaddrinfo(res);
            return -1;
        }
        *out_family = AF_INET6;
    } else {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}

static int make_dgram_socket(int family, struct sockaddr *addr, socklen_t addrlen,
                             char *err, size_t err_size)
{
    int fd = -1;

    /* ponytail: тестовый хук — форсировать raw-путь (нет прав на dgram в проде) */
    if (getenv("FAST_PING_FORCE_RAW")) {
        snprintf(err, err_size, "forced raw (env)");
        return -1;
    }

    if (family == AF_INET) {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    } else if (family == AF_INET6) {
        fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    } else {
        snprintf(err, err_size, "unsupported family");
        return -1;
    }

    if (fd < 0) {
        snprintf(err, err_size, "socket: %s", strerror(errno));
        return -1;
    }

    if (connect(fd, addr, addrlen) != 0) {
        int e = errno;
        close(fd);
        snprintf(err, err_size, "connect: %s", strerror(e));
        return -1;
    }

    return fd;
}

static int make_raw_socket(int family, struct sockaddr *addr, socklen_t addrlen,
                           char *err, size_t err_size)
{
    int fd = -1;

    if (family == AF_INET) {
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else if (family == AF_INET6) {
        fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    } else {
        snprintf(err, err_size, "unsupported family");
        return -1;
    }

    if (fd < 0) {
        snprintf(err, err_size, "raw socket: %s", strerror(errno));
        return -1;
    }

    /* Не connect()им raw сокет: ядро не доставляет эхо-ответы (type=0)
     * на connected raw ICMP, только собственные ушедшие запросы.
     * Отправляем sendto(), фильтруем ответы по src-IP и ICMP id. */
    (void)addr;
    (void)addrlen;

    return fd;
}

static int build_icmpv4_packet(unsigned char *pkt, size_t pkt_size, uint16_t seq,
                               uint16_t id)
{
    struct icmp_echo_hdr *hdr = (struct icmp_echo_hdr *)pkt;
    size_t payload_len = 32;

    if (pkt_size < sizeof(*hdr) + payload_len)
        return -1;

    memset(pkt, 0, pkt_size);

    hdr->type = 8;     /* ICMP_ECHO */
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->id = htons(id);
    hdr->seq = htons(seq);

    uint64_t ts = (uint64_t)now_ns();
    memcpy(pkt + sizeof(*hdr), &ts, sizeof(ts));

    hdr->checksum = htons(in_cksum(pkt, sizeof(*hdr) + payload_len));
    return (int)(sizeof(*hdr) + payload_len);
}

static int build_icmpv6_packet(unsigned char *pkt, size_t pkt_size, uint16_t seq,
                               uint16_t id,
                               const struct in6_addr *src6,
                               const struct in6_addr *dst6,
                               int need_checksum)
{
    struct icmp6_echo_hdr *hdr = (struct icmp6_echo_hdr *)pkt;
    size_t payload_len = 32;
    size_t total = sizeof(*hdr) + payload_len;

    if (pkt_size < total)
        return -1;

    memset(pkt, 0, pkt_size);

    hdr->type = 128; /* ICMP6_ECHO_REQUEST */
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->id = htons(id);
    hdr->seq = htons(seq);

    uint64_t ts = (uint64_t)now_ns();
    memcpy(pkt + sizeof(*hdr), &ts, sizeof(ts));

    if (need_checksum && src6 && dst6)
        hdr->checksum = htons(icmpv6_checksum(src6, dst6, pkt, total));

    return (int)total;
}

static void finish_stats(PingTask *task, int count, const char *got,
                         const double *rtt, unsigned long received)
{
    if (received > 0) {
        double min_rtt = 0.0;
        double max_rtt = 0.0;
        double sum = 0.0;
        int first = 1;

        for (int i = 1; i <= count; i++) {
            if (!got[i])
                continue;

            if (first) {
                min_rtt = rtt[i];
                max_rtt = rtt[i];
                first = 0;
            } else {
                if (rtt[i] < min_rtt) min_rtt = rtt[i];
                if (rtt[i] > max_rtt) max_rtt = rtt[i];
            }

            sum += rtt[i];
        }

        if (!first) {
            double avg = sum / (double)received;
            double sq = 0.0;

            for (int i = 1; i <= count; i++) {
                if (got[i])
                    sq += (rtt[i] - avg) * (rtt[i] - avg);
            }

            double mdev = received ? sqrt(sq / (double)received) : 0.0;

            task->reachable = 1;
            task->parsed_rtt = 1;
            task->received = received;

            snprintf(task->rtt, sizeof(task->rtt), "%.3f/%.3f/%.3f/%.3f",
                     min_rtt, avg, max_rtt, mdev);
            return;
        }
    }

    snprintf(task->rtt, sizeof(task->rtt), "N/A");
}

static int run_dgram_ping(PingTask *task, int fd)
{
    int count = task->count;
    double *rtt = calloc((size_t)count + 1, sizeof(*rtt));
    char *got = calloc((size_t)count + 1, 1);

    if (!rtt || !got) {
        task->error = ERR_SEND;
        snprintf(task->err, sizeof(task->err), "allocation failed");
        close(fd);
        free(rtt);
        free(got);
        return -1;
    }

    task->sent = 0;
    unsigned long received = 0;
    int recv_error = 0;

    /* Sequential ping: send seq, ждём ответ именно на этот seq (per-seq
     * deadline 2 c), RTT = rx - tx конкретного пакета, затем следующий seq. */
    for (int seq = 1; seq <= count; seq++) {
        if (g_cancelled)
            break;

        unsigned char pkt[128];
        int n = 0;

        if (task->family == AF_INET)
            n = build_icmpv4_packet(pkt, sizeof(pkt), (uint16_t)seq, task->want_id);
        else
            n = build_icmpv6_packet(pkt, sizeof(pkt), (uint16_t)seq, task->want_id, NULL, NULL, 0);

        if (n <= 0) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "build packet failed");
            break;
        }

        if (send(fd, pkt, (size_t)n, 0) < 0) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "send: %s", strerror(errno));
            break;
        }

        int64_t tx = now_ns();
        task->sent++;

        int got_reply = 0;
        int64_t rdeadline = tx + 2000000000LL;

        while (!got_reply && !g_cancelled) {
            int64_t now = now_ns();
            if (now >= rdeadline)
                break;

            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            int64_t remain = rdeadline - now;
            tv.tv_sec = remain / 1000000000LL;
            tv.tv_usec = (useconds_t)((remain % 1000000000LL) / 1000LL);

            int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                recv_error = 1;
                break;
            }
            if (rc == 0)
                break;

            unsigned char buf[256];
            ssize_t rn = recv(fd, buf, sizeof(buf), 0);
            if (rn < 0) {
                if (errno == EINTR)
                    continue;
                recv_error = 1;
                break;
            }

            if (rn < 8)
                continue;

            uint8_t type = buf[0];
            uint16_t pseq = (uint16_t)((buf[6] << 8) | buf[7]);

            int ok_reply = 0;
            if (task->family == AF_INET && type == 0)
                ok_reply = 1;
            else if (task->family == AF_INET6 && type == 129)
                ok_reply = 1;

            if (!ok_reply || pseq != (uint16_t)seq || got[pseq])
                continue;

            int64_t rx = now_ns();
            rtt[pseq] = (rx - tx) / 1000000.0;
            got[pseq] = 1;
            received++;
            got_reply = 1;
        }
    }

    if (recv_error && task->error == ERR_NONE) {
        task->error = ERR_RECV;
        snprintf(task->err, sizeof(task->err), "recv: %s", strerror(errno));
    }

    finish_stats(task, count, got, rtt, received);

    close(fd);
    free(rtt);
    free(got);

    return task->reachable ? 0 : -1;
}

static int ipv6_icmp_offset(const unsigned char *buf, size_t n)
{
    if (n < 40)
        return -1;

    if ((buf[0] >> 4) != 6)
        return -1;

    size_t off = 40;
    uint8_t nh = buf[6];

    while (off < n) {
        if (nh == 58)
            break;

        if (off + 2 > n)
            return -1;

        if (nh == 0 || nh == 43 || nh == 44 || nh == 51 || nh == 60) {
            size_t ext_len = ((size_t)(buf[off + 1] & 0x3F) + 1) * 8;
            if (off + ext_len > n)
                return -1;
            nh = buf[off];
            off += ext_len;
        } else {
            return -1;
        }
    }

    if (nh != 58)
        return -1;

    return (int)off;
}

static int run_raw_ping(PingTask *task, int fd)
{
    int count = task->count;
    double *rtt = calloc((size_t)count + 1, sizeof(*rtt));
    char *got = calloc((size_t)count + 1, 1);

    if (!rtt || !got) {
        task->error = ERR_SEND;
        snprintf(task->err, sizeof(task->err), "allocation failed");
        close(fd);
        free(rtt);
        free(got);
        return -1;
    }

    struct in6_addr src6;
    struct in6_addr dst6;
    memset(&src6, 0, sizeof(src6));
    memset(&dst6, 0, sizeof(dst6));

    int need_v6_checksum = (task->family == AF_INET6);

    if (need_v6_checksum) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, task->ip, &sin6->sin6_addr) != 1) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "bad IPv6 address");
            close(fd);
            free(rtt);
            free(got);
            return -1;
        }

        socklen_t slen = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *)&ss, &slen) == 0) {
            src6 = ((struct sockaddr_in6 *)&ss)->sin6_addr;
        }
        dst6 = sin6->sin6_addr;
    }

    /* Адрес назначения для sendto() — raw сокет не connect()нут */
    struct sockaddr_storage dstss;
    memset(&dstss, 0, sizeof(dstss));
    socklen_t dstlen = 0;
    if (task->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&dstss;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, task->ip, &sin->sin_addr) != 1) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "bad IPv4 address");
            close(fd);
            free(rtt); free(got);
            return -1;
        }
        dstlen = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dstss;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, task->ip, &sin6->sin6_addr) != 1) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "bad IPv6 address");
            close(fd);
            free(rtt); free(got);
            return -1;
        }
        dstlen = sizeof(*sin6);
    }

    task->sent = 0;
    unsigned long received = 0;
    int recv_error = 0;

    /* id пакета: big-endian на проводе -> host-порядковый (без htons),
     * сравниваем с task->want_id (пер-тредовый, unique). */
    for (int seq = 1; seq <= count; seq++) {
        if (g_cancelled)
            break;

        unsigned char pkt[128];
        int n = 0;

        if (task->family == AF_INET) {
            n = build_icmpv4_packet(pkt, sizeof(pkt), (uint16_t)seq, task->want_id);
        } else {
            n = build_icmpv6_packet(pkt, sizeof(pkt), (uint16_t)seq, task->want_id,
                                    &src6, &dst6, need_v6_checksum);
        }

        if (n <= 0) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "build packet failed");
            break;
        }

        if (sendto(fd, pkt, (size_t)n, 0,
                   (struct sockaddr *)&dstss, dstlen) < 0) {
            task->error = ERR_SEND;
            snprintf(task->err, sizeof(task->err), "raw send: %s", strerror(errno));
            break;
        }

        int64_t tx = now_ns();
        task->sent++;

        /* Ждём ответ именно на этот seq */
        int got_reply = 0;
        int64_t rdeadline = tx + 2000000000LL;

        while (!got_reply && !g_cancelled) {
            int64_t now = now_ns();
            if (now >= rdeadline)
                break;

            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            int64_t remain = rdeadline - now;
            tv.tv_sec = remain / 1000000000LL;
            tv.tv_usec = (useconds_t)((remain % 1000000000LL) / 1000LL);

            int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                recv_error = 1;
                break;
            }
            if (rc == 0)
                break;

            unsigned char buf[512];
            ssize_t rn = recv(fd, buf, sizeof(buf), 0);
            if (rn < 0) {
                if (errno == EINTR)
                    continue;
                recv_error = 1;
                break;
            }

            int icmtoff = -1;
            if (task->family == AF_INET) {
                if ((size_t)rn < 20)
                    continue;
                if ((buf[0] >> 4) != 4)
                    continue;
                int ihl = (buf[0] & 0x0F) * 4;
                if (ihl < 20 || (size_t)(ihl + 8) > (size_t)rn)
                    continue;
                icmtoff = ihl;
            } else {
                icmtoff = ipv6_icmp_offset(buf, (size_t)rn);
                if (icmtoff < 0)
                    continue;
            }

            if ((size_t)(icmtoff + 8) > (size_t)rn)
                continue;

            uint8_t type = buf[icmtoff];
            uint16_t pseq = (uint16_t)((buf[icmtoff + 6] << 8) | buf[icmtoff + 7]);
            uint16_t id   = (uint16_t)((buf[icmtoff + 4] << 8) | buf[icmtoff + 5]);

            /* Raw socket не connected — видит ВСЕ ICMP на машине.
             * Фильтруем: src-IP == наш dst + ICMP id == наш want_id
             * (v4 и v6: у dgram-сокетов ядро само фильтрует, у raw — нет). */
            if (task->family == AF_INET) {
                if ((size_t)rn < (size_t)icmtoff + 20)
                    continue;
                const uint8_t *src = buf + 12; /* IPv4 src addr */
                const uint32_t want = ((const struct sockaddr_in *)&dstss)->sin_addr.s_addr;
                if (memcmp(src, &want, 4) != 0)
                    continue;
            }
            if (id != task->want_id)
                continue;

            int ok_reply = 0;
            if (task->family == AF_INET && type == 0)
                ok_reply = 1;
            else if (task->family == AF_INET6 && type == 129)
                ok_reply = 1;

            if (!ok_reply || pseq != (uint16_t)seq || got[pseq])
                continue;

            int64_t rx = now_ns();
            rtt[pseq] = (rx - tx) / 1000000.0;
            got[pseq] = 1;
            received++;
            got_reply = 1;
        }
    }

    if (recv_error && task->error == ERR_NONE) {
        task->error = ERR_RECV;
        snprintf(task->err, sizeof(task->err), "raw recv: %s", strerror(errno));
    }

    finish_stats(task, count, got, rtt, received);

    close(fd);
    free(rtt);
    free(got);

    return task->reachable ? 0 : -1;
}

static void *ping_thread(void *arg)
{
    PingTask *task = (PingTask *)arg;

    if (g_cancelled)
        return NULL;

    if (host_to_ip(task->input, task->ip, sizeof(task->ip), &task->family) != 0) {
        task->resolved = 0;
        task->error = ERR_RESOLVE;
        return NULL;
    }

    task->resolved = 1;

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));

    if (task->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, task->ip, &sin->sin_addr) != 1) {
            task->error = ERR_SOCKET;
            snprintf(task->err, sizeof(task->err), "bad IPv4 address");
            return NULL;
        }
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, task->ip, &sin6->sin6_addr) != 1) {
            task->error = ERR_SOCKET;
            snprintf(task->err, sizeof(task->err), "bad IPv6 address");
            return NULL;
        }
    }

    socklen_t len =
        (task->family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    char err1[128];
    char err2[128];

    int fd = make_dgram_socket(task->family, (struct sockaddr *)&ss, len,
                               err1, sizeof(err1));

    if (fd < 0) {
        fd = make_raw_socket(task->family, (struct sockaddr *)&ss, len,
                             err2, sizeof(err2));
        if (fd < 0) {
            task->error = ERR_SOCKET;
            snprintf(task->err, sizeof(task->err), "dgram: %s; raw: %s", err1, err2);
            return NULL;
        }
        run_raw_ping(task, fd);
        return NULL;
    }

    run_dgram_ping(task, fd);
    return NULL;
}

static const char *status_color(int reachable)
{
    if (!g_color)
        return "";
    return reachable ? "\033[0;32m" : "\033[0;31m";
}

static const char *error_color(void)
{
    if (!g_color)
        return "";
    return "\033[0;31m";
}

static const char *reset_color(void)
{
    if (!g_color)
        return "";
    return "\033[0m";
}

static void print_result(const PingTask *task, int lang)
{
    if (task->error == ERR_RESOLVE) {
        printf("%s%s%s %-15s | %s\n",
               error_color(), lang_error[lang], reset_color(),
               task->input, lang_dns[lang]);
        return;
    }

    if (task->error == ERR_SOCKET) {
        printf("%s%s%s %-15s | %s: %s\n",
               error_color(), lang_error[lang], reset_color(),
               task->input, lang_socket[lang], task->err);
        return;
    }

    if (task->error == ERR_SEND) {
        printf("%s%s%s %-15s | %s: %s\n",
               error_color(), lang_error[lang], reset_color(),
               task->input, lang_send[lang], task->err);
        return;
    }

    if (task->error == ERR_RECV) {
        printf("%s%s%s %-15s | %s: %s\n",
               error_color(), lang_error[lang], reset_color(),
               task->input, lang_recv[lang], task->err);
        return;
    }

    if (task->reachable) {
        printf("%s%s%s %-15s | %s%s\n",
               status_color(1), lang_online[lang], reset_color(),
               task->ip, lang_rtt[lang], task->rtt);
    } else {
        printf("%s%s%s %-15s | %s\n",
               status_color(0), lang_offline[lang], reset_color(),
               task->ip, lang_unavailable[lang]);
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int lang = 0;
    int has_c = 0;
    long packet_count = 0;

    if (isatty(STDOUT_FILENO))
        g_color = 1;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while ((opt = getopt(argc, argv, "c:l:")) != -1) {
        switch (opt) {
        case 'c': {
            char *end = NULL;
            packet_count = strtol(optarg, &end, 10);
            if (!end || *end != '\0' || packet_count <= 0 || packet_count > 1000000) {
                fprintf(stderr, "Invalid packet count\n");
                usage(argv[0], lang);
                return 1;
            }
            has_c = 1;
            break;
        }
        case 'l': {
            char *end = NULL;
            long l = strtol(optarg, &end, 10);
            if (!end || *end != '\0' || (l != 0 && l != 1)) {
                fprintf(stderr, "Invalid language\n");
                usage(argv[0], lang);
                return 1;
            }
            lang = (int)l;
            break;
        }
        default:
            usage(argv[0], lang);
            return 1;
        }
    }

    if (!has_c) {
        usage(argv[0], lang);
        return 1;
    }

    size_t n = (size_t)(argc - optind);
    if (n == 0) {
        usage(argv[0], lang);
        return 1;
    }

    PingTask *tasks = calloc(n, sizeof(*tasks));
    pthread_t *threads = malloc(n * sizeof(*threads));

    if (!tasks || !threads) {
        fprintf(stderr, "Allocation failed\n");
        free(tasks);
        free(threads);
        return 1;
    }

    for (size_t i = 0; i < n; i++) {
        tasks[i].input = argv[optind + i];
        tasks[i].count = (int)packet_count;
        tasks[i].family = 0;
        tasks[i].want_id = next_icmp_id();
        tasks[i].resolved = 0;
        tasks[i].reachable = 0;
        tasks[i].parsed_rtt = 0;
        tasks[i].sent = 0;
        tasks[i].received = 0;
        tasks[i].error = ERR_NONE;
        snprintf(tasks[i].rtt, sizeof(tasks[i].rtt), "N/A");
        tasks[i].err[0] = '\0';
    }

    printf("%s\n", lang_header[lang]);
    printf("------------------------------------------------------------\n");

    size_t created = 0;
    for (size_t i = 0; i < n; i++) {
        if (g_cancelled)
            break;

        int rc = pthread_create(&threads[created], NULL, ping_thread, &tasks[i]);
        if (rc != 0) {
            fprintf(stderr, "pthread_create failed for %s: %s\n", tasks[i].input, strerror(rc));
            break;
        }
        created++;
    }

    for (size_t i = 0; i < created; i++) {
        if (g_cancelled)
            break;
        pthread_join(threads[i], NULL);
    }

    if (g_cancelled) {
        for (size_t i = 0; i < created; i++)
            pthread_join(threads[i], NULL);

        printf("%s", lang_interrupted[lang]);
        free(tasks);
        free(threads);
        return 1;
    }

    for (size_t i = 0; i < created; i++)
        print_result(&tasks[i], lang);

    printf("------------------------------------------------------------\n");

    size_t up = 0, down = 0;
    unsigned long sent_total = 0, received_total = 0;

    for (size_t i = 0; i < created; i++) {
        if (tasks[i].reachable)
            up++;
        else
            down++;

        sent_total += tasks[i].sent;
        received_total += tasks[i].received;
    }

    size_t host_loss = created ? (down * 100) / created : 0;
    unsigned long pkt_loss = sent_total ? ((sent_total - received_total) * 100) / sent_total : 0;

    printf("\n%s:\n", lang_summary[lang]);
    printf(lang_stats_hosts[lang], created, up, down, host_loss);
    printf("\n");
    printf(lang_stats_pkts[lang], sent_total, received_total, pkt_loss);
    printf("\n");

    free(tasks);
    free(threads);
    return 0;
}
