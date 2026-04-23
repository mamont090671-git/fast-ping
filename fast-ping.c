#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct {
    char *ip;
    int count;
    int lang;
    int thread_id;
    int is_valid;
    int success;
} PingTask;

volatile sig_atomic_t cancelled = 0;
int total_threads = 0;
int completed_threads = 0;

static void signal_handler(int sig) {
    cancelled = 1;
    (void)sig;
}

// Языковые строки
/* Прототипы функций */
int is_valid_ip(const char *ip);
int resolve_hostname(const char *hostname, char *ip_buffer, size_t buffer_size);

const char *lang_status[] = {"STATUS", "СТАТУС"};
const char *lang_ip[] = {"IP ADDRESS", "IP АДРЕС"};
const char *lang_time[] = {"TIME (min/avg/max/mdev)", "ВРЕМЯ (min/avg/max/mdev)"};
const char *lang_online[] = {"[ ONLINE  ]", "[ ONLINE  ]"};
const char *lang_offline[] = {"[ OFFLINE ]", "[ OFFLINE ]"};
const char *lang_error[] = {"[ ERROR   ]", "[ ERROR   ]"};
const char *lang_usage[] = {"Usage: %s -c <packets> <ip1> <ip2> ...", "Использование: %s -c <кол-во пакетов> <ip1> <ip2> ..."};
const char *lang_rtt[] = {"RTT (ms): ", "RTT (ms): "};
const char *lang_unavailable[] = {"Unavailable", "Недоступен"};
const char *lang_popen_error[] = {"Error popen", "Ошибка popen"};
const char *lang_thread_error[] = {"Error creating thread for %s", "Ошибка создания потока для %s"};
const char *lang_interrupted[] = {"\n\nInterrupted by user\n", "\n\nПрервано пользователем\n"};
const char *lang_ping_error[] = {"Error executing ping", "Ошибка выполнения ping"};
const char *lang_summary[] = {"SUMMARY", "СВОДКА"};
const char *lang_stats[] = {"Total: %d | Success: %d | Failed: %d | Loss: %d%%", "Всего: %d | Успешно: %d | Ошибок: %d | Потерь: %d%%"};

void* ping_ip(void* arg) {
    PingTask *task = (PingTask*)arg;
    char command[512];
    char ip_or_host[256];
    char buffer[512];
    char latency_info[128] = "N/A";
    // Проверка на IP или доменное имя
    if (is_valid_ip(task->ip)) {
        strncpy(ip_or_host, task->ip, sizeof(ip_or_host));
        ip_or_host[sizeof(ip_or_host) - 1] = '\0';
    } else {
        // Это доменное имя, пробуем разрешить
        if (resolve_hostname(task->ip, ip_or_host, sizeof(ip_or_host)) != 0) {
            printf("\033[0;31m%s\033[0m %-15s | DNS resolution failed\n", lang_error[task->lang], task->ip);
            task->is_valid = 0;
            task->success = 0;
            return NULL;
        }
    }

    // Используем LC_ALL=C для стандартного вывода ping (RTT)
    snprintf(command, sizeof(command), "LC_ALL=C ping -c %d -W 2 %s", task->count, ip_or_host);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("\033[0;31m%s\033[0m %-15s | %s\n", lang_error[task->lang], task->ip, lang_popen_error[task->lang]);
        task->success = 0;
        return NULL;
    }
    
     int packets_sent = 0;
    int packets_received = 0;
    int ping_success = 0;
    int rtt_found = 0;
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Поиск строки с RTT
        if (strstr(buffer, "rtt") || strstr(buffer, "round-trip")) {
            task->is_valid = 1;
            rtt_found = 1;
            char *start = strchr(buffer, '=');
            if (start) {
                strncpy(latency_info, start + 2, sizeof(latency_info) - 1);
                latency_info[sizeof(latency_info) - 1] = '\0';
                
                // Удаляем начальные пробелы
                char *p = latency_info;
                while (*p == ' ') p++;
                
                // Удаляем лишние пробелы и переносы строки в конце
                char *end = p + strlen(p) - 1;
                while (end > p && (*end == ' ' || *end == '\n' || *end == '\r')) {
                    *end = '\0';
                    end--;
                }
                
                if (strlen(p) > 0) {
                    strncpy(latency_info, p, sizeof(latency_info) - 1);
                    latency_info[sizeof(latency_info) - 1] = '\0';
                }
            }
        }
        
        // Парсинг статистики ping
        if (strstr(buffer, "packets transmitted") && strstr(buffer, " received")) {
            char *trans = strstr(buffer, "packets transmitted");
            char *rec = strstr(buffer, " received");
            // Извлекаем число из строки "X packets transmitted, Y received"
            char *end_trans = strchr(trans, ',');
            if (end_trans) {
                *end_trans = '\0';
            }
            char *end_rec = strchr(rec, ',');
            if (end_rec) {
                *end_rec = '\0';
            }
            packets_sent = atoi(trans);
            packets_received = atoi(rec);
            if (packets_sent > 0 && packets_received == packets_sent) {
                ping_success = 1;
            }
        }
    }
    
    // Если не смогли распарсить статистику, используем exit code
    int status = pclose(fp);
    if (!ping_success && WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        ping_success = (exit_code == 0);
    }
    task->success = ping_success;
    
    // Не печатать, если прерывание произошло
    if (!cancelled) {
        if (task->success) {
            printf("\033[0;32m%s\033[0m %-15s | %s%s\n", lang_online[task->lang], task->ip, lang_rtt[task->lang], latency_info);
        } else {
            printf("\033[0;31m%s\033[0m %-15s | %s\n", lang_offline[task->lang], task->ip, lang_unavailable[task->lang]);
        }
    }
    
    // Атомарное обновление счетчика завершенных
    __sync_fetch_and_add(&completed_threads, 1);
    
    return NULL;
}

int is_valid_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int resolve_hostname(const char *hostname, char *ip_buffer, size_t buffer_size) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    he = gethostbyname(hostname);
    if (he == NULL) {
        return -1; // DNS lookup failed
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    for (i = 0; addr_list[i] != NULL; i++) {
        if (inet_ntoa(*addr_list[i]) != NULL) {
            strncpy(ip_buffer, inet_ntoa(*addr_list[i]), buffer_size - 1);
            ip_buffer[buffer_size - 1] = '\0';
            return 0;
        }
    }

    return -1;
}

int main(int argc, char *argv[]) {
    int lang = 0;
    int success_count = 0;
    int failed_count = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int has_c = 0;
    int packet_count = 0;
    int arg_start = 1;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            lang = atoi(argv[++i]);
            if (lang < 0 || lang > 1) {
                fprintf(stderr, "Error: Invalid language code. Use -l 0 (English) or -l 1 (Russian).\n");
                printf(lang_usage[0], argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            has_c = 1;
            packet_count = atoi(argv[++i]);
            if (packet_count <= 0) {
                fprintf(stderr, "Error: Packet count must be positive.\n");
                printf(lang_usage[0], argv[0]);
                return 1;
            }
            arg_start = i + 1;
        }
    }
    
    if (!has_c || packet_count <= 0) {
        printf(lang_usage[lang], argv[0]);
        printf("\nOptions:\n");
        printf("  -c <count>    Number of packets to ping\n");
        printf("  -l <lang>     Language: 0=English, 1=Russian (default: 0)\n");
        printf("  Hosts: Can be IP addresses or domain names (e.g., google.com)\n");
        return 1;
    }
    
    int num_ips = argc - arg_start;
    if (num_ips < 1) {
        printf(lang_usage[lang], argv[0]);
        return 1;
    }
    
    total_threads = num_ips;
    completed_threads = 0;
    
    pthread_t threads[num_ips];
    PingTask tasks[num_ips];
    
    printf("\n%-11s %-15s | %s\n", lang_status[lang], lang_ip[lang], lang_time[lang]);
    printf("------------------------------------------------------------\n");
    
    for (int i = 0; i < num_ips && !cancelled; i++) {
        tasks[i].ip = argv[arg_start + i];
        tasks[i].count = packet_count;
        tasks[i].lang = lang;
        tasks[i].thread_id = i;
        tasks[i].is_valid = -1;
        tasks[i].success = 0;
        
        if (pthread_create(&threads[i], NULL, ping_ip, &tasks[i]) != 0) {
            fprintf(stderr, lang_thread_error[lang], tasks[i].ip);
            return 1;
        }
    }
    
    if (cancelled) {
        fprintf(stdout, "%s", lang_interrupted[lang]);
        for (int i = 0; i < num_ips; i++) {
            pthread_cancel(threads[i]);
            pthread_join(threads[i], NULL);
        }
        return 1;
    }
    
    for (int i = 0; i < num_ips; i++) {
        pthread_join(threads[i], NULL);
    }
    
    for (int i = 0; i < num_ips; i++) {
        if (tasks[i].is_valid == 1) {
            if (tasks[i].success) success_count++;
            else failed_count++;
        } else {
            failed_count++;
        }
    }
    
    printf("------------------------------------------------------------\n");
    printf("\n");
    
    // SUMMARY
    printf("%s:\n", lang_summary[lang]);
    int loss = num_ips > 0 ? (failed_count * 100 / num_ips) : 0;
    printf(lang_stats[lang], num_ips, success_count, failed_count, loss);
    printf("\n");
    
    return 0;
}
