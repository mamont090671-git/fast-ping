#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>

typedef struct {
    char *ip;
    int count;
    int lang;  // 0 = English, 1 = Russian
} PingTask;

volatile int cancelled = 0;

static void signal_handler(int sig) {
    cancelled = 1;
}

// Языковые строки
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

void* ping_ip(void* arg) {
    PingTask *task = (PingTask*)arg;
    char command[256];
    char buffer[256];
    char latency_info[128] = "N/A";

    // Set C locale so ping outputs "rtt" instead of Russian "итого"
    snprintf(command, sizeof(command), "LC_ALL=C ping -c %d -W 2 %s 2>&1", task->count, task->ip);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("\033[0;31m%s\033[0m %-15s | %s\n", lang_error[task->lang], task->ip, lang_popen_error[task->lang]);
        return NULL;
    }
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Look for RTT results line
        if (strstr(buffer, "rtt") || strstr(buffer, "round-trip")) {
            char *start = strchr(buffer, '=');
            if (start) {
                // Copy data after '=' with size limit
                size_t remaining = sizeof(latency_info) - 1;
                strncpy(latency_info, start + 2, remaining);
                latency_info[remaining] = 0;
                // Remove trailing spaces and newlines
                char *end = latency_info + strlen(latency_info) - 1;
                while (end > latency_info && (*end == ' ' || *end == '\n' || *end == '\r')) {
                    *end = 0;
                    end--;
                }
            }
        }
    }
    
    int status = pclose(fp);
    
    // Check exit status
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            printf("\033[0;32m%s\033[0m %-15s | %s%s\n", lang_online[task->lang], task->ip, lang_rtt[task->lang], latency_info);
        } else {
            printf("\033[0;31m%s\033[0m %-15s | %s\n", lang_offline[task->lang], task->ip, lang_unavailable[task->lang]);
        }
    } else {
        printf("\033[0;31m%s\033[0m %-15s | %s\n", lang_error[task->lang], task->ip, lang_ping_error[task->lang]);
    }
    fflush(stdout);
    
    return NULL;
}

int is_valid_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int main(int argc, char *argv[]) {
    int lang = 0;  // Default: English
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse arguments: -l 1 for Russian, -l 0 for English, -c <count> <ips>
    int has_c = 0;
    int packet_count = 0;
    int arg_start = 1;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            lang = atoi(argv[++i]);
            if (lang < 0 || lang > 1) {
                printf(lang_usage[lang], argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            has_c = 1;
            packet_count = atoi(argv[++i]);
            arg_start = i + 1;
        }
    }
    
    if (!has_c || packet_count <= 0) {
        printf(lang_usage[lang], argv[0]);
        printf("\nOptions:\n");
        printf("  -c <count>    Number of packets to ping\n");
        printf("  -l <lang>     Language: 0=English, 1=Russian (default: 0)\n");
        return 1;
    }
    
    int num_ips = argc - arg_start;
    
    if (num_ips < 1) {
        printf(lang_usage[lang], argv[0]);
        return 1;
    }
    
    pthread_t threads[num_ips];
    PingTask tasks[num_ips];
    
    // Print header in selected language
    printf("\n%-11s %-15s | %s\n", lang_status[lang], lang_ip[lang], lang_time[lang]);
    printf("------------------------------------------------------------\n");
    
    // Start threads
    for (int i = 0; i < num_ips && !cancelled; i++) {
        tasks[i].ip = argv[arg_start + i];
        tasks[i].count = packet_count;
        tasks[i].lang = lang;
        if (pthread_create(&threads[i], NULL, ping_ip, &tasks[i]) != 0) {
            fprintf(stderr, lang_thread_error[lang], tasks[i].ip);
            return 1;
        }
    }
    
    // Check for interruption
    if (cancelled) {
        printf(lang_interrupted[lang]);
        for (int i = 0; i < num_ips; i++) {
            pthread_cancel(threads[i]);
        }
        return 1;
    }
    
    // Wait for all threads
    for (int i = 0; i < num_ips; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("------------------------------------------------------------\n\n");
    return 0;
}
