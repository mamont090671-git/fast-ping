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
} PingTask;

volatile int cancelled = 0;

static void signal_handler(int sig) {
    cancelled = 1;
}

void* ping_ip(void* arg) {
    PingTask *task = (PingTask*)arg;
    char command[256];
    char buffer[256];
    char latency_info[128] = "N/A";

    // Устанавливаем локаль C для текущего потока, чтобы ping выводил "rtt" вместо "итого"
    // (Работает в POSIX системах)
    
   // Формируем команду. -c пакеты, -W таймаут ожидания ответа
    snprintf(command, sizeof(command), "LC_ALL=C ping -c %d -W 2 %s 2>&1", task->count, task->ip);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("\033[0;31m[ ERROR   ]\033[0m %-15s | Ошибка popen\n", task->ip);
        return NULL;
    }
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Ищем строку с результатами RTT
        if (strstr(buffer, "rtt") || strstr(buffer, "round-trip")) {
            char *start = strchr(buffer, '=');
            if (start) {
                // Копируем данные после '=' и ограничиваем размер
                size_t remaining = sizeof(latency_info) - 1;
                strncpy(latency_info, start + 2, remaining);
                latency_info[remaining] = 0;
                // Убираем лишние пробелы и переносы
                char *end = latency_info + strlen(latency_info) - 1;
                while (end > latency_info && (*end == ' ' || *end == '\n' || *end == '\r')) {
                    *end = 0;
                    end--;
                }
            }
        }
    }
    
    // pclose возвращает статус завершения команды
    int status = pclose(fp);
    
  // Проверка статуса (WIFEXITED и WEXITSTATUS)
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        // exit_code 0 = все пинги успешны, 1 = некоторые пакеты потеряны, 2 = ошибка
        if (exit_code == 0) {
            printf("\033[0;32m[ ONLINE  ]\033[0m %-15s | RTT (ms): %s\n", task->ip, latency_info);
        } else {
            printf("\033[0;31m[ OFFLINE ]\033[0m %-15s | Недоступен\n", task->ip);
        }
    } else {
        printf("\033[0;31m[ ERROR   ]\033[0m %-15s | Ошибка выполнения ping\n", task->ip);
    }
    fflush(stdout);
    
    return NULL;
}

int is_valid_ip(const char *ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int main(int argc, char *argv[]) {
    // Регистрация обработчика сигнала
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Проверка аргументов: ./program -c 3 8.8.8.8 1.1.1.1
    if (argc < 4 || strcmp(argv[1], "-c") != 0) {
        printf("Использование: %s -c <кол-во пакетов> <ip1> <ip2> ...\n", argv[0]);
        return 1;
    }
    
    int packet_count = atoi(argv[2]);
    int num_ips = argc - 3;
    
    pthread_t threads[num_ips];
    PingTask tasks[num_ips];
    
    printf("\n%-11s %-15s | %s\n", "СТАТУС", "IP АДРЕС", "ВРЕМЯ (min/avg/max/mdev)");
    printf("------------------------------------------------------------\n");
    
    // Запуск потоков
    for (int i = 0; i < num_ips && !cancelled; i++) {
        tasks[i].ip = argv[i + 3];
        tasks[i].count = packet_count;
        if (pthread_create(&threads[i], NULL, ping_ip, &tasks[i]) != 0) {
            fprintf(stderr, "Ошибка создания потока для %s\n", tasks[i].ip);
            return 1;
        }
    }
    
    // Проверка на прерывание
    if (cancelled) {
        printf("\n\nПрервано пользователем\n");
        for (int i = 0; i < num_ips; i++) {
            pthread_cancel(threads[i]);
        }
        return 1;
    }
    
    // Ожидание завершения всех потоков
    for (int i = 0; i < num_ips; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("------------------------------------------------------------\n\n");
    return 0;
}

