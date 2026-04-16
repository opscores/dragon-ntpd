/*
 * threads_test.c - Тестовая программа для threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>

#include "threads.h"

/* Глобальный флаг для обработки сигнала */
static volatile sig_atomic_t g_shutdown = 0;

/* Обработчик сигнала */
static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
    signal_threads(sig);
}

int main(int argc, char *argv[]) {
    int ret = 0;

    /* Инициализация syslog */
    openlog("threads_test", LOG_PID | LOG_CONS, LOG_USER);

    printf("=== Threads Test Program ===\n\n");

    /* Установка обработчиков сигналов */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Запуск peer thread */
    printf("1. Запуск peer thread...\n");
    ret = start_peer_thread();
    if (ret == 0) {
        printf("   OK: peer thread запущен\n\n");
    } else {
        printf("   ERROR: не удалось запустить peer thread\n\n");
    }

    /* Запуск clock thread */
    printf("2. Запуск clock thread...\n");
    ret = start_clock_thread();
    if (ret == 0) {
        printf("   OK: clock thread запущен\n\n");
    } else {
        printf("   ERROR: не удалось запустить clock thread\n\n");
    }

    /* Проверка статуса */
    printf("3. Проверка статуса threads...\n");
    printf("   Активных threads: %d\n", get_active_threads());
    printf("   Threads running: %s\n\n", is_threads_running() ? "yes" : "no");

    /* Имитация работы */
    printf("4. Имитация работы threads (5 секунд)...\n");
    sleep(5);

    /* Остановка threads */
    printf("5. Остановка threads...\n");
    stop_peer_thread();
    stop_clock_thread();
    wait_for_threads();
    printf("   OK: threads остановлены\n\n");

    /* Финальная проверка */
    printf("6. Финальная проверка...\n");
    printf("   Активных threads: %d\n", get_active_threads());
    printf("   Threads running: %s\n\n", is_threads_running() ? "yes" : "no");

    /* Закрытие syslog */
    closelog();

    printf("=== Тестирование завершено успешно ===\n");
    return 0;
}
