/*
 * threads.c - Реализация peer и clock threads согласно RFC 5905 Section 5
 *
 * RFC 5905 требует:
 * - Отдельный peer process для каждого сервера времени
 * - Отдельный clock adjust process для дисциплины часов
 *
 * Эта реализация использует pthread вместо отдельных процессов
 * для упрощения и совместимости.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "ntpd.h"

/* ============================================================================
 * ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
 * ============================================================================ */

/* Флаг для остановки threads */
static volatile int g_threads_running = 1;

/* Мьютекс для синхронизации доступа к общим ресурсам */
static pthread_mutex_t g_threads_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Условный сигнал для синхронизации */
static pthread_cond_t g_threads_cond = PTHREAD_COND_INITIALIZER;

/* Счётчик активных threads */
static int g_active_threads = 0;

/* ============================================================================
 * ФУНКЦИЯ start_peer_thread
 * ============================================================================
 * RFC 5905 Section 5: запустить peer thread для обработки запросов от NTP серверов
 * 
 * Peer thread отвечает за:
 * - Приём NTP-запросов от клиентов
 * - Отправку NTP-ответов
 * - Обработку Leap Indicator
 * - Поддержку symmetric и broadcast mode
 */
int start_peer_thread(void) {
    if (g_threads_running) {
        syslog(LOG_WARNING, "Peer thread уже запущен");
        return -1;
    }

    pthread_t thread;
    int ret = pthread_create(&thread, NULL, peer_thread_func, NULL);
    
    if (ret != 0) {
        syslog(LOG_ERR, "Ошибка создания peer thread: %s", strerror(ret));
        return -1;
    }

    syslog(LOG_INFO, "Peer thread запущен (PID: %d)", getpid());
    g_threads_running = 1;
    g_active_threads++;

    return 0;
}

/* ============================================================================
 * ФУНКЦИЯ peer_thread_func (внутренняя)
 * ============================================================================
 * Основной цикл peer thread
 */
static void* peer_thread_func(void *arg) {
    (void)arg;

    syslog(LOG_INFO, "Peer thread начал работу");

    while (g_threads_running) {
        /* Ждём синхронизации (можно добавить таймаут) */
        pthread_mutex_lock(&g_threads_mutex);
        while (g_threads_running) {
            pthread_cond_wait(&g_threads_cond, &g_threads_mutex);
        }
        pthread_mutex_unlock(&g_threads_mutex);

        /* Проверка флага остановки */
        if (!g_threads_running) {
            break;
        }

        /* Здесь должна быть логика обработки NTP-запросов */
        /* Пока заглушка - просто спим */
        usleep(100000); /* 100ms */
    }

    syslog(LOG_INFO, "Peer thread остановлен");
    g_active_threads--;

    return NULL;
}

/* ============================================================================
 * ФУНКЦИЯ stop_peer_thread
 * ============================================================================
 * Остановить peer thread
 */
void stop_peer_thread(void) {
    pthread_mutex_lock(&g_threads_mutex);
    g_threads_running = 0;
    pthread_cond_broadcast(&g_threads_cond);
    pthread_mutex_unlock(&g_threads_mutex);
    syslog(LOG_INFO, "Запрос на остановку peer thread");
}

/* ============================================================================
 * ФУНКЦИЯ start_clock_thread
 * ============================================================================
 * RFC 5905 Section 5: запустить clock thread для дисциплины часов
 * 
 * Clock thread отвечает за:
 * - Вычисление смещения (offset)
 * - Применение коррекции времени (slew или step)
 * - Обновление root dispersion
 * - Фильтрацию выбросов (алгоритм Маркса)
 */
int start_clock_thread(void) {
    if (g_threads_running) {
        syslog(LOG_WARNING, "Clock thread уже запущен");
        return -1;
    }

    pthread_t thread;
    int ret = pthread_create(&thread, NULL, clock_thread_func, NULL);
    
    if (ret != 0) {
        syslog(LOG_ERR, "Ошибка создания clock thread: %s", strerror(ret));
        return -1;
    }

    syslog(LOG_INFO, "Clock thread запущен (PID: %d)", getpid());
    g_threads_running = 1;
    g_active_threads++;

    return 0;
}

/* ============================================================================
 * ФУНКЦИЯ clock_thread_func (внутренняя)
 * ============================================================================
 * Основной цикл clock thread
 */
static void* clock_thread_func(void *arg) {
    (void)arg;

    syslog(LOG_INFO, "Clock thread начал работу");

    while (g_threads_running) {
        /* Ждём синхронизации */
        pthread_mutex_lock(&g_threads_mutex);
        while (g_threads_running) {
            pthread_cond_wait(&g_threads_cond, &g_threads_mutex);
        }
        pthread_mutex_unlock(&g_threads_mutex);

        /* Проверка флага остановки */
        if (!g_threads_running) {
            break;
        }

        /* Здесь должна быть логика дисциплины часов:
         * 1. Вычисление смещения от сервера времени
         * 2. Фильтрация выбросов (алгоритм Маркса)
         * 3. Применение коррекции (slew или step)
         * 4. Обновление root dispersion
         */
        
        /* Пока заглушка - просто спим */
        usleep(100000); /* 100ms */
    }

    syslog(LOG_INFO, "Clock thread остановлен");
    g_active_threads--;

    return NULL;
}

/* ============================================================================
 * ФУНКЦИЯ stop_clock_thread
 * ============================================================================
 * Остановить clock thread
 */
void stop_clock_thread(void) {
    pthread_mutex_lock(&g_threads_mutex);
    g_threads_running = 0;
    pthread_cond_broadcast(&g_threads_cond);
    pthread_mutex_unlock(&g_threads_mutex);
    syslog(LOG_INFO, "Запрос на остановку clock thread");
}

/* ============================================================================
 * ФУНКЦИЯ wait_for_threads
 * ============================================================================
 * Дождаться завершения всех threads
 */
void wait_for_threads(void) {
    while (g_active_threads > 0) {
        usleep(10000); /* 10ms */
    }
}

/* ============================================================================
 * ФУНКЦИЯ get_active_threads
 * ============================================================================
 * Получить количество активных threads
 */
int get_active_threads(void) {
    return g_active_threads;
}

/* ============================================================================
 * ФУНКЦИЯ is_threads_running
 * ============================================================================
 * Проверить, запущены ли threads
 */
int is_threads_running(void) {
    return g_threads_running;
}

/* ============================================================================
 * ФУНКЦИЯ signal_threads
 * ============================================================================
 * Отправить сигнал на threads (для graceful shutdown)
 */
void signal_threads(int sig) {
    syslog(LOG_INFO, "Signal %d получен, останавливаем threads", sig);
    stop_peer_thread();
    stop_clock_thread();
}
