/*
 * threads.h - Заголовочный файл для thread функций
 */

#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ФУНКЦИИ ЗАПУСКА THREADS
 * ============================================================================ */

/**
 * Запустить peer thread для обработки NTP-запросов
 * 
 * @return 0 на успех, -1 на ошибку
 * 
 * RFC 5905 Section 5: запустить peer process для каждого сервера времени
 */
int start_peer_thread(void);

/**
 * Остановить peer thread
 */
void stop_peer_thread(void);

/**
 * Запустить clock thread для дисциплины часов
 * 
 * @return 0 на успех, -1 на ошибку
 * 
 * RFC 5905 Section 5: запустить clock adjust process
 */
int start_clock_thread(void);

/**
 * Остановить clock thread
 */
void stop_clock_thread(void);

/* ============================================================================
 * ФУНКЦИИ УПРАВЛЕНИЯ
 * ============================================================================ */

/**
 * Дождаться завершения всех threads
 */
void wait_for_threads(void);

/**
 * Получить количество активных threads
 * 
 * @return количество активных threads
 */
int get_active_threads(void);

/**
 * Проверить, запущены ли threads
 * 
 * @return 1 если запущены, 0 если остановлены
 */
int is_threads_running(void);

/**
 * Отправить сигнал на threads (для graceful shutdown)
 * 
 * @param sig номер сигнала
 */
void signal_threads(int sig);

#ifdef __cplusplus
}
#endif

#endif /* THREADS_H */
