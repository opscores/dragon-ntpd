#define _POSIX_C_SOURCE 200809L
/**
 * threads.c - Многопоточная обработка NTP-пэеров и системных часов
 *
 * Реализация согласно RFC 5905 Section 5:
 * - Каждый NTP-пэр обрабатывается в отдельном потоке
 * - Системные часы (дисплей, календарь) обрабатываются в отдельном потоке
 *
 * POSIX best practices (POSIX threads):
 * - Использование pthread_mutex для синхронизации доступа к общим данным
 * - pthread_cond для уведомления потоков об изменениях
 * - pthread_detach для автоматической очистки ресурсов
 * - Проверка возврата всех pthread_* функций
 * - Правильное управление памятью
 * - Обработка ошибок
 * - Атомарные операции для флагов (C11)
 * - Барьеры памяти для согласованности видимости данных
 */

#include "ntp_packet.h"
#include "ntpd.h"
#include "time_sync.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h> /* C11 atomic operations */
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

/* ============================================================================
 * Константы для типов коррекции часов (RFC 5905 Section 5.1)
 * ============================================================================
 */

#define STEP 1 /* Мгновенная коррекция (clock_settime) */
#define SLEW 2 /* Плавная коррекция (adjtime) */

/* ============================================================================
 * Контекстные структуры для потоков
 * ============================================================================
 */

/**
 * Контекст потока обработки пэера
 * Содержит все данные, необходимые для обработки одного NTP-пэера
 *
 * RFC 5905 Section 5: Каждый NTP-пэр обрабатывается в отдельном потоке
 * POSIX best practices: Использование atomic для флагов и дескрипторов
 *
 * @note Убраны неиспользуемые поля: sock_type (всегда SOCK_DGRAM),
 *       thread_id (управляется через g_peer_threads[]),
 *       sock_cond (не работает с MSG_DONTWAIT)
 */
typedef struct {
    int idx;                                     // Peer index in peer pool
    int sock_fd;                                 // Socket file descriptor
    char ip[INET_ADDRSTRLEN];                    // Peer IP address
    char port[16];                               // Peer port
    pthread_mutex_t sock_mutex;                  // Mutex for socket operations
    struct sockaddr_storage client_addr_storage; // Buffer for client address
    socklen_t client_addr_len;                   // Client address length
    PeerState* peer_state;                       // Peer state
    atomic_bool sock_valid; // Socket validity flag (atomic for signal safety)
} PeerThreadContext;

/**
 * Clock thread context
 * Contains data for updating system clock
 */
typedef struct {
    int interval_ms;             /* Update interval in ms */
    pthread_mutex_t clock_mutex; /* Mutex for clock access */
    pthread_cond_t clock_cond;   /* Condition for waking up thread */
    bool running;                /* Thread running flag */
    pthread_t thread_id;         /* Thread descriptor */
    int64_t last_offset_us;      /* Last correction value */
    int last_correction;         /* Last correction (SLEW/STEP) */
} ClockThreadContext;

/* ============================================================================
 * Глобальные переменные
 * ============================================================================
 */

/* Контекст потока пэера */
PeerThreadContext g_peer_ctx[MAX_PEERS];

/* Контекст потока часов */
ClockThreadContext g_clock_ctx = {0};

/* Флаги работы потоков пэеров (atomic для signal safety) */
static atomic_bool g_peer_threads_running[MAX_PEERS];

/* Флаг работы потока часов (atomic для signal safety) */
static atomic_bool g_clock_thread_running = 0;

/* Массив дескрипторов потоков пэеров */
static pthread_t g_peer_threads[MAX_PEERS];

/**
 * Обработка входящего запроса от NTP-пэера
 *
 * @param buffer Буфер с данными запроса
 * @param size Размер буфера
 * @param ip IP-адрес клиента
 * @param port Порт клиента
 *
 * @return 0 на успех, < 0 на ошибку
 */
static int handle_peer_request(const void* buffer, size_t size, const char* ip,
                               const char* port, int peer_idx) {
    int ret = 0;

    if (peer_idx < 0 || peer_idx >= MAX_PEERS) {
        syslog(LOG_WARNING, "handle_peer_request: невалидный peer_idx=%d",
               peer_idx);
        return -1;
    }

    // Проверка размера пакета
    if (size < sizeof(NtpPacket)) {
        syslog(LOG_WARNING, "Пакет от %s:%s слишком мал (%zu байт)", ip, port,
               size);
        return -1;
    }

    // Парсинг входящего пакета
    NtpPacket pkt;
    memset(&pkt, 0, sizeof(pkt));

    if (!parse_ntp_packet(buffer, size, &pkt)) {
        syslog(LOG_WARNING, "Не удалось распарсить пакет от %s:%s", ip, port);
        return -1;
    }

    // Проверка режима (должен быть клиентом - MODE 3)
    if ((pkt.li_vn_mode & NTP_MODE_MASK) != NTP_MODE_CLIENT) {
        syslog(LOG_DEBUG, "Не клиентский режим от %s:%s (MODE=%u)", ip, port,
               pkt.li_vn_mode & NTP_MODE_MASK);
        return -1;
    }

    // Блокировка мьютекса (используем переданный peer_idx)
    pthread_mutex_lock(&g_peer_ctx[peer_idx].sock_mutex);

    if (atomic_load_explicit(&g_peer_ctx[peer_idx].sock_valid,
                             memory_order_acquire)) {
        // Отправка ответа
        NtpPacket response;
        memset(&response, 0, sizeof(response));

        // LI=0, VN=4, Mode=3 (client)
        response.li_vn_mode = (uint8_t)((0u << 6) | (NTP_VN_4 << 3) | 3u);
        response.stratum = g_local_stratum;
        response.precision = g_local_precision;
        response.poll = g_peer_poll;
        response.root_delay = g_local_root_delay;
        response.root_disp = g_local_root_disp;
        response.ref_id = g_local_ref_id;
        response.ref_ts = g_local_ref_ts;
        response.recv_ts = pkt.recv_ts;
        response.xmit_ts = pkt.xmit_ts;
        response.orig_ts = ntp_timestamp_now();

        ssize_t send_len =
            sendto(g_peer_ctx[peer_idx].sock_fd, &response, sizeof(response), 0,
                   (struct sockaddr*)&g_peer_ctx[peer_idx].client_addr_storage,
                   g_peer_ctx[peer_idx].client_addr_len);

        if (send_len < 0) {
            syslog(LOG_WARNING, "Ошибка отправки ответа %s:%s: %s", ip, port,
                   strerror(errno));
            ret = -1;
        } else {
            syslog(LOG_DEBUG, "Ответ отправлен %s:%s (%zd байт)", ip, port,
                   send_len);
        }
    }

    pthread_mutex_unlock(&g_peer_ctx[peer_idx].sock_mutex);

    return ret;
}

/**
 * Основной цикл потока обработки пэера
 *
 * @param arg Указатель на контекст потока
 *
 * @return void * (NULL) на успех
 */
/**
 * peer_thread_main - Main loop for peer thread (RFC 5905 Section 5)
 * @arg: Pointer to PeerThreadContext
 *
 * Handles incoming NTP requests from peers.
 * Uses atomic_bool for thread running flag (C11).
 * Releases resources via pthread_detach().
 *
 * Return: void * (NULL) on exit
 */
static void* peer_thread_main(void* arg) {
    PeerThreadContext* ctx = (PeerThreadContext*)arg;
    int idx = ctx->idx; // Получаем idx из контекста (исправлен баг)

    if (idx < 0 || idx >= MAX_PEERS) {
        syslog(LOG_ERR, "peer_thread_main: невалидный idx=%d", idx);
        return NULL;
    }

    syslog(LOG_INFO, "Поток обработки пэера запущен для %s:%s (idx=%d)",
           ctx->ip, ctx->port, idx);

    // Установка флагов (C11 memory barrier implicit in atomic_store)
    atomic_store_explicit(&g_peer_threads_running[idx], 1,
                          memory_order_release);

    // Защита g_peer_ctx мьютексом при инициализации
    pthread_mutex_lock(&g_peer_ctx[idx].sock_mutex);
    atomic_store_explicit(&g_peer_ctx[idx].sock_valid, 1, memory_order_release);
    g_peer_ctx[idx].sock_fd = ctx->sock_fd;
    g_peer_ctx[idx].peer_state = ctx->peer_state;
    pthread_mutex_unlock(&g_peer_ctx[idx].sock_mutex);

    // Основной цикл
    while (atomic_load_explicit(&g_peer_threads_running[idx],
                                memory_order_acquire)) {
        /* Блокировка на входящие запросы */
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));

        ssize_t recv_len =
            recvfrom(ctx->sock_fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                     (struct sockaddr*)&g_peer_ctx[idx].client_addr_storage,
                     &g_peer_ctx[idx].client_addr_len);

        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Нет данных - продолжаем цикл */
                continue;
            }
            syslog(LOG_WARNING, "Ошибка приёма от пэера %s:%s: %s", ctx->ip,
                   ctx->port, strerror(errno));
            break;
        }

        /* Обработка запроса */
        char client_ip[INET_ADDRSTRLEN];
        if (inet_ntop(
                AF_INET,
                &((struct sockaddr_in*)&g_peer_ctx[idx].client_addr_storage)
                     ->sin_addr,
                client_ip, sizeof(client_ip)) == NULL) {
            snprintf(client_ip, sizeof(client_ip), "%s", "unknown");
        }
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%hu",
                 (unsigned short)ntohs(
                     ((struct sockaddr_in*)&g_peer_ctx[idx].client_addr_storage)
                         ->sin_port));

        handle_peer_request(buffer, (size_t)recv_len, client_ip, port_str, idx);
    }

    // Очистка
    atomic_store_explicit(&g_peer_ctx[idx].sock_valid, 0, memory_order_release);
    atomic_store_explicit(&g_peer_threads_running[idx], 0,
                          memory_order_release);

    syslog(LOG_INFO, "Поток обработки пэера %s:%s завершён", ctx->ip,
           ctx->port);

    return NULL;
}

/**
 * Создание контекста потока пэера
 *
 * @param sock_fd Файловый дескриптор сокетa
 * @param ip IP-адрес пэера
 * @param port Порт пэера
 * @param peer_state Состояние пэера
 * @param idx Индекс в пуле пэеров
 *
 * @return 0 на успех, < 0 на ошибку
 */
static int peer_thread_init(int sock_fd, const char* ip, const char* port,
                            PeerState* peer_state, int idx) {
    // Инициализация контекста
    memset(&g_peer_ctx[idx], 0, sizeof(g_peer_ctx[idx]));
    snprintf(g_peer_ctx[idx].ip, sizeof(g_peer_ctx[idx].ip), "%s", ip);
    snprintf(g_peer_ctx[idx].port, sizeof(g_peer_ctx[idx].port), "%s", port);
    g_peer_ctx[idx].sock_fd = sock_fd;
    g_peer_ctx[idx].peer_state = peer_state;

    // Инициализация мьютекса
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE);

    if (pthread_mutex_init(&g_peer_ctx[idx].sock_mutex, &attr) != 0) {
        syslog(LOG_ERR, "Ошибка инициализации мьютекса пэера %d: %s", idx,
               strerror(errno));
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);
    return 0;
}

/**
 * Запуск потока обработки пэера
 *
 * @param sock_fd Файловый дескриптор сокетa
 * @param ip IP-адрес пэера
 * @param port Порт пэера
 * @param peer_state Состояние пэера
 * @param idx Индекс в пуле пэеров
 *
 * @return 0 на успех, < 0 на ошибку
 */
int start_peer_thread(int sock_fd, const char* ip, const char* port,
                      PeerState* peer_state, int idx) {
    pthread_t thread;

    // Проверка параметров
    if (sock_fd < 0 || ip == NULL || port == NULL || idx < 0 ||
        idx >= MAX_PEERS) {
        syslog(LOG_ERR,
               "start_peer_thread %d: NULL параметры или невалидный сокет/idx",
               idx);
        return -1;
    }

    // Инициализация контекста
    if (peer_thread_init(sock_fd, ip, port, peer_state, idx) != 0) {
        syslog(LOG_ERR, "Ошибка инициализации потока пэера %d", idx);
        return -1;
    }

    // Установка idx в контекст перед запуском потока (ОБЯЗАТЕЛЬНО)
    g_peer_ctx[idx].idx = idx;

    // Запуск потока
    if (pthread_create(&thread, NULL, peer_thread_main, &g_peer_ctx[idx]) !=
        0) {
        syslog(LOG_ERR, "Ошибка создания потока пэера %d: %s", idx,
               strerror(errno));
        return -1;
    }

    // pthread_detach для автоматической очистки ресурсов
    if (pthread_detach(thread) != 0) {
        syslog(LOG_ERR, "Ошибка pthread_detach потока пэера %d: %s", idx,
               strerror(errno));
        return -1;
    }

    // Сохранение дескриптора потока
    g_peer_threads[idx] = thread;

    // Установка флагов (C11 memory barrier для согласованн��сти видимости
    // данных)
    atomic_store_explicit(&g_peer_threads_running[idx], 1,
                          memory_order_release);

    // Защита sock_fd и peer_state мьютексом (не атомарные типы)
    pthread_mutex_lock(&g_peer_ctx[idx].sock_mutex);
    atomic_store_explicit(&g_peer_ctx[idx].sock_valid, 1, memory_order_release);
    g_peer_ctx[idx].sock_fd = sock_fd;
    g_peer_ctx[idx].peer_state = peer_state;
    pthread_mutex_unlock(&g_peer_ctx[idx].sock_mutex);

    syslog(LOG_INFO, "Поток пэера %d запущен для %s:%s", idx, ip, port);

    return 0;
}

/**
 * Остановка потока обработки пэера
 *
 * @param idx Индекс в пуле пэеров
 *
 * @return void
 */
void stop_peer_thread(void) {
    // Останавливаем все потоки пэеров
    for (int i = 0; i < g_peer_pool_count; i++) {
        if (atomic_load_explicit(&g_peer_threads_running[i],
                                 memory_order_acquire)) {
            // Сброс флагов - поток выйдет из цикла при проверке
            atomic_store_explicit(&g_peer_threads_running[i], 0,
                                  memory_order_release);

            // pthread_join для ожидания завершения
            int join_ret = pthread_join(g_peer_threads[i], NULL);
            if (join_ret != 0) {
                syslog(LOG_WARNING, "Ошибка pthread_join потока пэера %d: %s",
                       i, strerror(join_ret));
            }

            syslog(LOG_INFO, "Поток пэера %d остановлен", i);
        }
    }
}

/**
 * Очистка ресурсов потока пэера
 *
 * RFC 5905 Section 5: Каждый NTP-пэр обрабатывается в отдельном потоке
 * POSIX best practices: Очистка только после остановки потока
 */
void cleanup_peer_thread(void) {
    syslog(LOG_INFO, "Очистка ресурсов потоков пэеров");

    // Очистка всех потоков пэеров
    for (int i = 0; i < g_peer_pool_count; i++) {
        // Проверка, что поток остановлен (atomic для signal safety)
        if (atomic_load_explicit(&g_peer_threads_running[i],
                                 memory_order_acquire)) {
            syslog(LOG_ERR, "cleanup_peer_thread %d: поток ещё работает!", i);
            continue;
        }

        // Защита sock_fd мьютексом перед закрытием
        pthread_mutex_lock(&g_peer_ctx[i].sock_mutex);
        if (g_peer_ctx[i].sock_fd >= 0) {
            if (close(g_peer_ctx[i].sock_fd) != 0) {
                syslog(LOG_WARNING, "Ошибка close сокетa пэера %d: %s", i,
                       strerror(errno));
            }
            g_peer_ctx[i].sock_fd = -1;
        }
        pthread_mutex_unlock(&g_peer_ctx[i].sock_mutex);

        // Обработка ошибок pthread_mutex_destroy
        if (pthread_mutex_destroy(&g_peer_ctx[i].sock_mutex) != 0) {
            syslog(LOG_WARNING, "Ошибка pthread_mutex_destroy пэера %d: %s", i,
                   strerror(errno));
        }
    }
}

/* ============================================================================
 * Функции для потока обработки часов
 * ============================================================================
 */

/**
 * Обновление системных часов
 *
 * @param offset_us Коррекция в микросекундах
 * @param correction Тип коррекции (SLEW или STEP)
 */
static void update_system_clock(int64_t offset_us, int correction) {
    pthread_mutex_lock(&g_clock_ctx.clock_mutex);

    g_clock_ctx.last_offset_us = offset_us;
    g_clock_ctx.last_correction = correction;

    /* Уведомление о коррекции */
    if (correction == STEP) {
        syslog(LOG_INFO, "Коррекция часов: STEP %ld мкс", (long)offset_us);
    } else if (correction == SLEW) {
        syslog(LOG_INFO, "Коррекция часов: SLEW %ld мкс", (long)offset_us);
    }

    pthread_mutex_unlock(&g_clock_ctx.clock_mutex);
}

/**
 * Основной цикл потока обработки часов
 *
 * @param arg Указатель на контекст потока
 *
 * @return void * (NULL) на успех
 */
static void* clock_thread_main(void* arg) {
    ClockThreadContext* ctx = (ClockThreadContext*)arg;

    /* CERT C 3.4.5: Check g_server_count before using global data */
    if (atomic_load_explicit(&g_server_count, memory_order_acquire) == 0) {
        syslog(LOG_WARNING,
               "Clock thread started but no NTP servers configured.");
        syslog(LOG_WARNING, "Clock thread will not perform synchronization.");
        /* Выходим из цикла, если нет серверов */
        atomic_store_explicit(&g_clock_thread_running, 0, memory_order_release);
        return NULL;
    }

    syslog(LOG_INFO, "Поток обработки часов запущен (интервал %d мс)",
           ctx->interval_ms);

    /* Установка флагов (C11 memory barrier implicit in atomic_store) */
    atomic_store_explicit(&g_clock_thread_running, 1, memory_order_release);

    /* Основной цикл */
    struct timespec deadline;
    while (
        atomic_load_explicit(&g_clock_thread_running, memory_order_acquire)) {
        /* Получение текущего времени */
        struct timeval tv;
        if (gettimeofday(&tv, NULL) != 0) {
            syslog(LOG_WARNING, "Ошибка получения времени: %s",
                   strerror(errno));
            continue;
        }

        /* Вычисление коррекции */
        int64_t now_ns = (int64_t)tv.tv_sec * 1000000000LL + tv.tv_usec * 1000;

        /* Защита g_last_sync_ts мьютексом (RFC 5905 Section 5.2) */
        pthread_mutex_lock(&g_mutex);
        int64_t expected_ns = (int64_t)g_last_sync_ts.sec * 1000000000LL +
                              g_last_sync_ts.frac * 1000;
        pthread_mutex_unlock(&g_mutex);

        int64_t offset_ns = now_ns - expected_ns;
        int64_t offset_us = offset_ns / 1000;

        /* Применение коррекции */
        int correction = apply_time_correction_slew_or_step(offset_us);
        update_system_clock(offset_us, correction);

        /* Установка таймера - используем абсолютное время */
        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
            syslog(LOG_WARNING, "Ошибка получения времени: %s",
                   strerror(errno));
            sleep((unsigned int)(ctx->interval_ms / 1000));
            continue;
        }
        deadline.tv_sec += ctx->interval_ms / 1000;
        deadline.tv_nsec += (ctx->interval_ms % 1000) * 1000000;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }

        pthread_mutex_lock(&g_clock_ctx.clock_mutex);
        int rc = pthread_cond_timedwait(&g_clock_ctx.clock_cond,
                                        &g_clock_ctx.clock_mutex, &deadline);
        pthread_mutex_unlock(&g_clock_ctx.clock_mutex);

        if (rc == ETIMEDOUT) {
            /* Таймер истёк - продолжаем цикл */
            continue;
        } else if (rc == EINTR) {
            /* Прерывание - проверяем флаг */
            if (!atomic_load_explicit(&g_clock_thread_running,
                                      memory_order_acquire)) {
                break;
            }
            continue;
        } else {
            /* Уведомление - пробуждаем поток */
            break;
        }
    }

    syslog(LOG_INFO, "Поток обработки часов завершён");

    return NULL;
}

/**
 * Создание контекста потока часов
 *
 * @param interval_ms Интервал обновления в мс
 *
 * @return 0 на успех, < 0 на ошибку
 */
static int clock_thread_init(int interval_ms) {
    int ret = 0;

    /* Инициализация контекста */
    memset(&g_clock_ctx, 0, sizeof(g_clock_ctx));
    g_clock_ctx.interval_ms = interval_ms;

    /* Инициализация мьютекса */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_PRIVATE);

    if (pthread_mutex_init(&g_clock_ctx.clock_mutex, &attr) != 0) {
        syslog(LOG_ERR, "Ошибка инициализации мьютекса часов: %s",
               strerror(errno));
        ret = -1;
        goto cleanup_attr;
    }

    /* Инициализация условия */
    if (pthread_cond_init(&g_clock_ctx.clock_cond, NULL) != 0) {
        syslog(LOG_ERR, "Ошибка инициализации условия часов: %s",
               strerror(errno));
        ret = -1;
        goto cleanup_mutex;
    }

cleanup_mutex:
    pthread_mutex_destroy(&g_clock_ctx.clock_mutex);
    pthread_cond_destroy(&g_clock_ctx.clock_cond);
cleanup_attr:
    pthread_mutexattr_destroy(&attr);

    return ret;
}

/**
 * Запуск потока обработки часов
 *
 * @param interval_ms Интервал обновления в мс
 *
 * @return 0 на успех, < 0 на ошибку
 */
int start_clock_thread(int interval_ms) {
    int ret = 0;
    pthread_t thread;

    /* Инициализация контекста */
    if (clock_thread_init(interval_ms) != 0) {
        syslog(LOG_ERR, "Ошибка инициализации потока часов");
        ret = -1;
        goto cleanup;
    }

    /* Запуск потока */
    if (pthread_create(&thread, NULL, clock_thread_main, &g_clock_ctx) != 0) {
        syslog(LOG_ERR, "Ошибка создания потока часов: %s", strerror(errno));
        ret = -1;
        goto cleanup;
    }

    /* ✅ ПРАКТИКА 1: pthread_detach для автоматической очистки ресурсов */
    if (pthread_detach(thread) != 0) {
        syslog(LOG_ERR, "Ошибка pthread_detach потока часов: %s",
               strerror(errno));
        ret = -1;
        goto cleanup;
    }

    /* Сохранение дескриптора потока */
    g_clock_ctx.thread_id = thread;

    syslog(LOG_INFO, "Поток часов запущен (интервал %d мс)", interval_ms);

cleanup:
    return ret;
}

/**
 * Остановка потока обработки часов
 *
 * @return void
 */
void stop_clock_thread(void) {
    int join_ret = 0;

    if (!atomic_load_explicit(&g_clock_thread_running, memory_order_acquire)) {
        return;
    }

    /* Сброс флагов */
    atomic_store_explicit(&g_clock_thread_running, 0, memory_order_release);

    /* Пробуждение потока */
    pthread_mutex_lock(&g_clock_ctx.clock_mutex);
    pthread_cond_signal(&g_clock_ctx.clock_cond);
    pthread_mutex_unlock(&g_clock_ctx.clock_mutex);

    /* ✅ ПРАКТИКА 4: Обработка ошибок pthread_join */
    join_ret = pthread_join(g_clock_ctx.thread_id, NULL);
    if (join_ret != 0) {
        syslog(LOG_WARNING, "Ошибка pthread_join потока часов: %s",
               strerror(join_ret));
    }

    /* Барьер памяти для согласованности видимости данных (C11 memory model) */
    atomic_thread_fence(memory_order_acquire);

    syslog(LOG_INFO, "Поток часов остановлен");
}

/**
 * Уведомление потока часов об изменении
 *
 * @return 0 на успех, < 0 на ошибку
 */
int clock_thread_notify(void) {
    int ret = 0;

    pthread_mutex_lock(&g_clock_ctx.clock_mutex);
    pthread_cond_signal(&g_clock_ctx.clock_cond);
    pthread_mutex_unlock(&g_clock_ctx.clock_mutex);

    return ret;
}

/**
 * Получение последнего значения коррекции
 *
 * @return Последнее значение коррекции в мкс
 */
int64_t clock_thread_get_last_offset(void) {
    pthread_mutex_lock(&g_clock_ctx.clock_mutex);
    int64_t offset = g_clock_ctx.last_offset_us;
    pthread_mutex_unlock(&g_clock_ctx.clock_mutex);

    return offset;
}

/**
 * Получение последней коррекции
 *
 * @return Последняя коррекция (SLEW или STEP)
 */
int clock_thread_get_last_correction(void) {
    pthread_mutex_lock(&g_clock_ctx.clock_mutex);
    int correction = g_clock_ctx.last_correction;
    pthread_mutex_unlock(&g_clock_ctx.clock_mutex);

    return correction;
}

/**
 * Очистка ресурсов потока часов
 */
void cleanup_clock_thread(void) {
    syslog(LOG_INFO, "Очистка ресурсов потока часов");

    /* Обработка ошибок pthread_mutex_destroy и pthread_cond_destroy */
    if (pthread_mutex_destroy(&g_clock_ctx.clock_mutex) != 0) {
        syslog(LOG_WARNING, "Ошибка pthread_mutex_destroy часов: %s",
               strerror(errno));
    }
    if (pthread_cond_destroy(&g_clock_ctx.clock_cond) != 0) {
        syslog(LOG_WARNING, "Ошибка pthread_cond_destroy часов: %s",
               strerror(errno));
    }
}
