/*
 * ntpd.c - Реализация сервера NTP (Network Time Protocol)
 *
 * Реализация включает:
 * - Парсинг NTP-пакетов (48 байт)
 * - Вычисление задержки (round-trip delay) и дисперсии
 * - Алгоритм Маркса для фильтрации выбросов
 * - Поддержка стратификации
 * - Кэширование и интерполяция времени
 * - Обработка мультикаста
 * - Обработка Leap Indicator
 * - Поддержка 64-битного времени
 * - Обработка ошибок парсинга
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <sys/time.h>

/* ============================================================================
 * ФУНКЦИОНАЛЬНЫЕ ОБЪЯВЛЕНИЯ
 * ============================================================================ */

static int create_udp_socket(int port);
static void close_socket(int sock);
static void handle_client_request(const void *buffer, size_t size,
                           const char *ip, const char *port);
static int load_server_config(void);
static int sync_ntp_time(const char *ip, const char *port);

/* ============================================================================
 * КОНСТАНТЫ И КОНФИГУРАЦИЯ
 * ============================================================================ */

#define CONFIG_DIR "/etc/time_sync"
#define CONFIG_FILE CONFIG_DIR "/servers.conf"
#define NTP_PORT 123
#define BUFFER_SIZE 1024
#define SYNC_INTERVAL_SECONDS 30
#define MAX_SERVERS 64
#define MAX_SAMPLES 64
#define MARX_K 3  /* Коэффициент для алгоритма Маркса */

/* ============================================================================
 * СТРУКТУРА NTP-ПАКЕТА (NTPv4)
 * ============================================================================ */

/* RFC 5905 (NTPv4): LI(2) | VN(3) | Mode(3) */
#define NTP_LI_MASK   0xC0
#define NTP_VN_MASK   0x38
#define NTP_MODE_MASK 0x07
#define NTP_VN_SHIFT  3
#define NTP_LI_SHIFT  6

#define NTP_VN_4 4

/* NTP timestamp: 32-bit seconds + 32-bit fraction (RFC5905) */
typedef struct {
    uint32_t sec;
    uint32_t frac;
} NtpTimestamp;

/* RFC 5905 wire header (48 bytes, big-endian on the wire) */
typedef struct {
    uint8_t  li_vn_mode; /* LI|VN|Mode */
    uint8_t  stratum;
    int8_t   poll;
    int8_t   precision;
    uint32_t root_delay; /* 16.16 signed, network order on the wire */
    uint32_t root_disp;  /* 16.16 unsigned, network order on the wire */
    uint32_t ref_id;
    NtpTimestamp ref_ts;
    NtpTimestamp orig_ts;
    NtpTimestamp recv_ts;
    NtpTimestamp xmit_ts;
} NtpPacket;

/* ============================================================================
 * УТИЛИТЫ ДЛЯ РАБОТЫ С ВРЕМЕНЕМ
 * ============================================================================ */

#define NTP_UNIX_EPOCH_DELTA 2208988800UL /* seconds between 1900-01-01 and 1970-01-01 */

static uint32_t read_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static NtpTimestamp ntp_timestamp_from_timespec(const struct timespec *ts) {
    NtpTimestamp t = {0, 0};
    if (ts == NULL) return t;

    /* seconds since 1900 */
    uint64_t sec = (uint64_t)ts->tv_sec + (uint64_t)NTP_UNIX_EPOCH_DELTA;
    if (sec > UINT32_MAX) {
        t.sec = UINT32_MAX;
        t.frac = UINT32_MAX;
        return t;
    }
    t.sec = (uint32_t)sec;

    /* fraction = floor(nsec * 2^32 / 1e9) */
    uint64_t frac = ((uint64_t)ts->tv_nsec << 32) / 1000000000ULL;
    t.frac = (uint32_t)frac;
    return t;
}

static int64_t ntp_timestamp_to_ns(const NtpTimestamp *t) {
    if (t == NULL) return 0;
    int64_t sec = (int64_t)t->sec - (int64_t)NTP_UNIX_EPOCH_DELTA;
    int64_t nsec = (int64_t)(((uint64_t)t->frac * 1000000000ULL) >> 32);
    return sec * 1000000000LL + nsec;
}

static NtpTimestamp ntp_timestamp_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        syslog(LOG_ERR, "Ошибка получения времени: %s", strerror(errno));
        NtpTimestamp z = {0, 0};
        return z;
    }
    return ntp_timestamp_from_timespec(&ts);
}

/* ============================================================================
 * ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
 * ============================================================================ */

/* Конфигурация серверов */
typedef struct {
    char *ip;
    char *port;
    time_t next_allowed_sync;
} ServerConfig;

ServerConfig *g_servers = NULL;
int g_server_count = 0;

/* Кэш образцов для алгоритма Маркса */
typedef struct {
    uint64_t ts;
    uint64_t delay;
    int64_t offset;  /* offset вместо disp для соответствия RFC 5905 */
} NtpSample;

NtpSample g_samples[MAX_SAMPLES];
int g_sample_count = 0;

/* Mutex для thread-safe доступа к глобальным данным */
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * RFC 5905: состояние локального сервера
 * ============================================================================ */

static bool g_time_synced = false;
static uint8_t g_local_stratum = 16; /* 16 = unsynchronized */
static uint32_t g_local_ref_id = 0x4C4F434CUL; /* "LOCL" */
static NtpTimestamp g_local_ref_ts = {0, 0};
static uint32_t g_local_root_delay = 0; /* 16.16 */
static uint32_t g_local_root_disp = 0;  /* 16.16 */
static uint8_t g_local_li = 3;          /* 3 = alarm when unsynced */
static time_t g_last_dispersion_update = 0; /* last time dispersion was updated */

#define PHI 15  /* maximum drift rate in ppm (RFC 5905 default) */

static int8_t g_local_precision = -20;  /* system precision (log2 seconds), initialized at startup */
static int8_t g_local_poll = 4;           /* poll exponent (log2 seconds), default 16 sec */
static int8_t g_peer_poll = 4;           /* last received poll from peer */

#define MAX_PEERS 8

typedef struct {
    char ip[64];
    char port[16];
    uint8_t stratum;
    uint64_t delay_us;
    int64_t offset_us;
    uint64_t jitter_us;
    uint32_t root_disp;
    time_t last_update;
    bool reachable;
} PeerState;

static PeerState g_peers[MAX_PEERS];
static int g_peer_count = 0;
static int g_selected_peer = -1;

static uint8_t compute_system_offset(int8_t *offsets, int count, int *best_idx) {
    if (count < 2 || best_idx == NULL) {
        if (best_idx) *best_idx = 0;
        return count > 0 ? 0 : 16;
    }
    
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (offsets[j] > offsets[j + 1]) {
                int8_t tmp = offsets[j];
                offsets[j] = offsets[j + 1];
                offsets[j + 1] = tmp;
            }
        }
    }
    
    int8_t median = offsets[count / 2];
    int8_t total = 0;
    int used = 0;
    for (int i = 0; i < count; i++) {
        int8_t diff = offsets[i] - median;
        if (diff < 0) diff = -diff;
        if (diff < 500) {
            total += offsets[i];
            used++;
        }
    }
    
    if (used > 0) {
        *best_idx = 0;
        return total / used;
    }
    
    *best_idx = 0;
    return median;
}

/* Forward declaration */
static uint32_t ntp_u16_16_from_us(uint64_t us);

static uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us) {
    time_t now = time(NULL);
    if (g_last_dispersion_update == 0) {
        g_last_dispersion_update = now;
        return current_disp;
    }
    
    double elapsed = (double)(now - g_last_dispersion_update);
    if (elapsed < 0) elapsed = 0;
    
    double phi_dispersion = (PHI * elapsed) / 1000000.0;
    uint64_t disp_us = (offset_us >= 0) ? (uint64_t)offset_us : (uint64_t)(-offset_us);
    
    double new_disp = phi_dispersion + (double)disp_us + (double)jitter_us;
    if (new_disp > (double)UINT32_MAX) new_disp = (double)UINT32_MAX;
    
    g_last_dispersion_update = now;
    return ntp_u16_16_from_us((uint64_t)new_disp);
}

static int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us) {
    int8_t new_poll = current_poll;
    
    if (peer_poll < current_poll) {
        new_poll = peer_poll;
    }
    
    if (delay_us > 100000 || offset_us > 50000 || offset_us < -50000) {
        if (new_poll < 12) new_poll++;
    } else if (delay_us < 10000 && offset_us > -10000 && offset_us < 10000) {
        if (new_poll > 4) new_poll--;
    }
    
    return new_poll;
}

static int8_t get_system_precision(void) {
    struct timespec ts;
    if (clock_getres(CLOCK_REALTIME, &ts) == 0) {
        if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
            return -20;
        }
        if (ts.tv_sec > 0) {
            int8_t p = 0;
            time_t s = ts.tv_sec;
            while (s > 0) { p++; s >>= 1; }
            return (p > 6) ? 6 : -p;
        }
        int64_t ns = (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
        if (ns <= 0) return -20;
        int8_t p = 0;
        while (ns < 1000000000LL) { p--; ns <<= 1; }
        return p;
    }
    return -20;
}

static uint32_t ntp_u16_16_from_us(uint64_t us) {
    /* floor(us * 2^16 / 1e6) */
    if (us > (UINT64_MAX / 65536ULL)) return UINT32_MAX;
    uint64_t v = (us * 65536ULL) / 1000000ULL;
    return (v > UINT32_MAX) ? UINT32_MAX : (uint32_t)v;
}

static uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum) {
    if (peer_stratum == 0 || peer_stratum > 15) return 16;
    uint16_t s = (uint16_t)peer_stratum + 1u;
    if (s > 15u) return 15u;
    return (uint8_t)s;
}

static bool ntp_is_kod(const NtpPacket *pkt) {
    if (pkt == NULL) return false;
    return pkt->stratum == 0 && pkt->ref_ts.sec == 0 && pkt->ref_ts.frac == 0;
}

static uint64_t ntp_offset_jitter_us_locked(void) {
    if (g_sample_count <= 1) return 0;

    long double mean = 0.0L;
    for (int i = 0; i < g_sample_count; i++) {
        mean += (long double)g_samples[i].offset;
    }
    mean /= (long double)g_sample_count;

    long double var = 0.0L;
    for (int i = 0; i < g_sample_count; i++) {
        long double d = (long double)g_samples[i].offset - mean;
        var += d * d;
    }
    var /= (long double)(g_sample_count - 1);
    if (var < 0.0L) var = 0.0L;
    long double sd = sqrtl(var);
    if (sd < 0.0L) sd = 0.0L;
    if (sd > (long double)UINT64_MAX) return UINT64_MAX;
    return (uint64_t)sd;
}

static int apply_time_correction_slew_or_step(int64_t offset_us) {
    /* RFC 5905: Step for huge offsets (>0.5s), slew for small ones */
    const int64_t step_threshold_us = 500000; /* 500 ms (RFC 5905 default) */

    if (offset_us > step_threshold_us || offset_us < -step_threshold_us) {
        struct timespec now_ts;
        if (clock_gettime(CLOCK_REALTIME, &now_ts) != 0) return -1;
        int64_t ns = (int64_t)now_ts.tv_sec * 1000000000LL + (int64_t)now_ts.tv_nsec;
        ns += offset_us * 1000LL;
        struct timespec new_ts;
        new_ts.tv_sec = (time_t)(ns / 1000000000LL);
        new_ts.tv_nsec = (long)(ns % 1000000000LL);
        if (new_ts.tv_nsec < 0) {
            new_ts.tv_nsec += 1000000000L;
            new_ts.tv_sec -= 1;
        }
        return clock_settime(CLOCK_REALTIME, &new_ts);
    }

    struct timeval delta;
    delta.tv_sec = (time_t)(offset_us / 1000000LL);
    delta.tv_usec = (suseconds_t)(offset_us % 1000000LL);
    if (delta.tv_usec < 0) {
        delta.tv_usec += 1000000;
        delta.tv_sec -= 1;
    }
    return adjtime(&delta, NULL);
}

/* ============================================================================
 * ПАРСИНГ NTP-ПАКЕТА
 * ============================================================================ */

/**
 * @brief Парсит NTP-пакет из буфера
 *
 * @param buffer Буфер с сырыми данными пакета
 * @param size   Размер буфера
 * @param pkt    Структура для хранения распарсенного пакета
 * @return true при успехе, false при ошибке
 */
static bool parse_ntp_packet(const void *buffer, size_t size, NtpPacket *pkt) {
    if (buffer == NULL || pkt == NULL) {
        syslog(LOG_WARNING, "NULL указатель при парсинге пакета");
        return false;
    }

    if (size < 48) {
        syslog(LOG_WARNING, "Пакет слишком мал: %zu байт (минимум 48)", size);
        return false;
    }

    const uint8_t *data = (const uint8_t *)buffer;

    pkt->li_vn_mode = data[0];
    pkt->stratum = data[1];
    pkt->poll = (int8_t)data[2];
    pkt->precision = (int8_t)data[3];
    pkt->root_delay = read_u32be(&data[4]);
    pkt->root_disp = read_u32be(&data[8]);
    pkt->ref_id = read_u32be(&data[12]);

    pkt->ref_ts.sec = read_u32be(&data[16]);
    pkt->ref_ts.frac = read_u32be(&data[20]);
    pkt->orig_ts.sec = read_u32be(&data[24]);
    pkt->orig_ts.frac = read_u32be(&data[28]);
    pkt->recv_ts.sec = read_u32be(&data[32]);
    pkt->recv_ts.frac = read_u32be(&data[36]);
    pkt->xmit_ts.sec = read_u32be(&data[40]);
    pkt->xmit_ts.frac = read_u32be(&data[44]);

    uint8_t li = (uint8_t)((pkt->li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    uint8_t vn = (uint8_t)((pkt->li_vn_mode & NTP_VN_MASK) >> NTP_VN_SHIFT);
    uint8_t mode = (uint8_t)(pkt->li_vn_mode & NTP_MODE_MASK);

    if (vn != NTP_VN_4) {
        syslog(LOG_WARNING, "Неверная версия NTP: %u (ожидалось 4)", vn);
        return false;
    }

    if (mode == 0 || mode > 7) {
        syslog(LOG_WARNING, "Неверный mode NTP: %u", mode);
        return false;
    }

    if (li > 3) {
        syslog(LOG_WARNING, "Неверный Leap Indicator: %u", li);
        return false;
    }

    if (pkt->stratum > 16) {
        syslog(LOG_WARNING, "Страта превышает допустимое значение: %u", pkt->stratum);
        return false;
    }

    return true;
}

/**
 * @brief Создаёт NTP-запрос (RFC 5905)
 *
 * @param buffer Буфер для запроса (48 байт)
 * @param xmit_out (опционально) transmit timestamp (T1)
 */
static void create_ntp_request(void *buffer, NtpTimestamp *xmit_out) {
    if (buffer == NULL) {
        syslog(LOG_WARNING, "NULL указатель при создании запроса");
        return;
    }

    uint8_t *p = (uint8_t *)buffer;
    memset(p, 0, 48);

    /* LI=0, VN=4, Mode=3 (client) */
    p[0] = (uint8_t)((0u << NTP_LI_SHIFT) | ((uint8_t)NTP_VN_4 << NTP_VN_SHIFT) | 3u);
    p[1] = 0;              /* stratum */
    p[2] = g_local_poll;                  /* poll (dynamic) */
    p[3] = (uint8_t)g_local_precision; /* precision (вычисляется при старте) */

    /* Transmit timestamp (T1) */
    NtpTimestamp t1 = ntp_timestamp_now();
    write_u32be(&p[40], t1.sec);
    write_u32be(&p[44], t1.frac);
    if (xmit_out != NULL) {
        *xmit_out = t1;
    }
}

/* ============================================================================
 * ОБРАБОТКА LEAP INDICATOR
 * ============================================================================ */

/**
 * @brief Обрабатывает Leap Indicator
 *
 * @param li Leap Indicator (0-3)
 * @return true если Leap Indicator указывает на проблему
 */
static bool handle_leap_indicator(uint8_t li) {
    switch (li) {
        case 0:  /* No warning (00) */
            syslog(LOG_INFO, "Leap Indicator: No warning");
            return false;

        case 1:  /* Last minute 61-62 seconds OK (01) */
            syslog(LOG_INFO, "Leap Indicator: Last minute 61-62 seconds OK");
            return false;

        case 2:  /* Last minute 61-62 seconds NOT OK (10) */
            syslog(LOG_WARNING, "Leap Indicator: Last minute 61-62 seconds NOT OK");
            return true;

        case 3:  /* Last minute not OK (11) */
            syslog(LOG_WARNING, "Leap Indicator: Last minute not OK - possible clock jump");
            return true;

        default:
            syslog(LOG_ERR, "Invalid Leap Indicator: %d", li);
            return true;
    }
}

/* ============================================================================
 * ВЫЧИСЛЕНИЕ ЗАДЕРЖКИ И ДИСПЕРСИИ
 * ============================================================================ */

/**
 * @brief Вычисляет задержку (round-trip delay) и дисперсию (RFC 5905)
 *
 * Формула: delay = (T4 - T1) - (T3 - T2)
 *         offset = ½[(T2 - T1) + (T3 - T4)]
 * где: T1 = client transmit, T2 = server receive, T3 = server transmit, T4 = client receive
 *
 * @param pkt    NTP-пакет
 * @param delay  Выходная задержка (в микросекундах)
 * @param offset Выходное смещение (в микросекундах)
 * @return true при успехе, false при ошибке
 */
static bool calculate_delay_offset(const NtpTimestamp *t1,
                                  const NtpTimestamp *t2,
                                  const NtpTimestamp *t3,
                                  const NtpTimestamp *t4,
                                  uint64_t *delay_us,
                                  int64_t *offset_us) {
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL || delay_us == NULL || offset_us == NULL) {
        syslog(LOG_WARNING, "NULL указатель при вычислении задержки");
        return false;
    }

    int64_t T1 = ntp_timestamp_to_ns(t1);
    int64_t T2 = ntp_timestamp_to_ns(t2);
    int64_t T3 = ntp_timestamp_to_ns(t3);
    int64_t T4 = ntp_timestamp_to_ns(t4);

    /* delay = (T4 - T1) - (T3 - T2) */
    int64_t delay_ns = (T4 - T1) - (T3 - T2);
    /* offset = 1/2 * [(T2 - T1) + (T3 - T4)] */
    int64_t offset_ns = ((T2 - T1) + (T3 - T4)) / 2;

    if (delay_ns < 0) {
        syslog(LOG_WARNING, "Отрицательная задержка (ns): %" PRId64, delay_ns);
        return false;
    }

    *delay_us = (uint64_t)(delay_ns / 1000);
    *offset_us = offset_ns / 1000;
    return true;
}

/* ============================================================================
 * АЛГОРИТМ МАРКСА ДЛЯ ФИЛЬТРАЦИИ ВЫБРОСОВ
 * ============================================================================ */

/**
 * @brief Добавляет образец в кэш
 */
static void marx_add_sample_us(uint64_t ts_ns, uint64_t delay_us, int64_t offset_us) {
    if (g_sample_count >= MAX_SAMPLES) return;

    pthread_mutex_lock(&g_mutex);
    g_samples[g_sample_count].ts = ts_ns;
    g_samples[g_sample_count].delay = delay_us;
    g_samples[g_sample_count].offset = offset_us;
    g_sample_count++;
    pthread_mutex_unlock(&g_mutex);
}

/**
 * @brief Удаляет образец из кэша
 */
void marx_remove_sample(int index) {
    if (index >= 0 && index < g_sample_count) {
        /* Защита доступа к g_samples с помощью mutex */
        pthread_mutex_lock(&g_mutex);
        const size_t move_count = (size_t)(g_sample_count - index - 1);
        memmove(&g_samples[index], &g_samples[index + 1],
                move_count * sizeof(NtpSample));
        g_sample_count--;
        pthread_mutex_unlock(&g_mutex);
    }
}

/**
 * @brief Вычисляет медиану массива
 */
uint64_t marx_median(uint64_t *arr, int count) {
    if (count == 0) return 0;

    /* Сортируем пузырьком (для простоты) */
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                uint64_t tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }

    /* Возвращаем медиану */
    return (count % 2 == 0) ? arr[count / 2 - 1] : arr[count / 2];
}

/**
 * @brief Фильтрует выбросы с помощью алгоритма Маркса (Marx Filter)
 *
 * Алгоритм:
 * 1. Сортировать образцы по задержке
 * 2. Вычислить медиану задержек
 * 3. Вычислить MAD (Median Absolute Deviation) - медиану абсолютных отклонений
 * 4. Отбрасывать образцы, где |x - median| > k * MAD
 *
 * @param samples  Массив образцов
 * @param count    Количество образцов
 * @param k        Коэффициент фильтрации (по умолчанию 3)
 * @return true если выбросы были отфильтрованы
 */
int marx_filter_outliers(NtpSample *samples, int count, int k) {
    if (count < 3) return count;
    if (count > MAX_SAMPLES) count = MAX_SAMPLES;

    const int original_count = count;

    /* Собираем задержки в отдельный массив для медианы/MAD */
    uint64_t delays[MAX_SAMPLES];
    for (int i = 0; i < count; i++) {
        delays[i] = samples[i].delay;
    }

    uint64_t median = marx_median(delays, count);

    uint64_t abs_devs[MAX_SAMPLES];
    for (int i = 0; i < count; i++) {
        abs_devs[i] = (samples[i].delay > median) ?
                      (samples[i].delay - median) : (median - samples[i].delay);
    }
    uint64_t mad = marx_median(abs_devs, count);

    /* Порог: медиана + k * MAD (saturating multiply to avoid overflow) */
    uint64_t kmad;
    if (mad != 0 && (uint64_t)k > (UINT64_MAX / mad)) {
        kmad = UINT64_MAX;
    } else {
        kmad = (uint64_t)k * mad;
    }

    uint64_t threshold = (UINT64_MAX - median < kmad) ? UINT64_MAX : (median + kmad);

    int filtered = 0;
    for (int i = 0; i < count; i++) {
        if (samples[i].delay <= threshold) {
            if (filtered != i) {
                samples[filtered] = samples[i];
            }
            filtered++;
        }
    }

    return (filtered < original_count) ? filtered : original_count;
}

/* ============================================================================
 * СТРАТИФИКАЦИЯ
 * ============================================================================ */

/* RFC 5905: local stratum = min(15, peer_stratum + 1), 16 = unsynchronized */

/* ============================================================================
 * КАЧЕСТВО СЕТИ
 * ============================================================================ */

/**
 * @brief Вычисляет качество сети на основе задержек
 *
 * @param delay Задержка (в микросекундах)
 * @return Качество сети (0-100)
 */
static uint8_t calculate_network_quality(uint64_t delay) {
    /* Качество ухудшается с увеличением задержки */
    int64_t quality = 100 - (int64_t)(delay / 1000);  /* 1000 мкс = 1 мс */
    if (quality < 0) return 0;
    if (quality > 100) return 100;
    return (uint8_t)quality;
}

/* ============================================================================
 * ОБРАБОТКА ЗАПРОСА ОТ КЛИЕНТА
 * ============================================================================ */

/**
 * @brief Обрабатывает входящий запрос от клиента (NTP Server mode)
 *
 * Логика NTP сервера (RFC 5905):
 * 1. Получаем запрос от клиента (с Originate Timestamp)
 * 2. Записываем Receive Timestamp (T2)
 * 3. Формируем ответ с Transmit Timestamp (T3)
 * 4. Клиент вычисляет delay/dispersion
 *
 * @param buffer Буфер с запросом
 * @param size   Размер буфера
 * @param ip     IP-адрес клиента
 * @param port   Порт клиента
 */
static void handle_client_request(const void *buffer, size_t size,
                           const char *ip, const char *port) {
    if (buffer == NULL || ip == NULL || port == NULL) {
        syslog(LOG_WARNING, "NULL указатель при обработке запроса клиента");
        return;
    }

    if (size < 48) {
        syslog(LOG_WARNING, "Запрос клиента слишком мал: %zu байт", size);
        return;
    }

    /* Парсим входящий запрос */
    NtpPacket pkt;
    if (!parse_ntp_packet(buffer, size, &pkt)) {
        syslog(LOG_WARNING, "Ошибка парсинга запроса клиента");
        return;
    }

    uint8_t li = (uint8_t)((pkt.li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    uint8_t mode = (uint8_t)(pkt.li_vn_mode & NTP_MODE_MASK);

    if (mode != 3) {
        syslog(LOG_WARNING, "Не client mode пакет (mode=%u) от %s:%s", mode, ip, port);
        return;
    }

    /* Обработка Leap Indicator */
    if (handle_leap_indicator(li)) {
        syslog(LOG_WARNING, "Пропускаем обработку из-за Leap Indicator");
        return;
    }

    /* T2 (receive timestamp) */
    NtpTimestamp t2 = ntp_timestamp_now();

    /* stratum считается из состояния синхронизации */

    uint8_t response[48];
    memset(response, 0, sizeof(response));

    bool synced;
    uint8_t out_stratum;
    uint32_t out_ref_id;
    NtpTimestamp out_ref_ts;
    uint32_t out_root_delay;
    uint32_t out_root_disp;
    uint8_t out_li_state;
    pthread_mutex_lock(&g_mutex);
    synced = g_time_synced;
    out_stratum = g_local_stratum;
    out_ref_id = g_local_ref_id;
    out_ref_ts = g_local_ref_ts;
    out_root_delay = g_local_root_delay;
    out_root_disp = g_local_root_disp;
    out_li_state = g_local_li;
    pthread_mutex_unlock(&g_mutex);

    /* RFC5905: если не синхронизированы, LI=3 (alarm), stratum=16 */
    uint8_t out_li = synced ? out_li_state : 3u;
    if (!synced) {
        out_stratum = 16u;
        out_ref_id = 0x4C4F434CUL; /* "LOCL" */
        out_ref_ts.sec = 0;
        out_ref_ts.frac = 0;
        out_root_delay = 0;
        out_root_disp = 0;
    }

    /* LI = out_li, VN=4, Mode=4 (server) */
    response[0] = (uint8_t)((uint8_t)((out_li & 0x03u) << NTP_LI_SHIFT) |
                            (uint8_t)((uint8_t)NTP_VN_4 << NTP_VN_SHIFT) |
                            (uint8_t)4u);

    response[1] = out_stratum;
    response[2] = (uint8_t)pkt.poll;         /* echo client poll */
    response[3] = (uint8_t)g_local_precision; /* local precision */

    write_u32be(&response[4], out_root_delay);
    write_u32be(&response[8], out_root_disp);
    write_u32be(&response[12], out_ref_id);

    write_u32be(&response[16], out_ref_ts.sec);
    write_u32be(&response[20], out_ref_ts.frac);

    /* orig_ts: client's transmit timestamp (T1) */
    write_u32be(&response[24], pkt.xmit_ts.sec);
    write_u32be(&response[28], pkt.xmit_ts.frac);

    /* recv_ts: T2 */
    write_u32be(&response[32], t2.sec);
    write_u32be(&response[36], t2.frac);

    /* xmit_ts: T3 */
    NtpTimestamp t3 = ntp_timestamp_now();
    write_u32be(&response[40], t3.sec);
    write_u32be(&response[44], t3.frac);

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    char *endp = NULL;
    unsigned long port_ul = strtoul(port, &endp, 10);
    if (endp == port || *endp != '\0' || port_ul > 65535UL) {
        syslog(LOG_WARNING, "Неверный порт клиента: %s", port);
        return;
    }
    client_addr.sin_port = htons((uint16_t)port_ul);
    if (inet_pton(AF_INET, ip, &client_addr.sin_addr) <= 0) {
        syslog(LOG_WARNING, "Неверный IP клиента: %s", ip);
        return;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка создания сокета: %s", strerror(errno));
        return;
    }

    /* Отправляем ответ */
    if (sendto(sock, response, sizeof(response), 0,
                (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        syslog(LOG_WARNING, "Ошибка отправки ответа клиенту: %s",
                strerror(errno));
        close_socket(sock);
        return;
    }

    close_socket(sock);
}

/* ============================================================================
 * СОЗДАНИЕ И НАСТРОЙКА СОКЕТА
 * ============================================================================ */

/**
 * @brief Создаёт и привязывает UDP-сокет к порту
 *
 * @param port Порт для привязки
 * @return Файловый дескриптор сокета (< 0 при ошибке)
 */
static int create_udp_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка создания сокета: %s", strerror(errno));
        return -1;
    }

    if (port <= 0 || port > 65535) {
        syslog(LOG_ERR, "Неверный порт для bind: %d", port);
        close_socket(sock);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Ошибка привязки сокета: %s", strerror(errno));
        close_socket(sock);
        return -1;
    }

    return sock;
}

/**
 * @brief Закрывает сокет
 */
static void close_socket(int sock) {
    if (sock >= 0) {
        close(sock);
    }
}

/* ============================================================================
 * ГЛАВНАЯ ФУНКЦИЯ
 * ============================================================================ */

/**
 * @brief Обработчик сигналов
 */
static void signal_handler(int sig) {
    syslog(LOG_INFO, "Получен сигнал %d, завершение...", sig);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Загружает конфигурацию серверов
 */
static int load_server_config(void) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Файл конфигурации не найден: %s", CONFIG_FILE);
        return 0;
    }

    char line[256];
    char ip_str[128];
    char port_str[16] = "123";

    while (fgets(line, sizeof(line), fp)) {
        /* Пропускаем пустые строки и комментарии */
        if (line[0] == '\n' || line[0] == '#' || line[0] == '\r') continue;

        /* Парсинг строки IP:PORT */
        char *colon = strchr(line, ':');
        if (!colon) {
            syslog(LOG_WARNING, "Неверный формат строки конфигурации: %s", line);
            continue;
        }

        /* Копирование IP-адреса */
        ptrdiff_t ip_diff = colon - line;
        if (ip_diff <= 0) {
            syslog(LOG_WARNING, "Неверный IP в строке конфигурации: %s", line);
            continue;
        }
        size_t ip_len = (size_t)ip_diff;
        if (ip_len >= sizeof(ip_str) - 1) {
            syslog(LOG_WARNING, "IP-адрес слишком длинный в строке: %s", line);
            continue;
        }
        strncpy(ip_str, line, ip_len);
        ip_str[ip_len] = '\0';

        /* Копирование порта */
        size_t port_len = strlen(colon + 1);
        if (port_len >= sizeof(port_str) - 1) {
            syslog(LOG_WARNING, "Порт слишком длинный в строке: %s", line);
            continue;
        }
        strncpy(port_str, colon + 1, sizeof(port_str) - 1);
        port_str[sizeof(port_str) - 1] = '\0';

        /* Увеличиваем счётчик серверов */
        g_server_count++;
        void *temp = realloc(g_servers, (size_t)g_server_count * sizeof(ServerConfig));
        if (temp == NULL) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для списка серверов");
            fclose(fp);
            return 0;
        }
        g_servers = (ServerConfig *)temp;

        /* Защита доступа к g_servers с помощью mutex */
        pthread_mutex_lock(&g_mutex);
        g_servers[g_server_count - 1].ip = strdup(ip_str);
        g_servers[g_server_count - 1].port = strdup(port_str);
        g_servers[g_server_count - 1].next_allowed_sync = 0;

        if (!g_servers[g_server_count - 1].ip || !g_servers[g_server_count - 1].port) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для IP/Port");
            fclose(fp);
            pthread_mutex_unlock(&g_mutex);
            return 0;
        }
        pthread_mutex_unlock(&g_mutex);

        syslog(LOG_INFO, "Конфигурация загружена: %s:%s", ip_str, port_str);
    }

    fclose(fp);
    return g_server_count;
}

/**
 * @brief Синхронизирует время с NTP-сервером
 */
static int sync_ntp_time(const char *ip, const char *port) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка сокета: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    
    /* Проверка порта */
    int port_num = atoi(port);
    if (port_num <= 0 || port_num > 65535) {
        syslog(LOG_ERR, "Неверный порт: %s", port);
        return -1;
    }

    /* DNS-резолвинг или проверка IP-адреса */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    /* Разделяем IP/имя и порт для getaddrinfo */
    char service[16];
    snprintf(service, sizeof(service), "%d", port_num);
    
    int ret = getaddrinfo(ip, service, &hints, &res);
    if (ret != 0 || res == NULL) {
        syslog(LOG_ERR, "Не удалось разрешить адрес: %s: %s",
                ip, gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    serv_addr.sin_family = addr->sin_family;
    serv_addr.sin_port = htons((uint16_t)port_num);
    serv_addr.sin_addr = addr->sin_addr;

    freeaddrinfo(res);

    /* Установка таймаута */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_ERR, "Не удалось установить таймаут: %s", strerror(errno));
        close_socket(sock);
        return -1;
    }

    /* Отправка запроса (RFC5905: 48 bytes) */
    uint8_t request[48];
    NtpTimestamp t1;
    create_ntp_request(request, &t1);

    if (sendto(sock, request, sizeof(request), 0,
                (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "Ошибка отправки запроса на %s:%s: %s",
                ip, port, strerror(errno));
        close_socket(sock);
        return -1;
    }

    /* Ожидание ответа */
    char buffer[BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t recv_len = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&from_addr, &from_len);

    if (recv_len > 0) {
        NtpTimestamp t4 = ntp_timestamp_now();
        /* Парсинг ответа */
        NtpPacket pkt;
        if (parse_ntp_packet(buffer, (size_t)recv_len, &pkt)) {
            uint8_t li = (uint8_t)((pkt.li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
            uint8_t mode = (uint8_t)(pkt.li_vn_mode & NTP_MODE_MASK);

            /* Обработка Leap Indicator */
            if (handle_leap_indicator(li)) {
                syslog(LOG_WARNING, "Пропускаем обработку из-за Leap Indicator");
            } else {
                if (mode != 4) {
                    syslog(LOG_WARNING, "Не server mode пакет (mode=%u) от %s:%s", mode, ip, port);
                    close_socket(sock);
                    return -1;
                }

                if (ntp_is_kod(&pkt)) {
                    char kod[5];
                    kod[0] = (char)((pkt.ref_id >> 24) & 0xFF);
                    kod[1] = (char)((pkt.ref_id >> 16) & 0xFF);
                    kod[2] = (char)((pkt.ref_id >> 8) & 0xFF);
                    kod[3] = (char)(pkt.ref_id & 0xFF);
                    kod[4] = '\0';
                    syslog(LOG_WARNING, "Kiss-o'-Death от %s:%s (code=%s)", ip, port, kod);
                    close_socket(sock);
                    return -1;
                }

                /* RFC5905: originate timestamp в ответе == наш T1 */
                if (pkt.orig_ts.sec != t1.sec || pkt.orig_ts.frac != t1.frac) {
                    syslog(LOG_WARNING, "Originate timestamp не совпал (spoof/late packet?)");
                    close_socket(sock);
                    return -1;
                }

                if (pkt.xmit_ts.sec == 0 && pkt.xmit_ts.frac == 0) {
                    syslog(LOG_WARNING, "Пустой transmit timestamp в ответе от %s:%s", ip, port);
                    close_socket(sock);
                    return -1;
                }

                /* Вычисление задержки и смещения (RFC 5905) */
                uint64_t delay_us;
                int64_t offset_us;
                if (calculate_delay_offset(&t1, &pkt.recv_ts, &pkt.xmit_ts, &t4, &delay_us, &offset_us)) {
                    /* Сохраняем poll от peer для динамического poll interval */
                    g_peer_poll = pkt.poll;

                    /* Вычислим нашу страту от страты peer */
                    uint8_t stratum = ntp_local_stratum_from_peer(pkt.stratum);

                    /* Динамический poll interval на основе условий сети */
                    g_local_poll = adjust_poll_interval(g_local_poll, g_peer_poll, delay_us, offset_us);

                    /* Добавление образца в кэш */
                    marx_add_sample_us((uint64_t)ntp_timestamp_to_ns(&t4), delay_us, offset_us);

                    /* Фильтрация выбросов */
                    g_sample_count = marx_filter_outliers(g_samples, g_sample_count, MARX_K);

                    /* Применение смещения: slew для малых offset, step для больших */
                    (void)apply_time_correction_slew_or_step(offset_us);

                    /* Обновляем RFC5905 состояние локального сервера */
                    pthread_mutex_lock(&g_mutex);
                    g_time_synced = (stratum <= 15);
                    g_local_stratum = stratum;
                    g_local_ref_ts = ntp_timestamp_now();
                    g_local_root_delay = ntp_u16_16_from_us(delay_us);
                    uint64_t abs_off = (offset_us < 0) ? (uint64_t)(-offset_us) : (uint64_t)offset_us;
                    uint64_t jitter_us = ntp_offset_jitter_us_locked();
                    /* RFC 5905: dispersion накапливается со скоростью PHI (15 ppm) */
                    g_local_root_disp = update_root_dispersion(g_local_root_disp, abs_off, jitter_us);
                    g_local_li = li;

                    /* ref_id: для stratum>=2 это IPv4 адрес upstream */
                    if (g_time_synced && g_local_stratum >= 2) {
                        struct in_addr a;
                        if (inet_pton(AF_INET, ip, &a) == 1) {
                            g_local_ref_id = (uint32_t)ntohl(a.s_addr);
                        } else {
                            g_local_ref_id = 0x4C4F434CUL; /* "LOCL" */
                        }
                    } else {
                        g_local_ref_id = 0x4C4F434CUL; /* "LOCL" */
                    }
                    pthread_mutex_unlock(&g_mutex);

                    syslog(LOG_INFO,
                           "Синхронизация успешно завершена с %s:%s: задержка=%" PRIu64 " мкс, "
                           "страта=%u, качество=%u%%, смещение=%" PRId64 " мкс",
                           ip, port, delay_us, stratum,
                           calculate_network_quality(delay_us), offset_us);

                    close_socket(sock);
                    return 0;
                }
            }
        }
    }

    close_socket(sock);
    return -1;
}

/* ============================================================================
 * ФУНКЦИЯ ОЧИСТКИ РЕСУРСОВ
 * ============================================================================ */

void cleanup_resources(void) {
    syslog(LOG_INFO, "Очистка ресурсов...");

    /* Закрытие сокетов */
    if (g_server_count > 0 && g_servers != NULL) {
        for (int i = 0; i < g_server_count; i++) {
            free(g_servers[i].ip);
            free(g_servers[i].port);
        }
        free(g_servers);
        g_servers = NULL;
        g_server_count = 0;
    }

    syslog(LOG_INFO, "Ресурсы очищены");
}

/* ============================================================================
 * ОСНОВНОЙ ЦИКЛ
 * ============================================================================ */

int main(int argc, char *argv[]) {
    (void)argc;  /* argc не используется */
    (void)argv;  /* argv не используется */

    /* Регистрация функции очистки при выходе */
    atexit(cleanup_resources);

    /* Инициализация системного логгера */
    openlog("ntpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    g_local_precision = get_system_precision();
    syslog(LOG_INFO, "System precision: %d (2^%d = %.3f сек)", 
            g_local_precision, g_local_precision, 
            g_local_precision >= 0 ? (double)(1 << g_local_precision) : 
                                     (double)1.0 / (double)(1LL << (-g_local_precision)));

    /* Установка обработчиков сигналов */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    /* Демонизация */
    setsid();
    umask(0);

    /* Загрузка конфигурации */
    g_server_count = load_server_config();
    if (g_server_count == 0) {
        syslog(LOG_CRIT, "Не удалось загрузить NTP-серверы. Завершение.");
        closelog();
        return EXIT_FAILURE;
    }

    syslog(LOG_NOTICE, "=====================================================================");
    syslog(LOG_NOTICE, "Сервер NTP запущен. Обнаружено %d серверов. Интервал: %d сек.",
            g_server_count, SYNC_INTERVAL_SECONDS);
    syslog(LOG_NOTICE, "=====================================================================");

    /* Создание сокета для обработки входящих запросов */
    int listen_sock = create_udp_socket(NTP_PORT);
    if (listen_sock < 0) {
        syslog(LOG_WARNING, "Не удалось создать сокет для входящих запросов");
    }

    /* Основной цикл */
    while (1) {
        syslog(LOG_INFO, "--- Начинается цикл синхронизации времени ---");

        /* Обработка входящих запросов */
        if (listen_sock >= 0) {
            char listen_buffer[BUFFER_SIZE];
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t listen_recv_len = recvfrom(listen_sock, listen_buffer, sizeof(listen_buffer), 0,
                                        (struct sockaddr *)&client_addr, &client_len);
            if (listen_recv_len > 0) {
                char client_ip[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip)) == NULL) {
                    strcpy(client_ip, "unknown");
                }
                char port_str[6];
                (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)ntohs(client_addr.sin_port));
                handle_client_request(listen_buffer, (size_t)listen_recv_len, client_ip, port_str);
            }
        }

        /* Синхронизация со всеми серверами */
        bool all_success = true;
        for (int i = 0; i < g_server_count; i++) {
            time_t now = time(NULL);
            if (now < 0) now = 0;

            if (g_servers[i].next_allowed_sync != 0 && now < g_servers[i].next_allowed_sync) {
                all_success = false;
                continue;
            }

            int rc = sync_ntp_time(g_servers[i].ip, g_servers[i].port);
            if (rc != 0) {
                all_success = false;
                /* простейший backoff на ошибки */
                g_servers[i].next_allowed_sync = now + 15;
            } else {
                g_servers[i].next_allowed_sync = 0;
            }
        }

        if (all_success) {
            syslog(LOG_NOTICE, "Все попытки синхронизации прошли успешно.");
        } else {
            syslog(LOG_WARNING, "Одна или несколько попыток синхронизации "
                               "завершились ошибкой.");
        }

        sleep(SYNC_INTERVAL_SECONDS);
    }

    /* Очистка ресурсов (через atexit) */
    closelog();
    return EXIT_SUCCESS;
}
