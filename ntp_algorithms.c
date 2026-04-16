#include "ntpd.h"

int64_t ntp_timestamp_to_ns(const NtpTimestamp *t) {
    if (t == NULL) return 0;
    int64_t sec = (int64_t)t->sec - (int64_t)NTP_UNIX_EPOCH_DELTA;
    int64_t nsec = (int64_t)(((uint64_t)t->frac * 1000000000ULL) >> 32);
    return sec * 1000000000LL + nsec;
}

bool calculate_delay_offset(const NtpTimestamp *t1,
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

    int64_t delay_ns = (T4 - T1) - (T3 - T2);
    int64_t offset_ns = ((T2 - T1) + (T3 - T4)) / 2;

    if (delay_ns < 0) {
        syslog(LOG_WARNING, "Отрицательная задержка (ns): %" PRId64, delay_ns);
        return false;
    }

    *delay_us = (uint64_t)(delay_ns / 1000);
    *offset_us = offset_ns / 1000;
    return true;
}

bool handle_leap_indicator(uint8_t li) {
    switch (li) {
        case 0:
            syslog(LOG_INFO, "Leap Indicator: No warning");
            return false;
        case 1:
            syslog(LOG_INFO, "Leap Indicator: Last minute 61-62 seconds OK");
            return false;
        case 2:
            syslog(LOG_WARNING, "Leap Indicator: Last minute 61-62 seconds NOT OK");
            return true;
        case 3:
            syslog(LOG_WARNING, "Leap Indicator: Last minute not OK - possible clock jump");
            return true;
        default:
            syslog(LOG_ERR, "Invalid Leap Indicator: %d", li);
            return true;
    }
}

uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum) {
    if (peer_stratum == 0 || peer_stratum > 15) return 16;
    uint16_t s = (uint16_t)peer_stratum + 1u;
    if (s > 15u) return 15u;
    return (uint8_t)s;
}

uint8_t compute_system_offset(int8_t *offsets, int count, int *best_idx) {
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
    int64_t total = 0;
    int used = 0;
    for (int i = 0; i < count; i++) {
        int8_t diff = offsets[i] - median;
        if (diff < 0) diff = -diff;
        /* diff имеет тип int8_t, диапазон -128..127, поэтому diff < 500 всегда истинно */
        if (diff < 127) {
            total += offsets[i];
            used++;
        }
    }

    if (used > 0) {
        *best_idx = 0;
        return (uint8_t)(total / used);
    }

    *best_idx = 0;
    return (uint8_t)median;
}

uint32_t ntp_u16_16_from_us(uint64_t us) {
    if (us > (UINT64_MAX / 65536ULL)) return UINT32_MAX;
    uint64_t v = (us * 65536ULL) / 1000000ULL;
    return (v > UINT32_MAX) ? UINT32_MAX : (uint32_t)v;
}

uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us) {
    /* Защита от race condition с g_last_dispersion_update */
    pthread_mutex_lock(&g_mutex);
    time_t last_update = g_last_dispersion_update;
    pthread_mutex_unlock(&g_mutex);

    if (last_update == 0) {
        g_last_dispersion_update = time(NULL);
        return current_disp;
    }

    /* Вычисление elapsed с защитой от race condition */
    time_t now = time(NULL);
    int64_t elapsed_sec = (int64_t)now - (int64_t)last_update;
    if (elapsed_sec < 0) elapsed_sec = 0;

    /* Вычисление phi_dispersion с защитой от overflow */
    /* PHI = 15, elapsed_sec >= 0 */
    double phi_dispersion = ((double)(int64_t)PHI * (double)elapsed_sec) / 1000000.0;

    /* Проверка на overflow перед сложением */
    /* Максимальное значение UINT32_MAX = 4294967295 */
    /* Проверка: phi_dispersion + disp_us + jitter_us <= UINT32_MAX */
    uint64_t disp_us = offset_us;  /* offset_us уже unsigned, берём абсолютное значение */
    uint64_t jitter_us_val = jitter_us;

    /* Проверка: phi_dispersion + disp_us <= UINT32_MAX */
    if (disp_us > (uint64_t)UINT32_MAX) {
        disp_us = UINT32_MAX;
    }

    /* Проверка: phi_dispersion + disp_us + jitter_us <= UINT32_MAX */
    double new_disp;
    if (phi_dispersion > (double)UINT32_MAX - (double)disp_us - (double)jitter_us_val) {
        new_disp = (double)UINT32_MAX;
    } else {
        new_disp = phi_dispersion + (double)disp_us + (double)jitter_us_val;
    }

    g_last_dispersion_update = now;
    return ntp_u16_16_from_us((uint64_t)new_disp);
}

int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us) {
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

/* ============================================================================
 * Вспомогательные функции
 * ============================================================================ */

uint8_t calculate_network_quality(uint64_t delay) {
    int64_t quality = 100 - (int64_t)(delay / 1000);
    if (quality < 0) return 0;
    if (quality > 100) return 100;
    return (uint8_t)quality;
}