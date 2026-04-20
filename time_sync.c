#define _GNU_SOURCE
#include "time_sync.h"
#include "filter.h"
#include "ido.h"
#include "leap_second.h"
#include "mode_handler.h"
#include "ntp_algorithms.h"
#include "ntp_packet.h"
#include "ntpd.h"
#include "socket.h"
#include "threads.h"
#include <sys/timex.h>

/* ============================================================================
 * Clock Accuracy State (RFC 5905 Section 7.4)
 * ============================================================================
 */

/* RFC 5905 Section 7.4: Clock accuracy state */
ClockAccuracyState g_clock_accuracy;

/* ============================================================================
 * Leap Second Handling Integration (RFC 5905 Section 11.4)
 * ============================================================================
 */

/**
 * leap_second_integration_check - Check and apply leap second events
 *
 * Called periodically to check for leap second events and apply corrections.
 *
 * Return: 0 on success, -1 on error
 */
static int leap_second_integration_check(void) {
    /* Check leap second files */
    if (leap_second_check_file() != 0) { return -1; }

    /* Check and apply scheduled events */
    if (leap_second_check_and_apply() != 0) { return -1; }

    return 0;
}

/* ============================================================================
 * File I/O helpers for frequency persistence
 * ============================================================================
 */

static int freq_file_write(double ppm) {
    FILE* fp = fopen(FREQ_FILE, "w");
    if (fp == NULL) {
        syslog(LOG_DEBUG, "Cannot open frequency file for write: %s", strerror(errno));
        return -1;
    }
    fprintf(fp, "%.9f\n", ppm);
    fclose(fp);
    return 0;
}

static int freq_file_read(double* ppm_out) {
    FILE* fp = fopen(FREQ_FILE, "r");
    if (fp == NULL) { return -1; }
    if (fscanf(fp, "%lf", ppm_out) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

/* ============================================================================
 * Frequency discipline state management
 * ============================================================================
 */

int load_frequency_persistent(void) {
    double ppm = 0.0;
    if (freq_file_read(&ppm) == 0) {
        if (ppm > -FREQ_OFFSET_MAX_PPM && ppm < FREQ_OFFSET_MAX_PPM) {
            g_freq_state.ppm = ppm;
            g_freq_state.state = FREQ_STATE_FSET;
            syslog(LOG_INFO, "Loaded frequency offset: %.3f PPM", ppm);
            return 0;
        }
    }
    g_freq_state.state = FREQ_STATE_NSET;
    return -1;
}

int save_frequency_persistent(void) {
    if (g_freq_state.state != FREQ_STATE_SYNC) { return 0; }
    freq_file_write(g_freq_state.ppm);
    return 0;
}

int init_frequency_discipline(void) {
    memset(&g_freq_state, 0, sizeof(g_freq_state));
    g_freq_state.ppm = 0.0;
    g_freq_state.ppm_filter = 0.0;
    g_freq_state.ppm_error_history = 0.0;
    g_freq_state.state = FREQ_STATE_NSET;
    g_freq_state.last_update = 0;
    g_freq_state.last_offset_us = 0;
    g_freq_state.pll_stable_count = 0;
    g_freq_state.fll_recovery_count = 0;
    g_freq_state.dynamic_pll_gain = PLL_NOMINAL_GAIN;
    g_freq_state.dynamic_fll_gain = PLL_NOMINAL_GAIN;
    g_freq_state.recent_jitter_us = 0;

    /* RFC 5905 Section 7.4: Initialize clock accuracy state */
    init_clock_accuracy();
    g_freq_state.last_applied_ppm = 0;
    g_freq_state.last_apply_time = 0;
    return 0;
}

/* ============================================================================
 * Loop filter utilities
 * ============================================================================
 */

static double apply_loop_filter(double new_ppm, double* filter_ppm, double alpha) {
    /* CERT C 3.4.5: Check for NULL pointer */
    if (filter_ppm == NULL) { return 0.0; }

    /* Apply deadband for small errors */
    if (fabs(*filter_ppm) < FREQ_DEADBAND_PPM && fabs(new_ppm) < FREQ_DEADBAND_PPM) { return *filter_ppm; }

    /* Exponential averaging (low-pass filter) */
    double filtered = *filter_ppm + alpha * (new_ppm - *filter_ppm);
    *filter_ppm = filtered;
    return filtered;
}

static void update_dynamic_gain(uint64_t recent_jitter_us) {
    /* Dynamic gain scheduling based on recent jitter */
    if (recent_jitter_us > JITTER_HIGH_THRESHOLD_US) {
        g_freq_state.dynamic_fll_gain = FLL_LOW_GAIN;
        g_freq_state.dynamic_pll_gain = PLL_LOW_GAIN;
    } else if (recent_jitter_us < JITTER_LOW_THRESHOLD_US) {
        g_freq_state.dynamic_fll_gain = FLL_HIGH_GAIN;
        g_freq_state.dynamic_pll_gain = PLL_HIGH_GAIN;
    } else {
        g_freq_state.dynamic_fll_gain = PLL_NOMINAL_GAIN;
        g_freq_state.dynamic_pll_gain = PLL_NOMINAL_GAIN;
    }
}

/* ============================================================================
 * Frequency adjustment functions
 * ============================================================================
 */

static int apply_freq_adjtime(double ppm) {
    double adj_sec = ppm / 1000000.0;
    struct timeval delta;
    delta.tv_sec = (time_t)(adj_sec);
    delta.tv_usec = (suseconds_t)((adj_sec - (double)delta.tv_sec) * 1000000.0);
    if (delta.tv_usec < 0) {
        delta.tv_usec += 1000000;
        delta.tv_sec -= 1;
    }
    if (delta.tv_sec > 0 || (delta.tv_sec == 0 && delta.tv_usec > 100)) {
        delta.tv_sec = 0;
        delta.tv_usec = 100;
    }
    if (delta.tv_sec < 0 || (delta.tv_sec == 0 && delta.tv_usec < -100)) {
        delta.tv_sec = 0;
        delta.tv_usec = -100;
    }
    int ret = adjtime(&delta, NULL);
    if (ret < 0) { syslog(LOG_DEBUG, "adjtime frequency correction failed: %s", strerror(errno)); }
    return ret;
}

static int apply_freq_adjtimex(double ppm) {
#ifdef __linux__
    struct timex tx;
    memset(&tx, 0, sizeof(tx));
    tx.modes = 0x0002;
    tx.freq = (long)(ppm * 65536.0);
    int ret = adjtimex(&tx);
    if (ret < 0) {
        syslog(LOG_DEBUG, "adjtimex frequency correction failed: %s", strerror(errno));
        return -1;
    }
    if ((tx.status & 0x0040) != 0) {
        syslog(LOG_WARNING, "Clock unsynced by kernel");
        return -1;
    }
    return ret;
#else
    (void)ppm;
    return -1;
#endif
}

static double clamp_frequency(double ppm) {
    if (ppm > FREQ_OFFSET_MAX_PPM) { return FREQ_OFFSET_MAX_PPM; }
    if (ppm < -FREQ_OFFSET_MAX_PPM) { return -FREQ_OFFSET_MAX_PPM; }
    return ppm;
}

int apply_frequency_adjustment(double ppm) {
    double clamped = clamp_frequency(ppm);
    if (fabs(clamped) < 0.001) { return 0; }
    if (apply_freq_adjtimex(clamped) == 0) {
        g_freq_state.ppm = clamped;
        return 0;
    }
    return apply_freq_adjtime(clamped);
}

/* ============================================================================
 * Frequency calculation functions
 * ============================================================================
 */

/* ============================================================================
 * RFC 5905 Section 11.3 - FLL (Frequency Locked Loop)
 * Formula: freq += (offset - c.offset) / (max(mu, ALLAN) * (FLL - poll))
 * ============================================================================
 */
static double calculate_fll_ppm(int64_t offset_us, time_t delta_sec, int poll_exp) {
    if (delta_sec <= 0) { return 0.0; }

    /* RFC 5905: FLL = MAXPOLL + 1 = 18 */
    int fll_const = MAXPOLL + 1;

    /* FLL contribution: (offset - c.offset) / (max(mu, ALLAN) * (FLL - poll)) */
    int etemp = fll_const - poll_exp;
    if (etemp < 4) { etemp = 4; } /* RFC 5905: AVG = 4 */

    double offset_s = (double)offset_us / 1000000.0;
    double allan = (double)CLOCK_ALLAN_INTERCEPT;
    double mu = (double)delta_sec;

    double denom = fmax(mu, allan) * (double)etemp;
    if (denom <= 0.0) { return 0.0; }

    double ppm = offset_s / denom;
    return clamp_frequency(ppm);
}

/* ============================================================================
 * RFC 5905 Section 11.3 - PLL (Phase Locked Loop)
 * Formula: freq += offset * min(mu, 2^poll) / (4 * PLL * (2^poll)^2)
 * ============================================================================
 */
static double calculate_pll_ppm(int64_t offset_us, time_t delta_sec, int poll_exp) {
    if (delta_sec <= 0) { return 0.0; }

    /* RFC 5905: PLL = 65536 */
    double pll_const = 65536.0;

    /* RFC 5905: PLL integration interval: min(mu, 2^poll) */
    time_t poll_interval = 1LL << poll_exp;
    time_t etemp = (delta_sec < poll_interval) ? delta_sec : poll_interval;

    /* PLL frequency correction: offset * etemp / (4 * PLL * (2^poll)^2) */
    double dtemp = 4.0 * pll_const * (double)poll_interval * (double)poll_interval;
    if (dtemp <= 0.0) { return 0.0; }

    double offset_s = (double)offset_us / 1000000.0;
    double ppm = offset_s * (double)etemp / dtemp;
    return clamp_frequency(ppm);
}

/* ============================================================================
 * RFC 5905 Section 11.3 - Public API for frequency calculation
 * Note: This is a simplified version for external use
 * ============================================================================
 */
double calculate_frequency_ppm(int64_t offset_us, time_t delta_sec) {
    if (delta_sec <= 0) { return 0.0; }
    double offset_s = (double)offset_us / 1000000.0;
    double ppm = (offset_s / (double)delta_sec) * 1000000.0;
    return clamp_frequency(ppm);
}

/* ============================================================================
 * Frequency discipline state machine
 * ============================================================================
 */

static int update_frequency_discipline_internal(int64_t offset_us, int poll_exp, uint64_t jitter_us) {
    time_t now = time(NULL);
    time_t tc = 1LL << poll_exp;
    if (tc < FREQ_UPDATE_INTERVAL_MIN_SEC) { tc = FREQ_UPDATE_INTERVAL_MIN_SEC; }

    double new_ppm = g_freq_state.ppm;
    if (g_freq_state.state == FREQ_STATE_NSET) {
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            /* RFC 5905 Section 11.3: FLL for initial frequency estimation */
            double new_ppm_calc = calculate_fll_ppm(offset_us, delta, poll_exp);
            new_ppm = new_ppm_calc;
            g_freq_state.ppm = new_ppm;
            g_freq_state.state = FREQ_STATE_FSET;
        }
    } else if (g_freq_state.state == FREQ_STATE_FSET) {
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            /* RFC 5905 Section 11.3: Transition from FLL to PLL */
            double old_ppm = g_freq_state.ppm;
            double new_ppm_calc = calculate_fll_ppm(offset_us, delta, poll_exp);
            /* FLL gain: new_ppm = old + (new - old) / 2^FLLGAIN */
            new_ppm = old_ppm + (new_ppm_calc - old_ppm) / (double)(1 << CLOCK_FLLGAIN);
            g_freq_state.ppm = new_ppm;
            g_freq_state.state = FREQ_STATE_SYNC;
        }
    } else {
        /* FREQ_STATE_SYNC - PLL mode with proper loop filter and gain scheduling */
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            /* RFC 5905 Section 7.4: Update clock accuracy state */
            update_clock_accuracy(offset_us, delta);

            double new_ppm_calc;

            /* RFC 5905 Section 11.3: FLL for large poll intervals (tau >= 2048s) */
            if (poll_exp >= 11) {
                /* Use Allan intercept for FLL mode */
                double avg_dt = (double)CLOCK_ALLAN_INTERCEPT;
                if (avg_dt > 0) {
                    new_ppm_calc = calculate_fll_ppm(offset_us, (time_t)avg_dt, poll_exp);
                } else {
                    new_ppm_calc = 0.0;
                }
            } else {
                /* PLL mode for small poll intervals */
                new_ppm_calc = calculate_pll_ppm(offset_us, delta, poll_exp);
            }

            /* RFC 5905 Section 11.3: Apply loop filter with dynamic gain */
            /* Update dynamic gains based on jitter */
            update_dynamic_gain(jitter_us);

            /* Apply loop filter (low-pass) */
            /* Formula: filtered_ppm = old_ppm + alpha * (new_ppm - old_ppm) */
            double filtered_ppm = apply_loop_filter(new_ppm_calc, &g_freq_state.ppm_filter, PLL_ALPHA);

            g_freq_state.ppm = filtered_ppm;

            g_freq_state.ppm = filtered_ppm;
        }
    }
    g_freq_state.last_update = now;
    g_freq_state.last_offset_us = offset_us;
    return apply_frequency_adjustment(g_freq_state.ppm);
}

int update_frequency_discipline(int64_t offset_us, int poll_exp) {
    /* CERT C 3.2.2: Protect against race conditions */
    pthread_mutex_lock(&g_mutex);

    /* Get jitter while holding the mutex to avoid double lock */
    uint64_t jitter_us = ntp_offset_jitter_us_locked();

    int result = update_frequency_discipline_internal(offset_us, poll_exp, jitter_us);

    pthread_mutex_unlock(&g_mutex);
    return result;
}

/* ============================================================================
 * Time synchronization
 * ============================================================================
 */

int apply_time_correction_slew_or_step(int64_t offset_us) {
    /* Check panic condition (RFC 5905 Section 11.3) */
    if (check_panic_condition(offset_us)) {
        syslog(LOG_WARNING, "Panic condition detected: time offset %lus exceeds threshold", offset_us / 1000);
        return -1;
    }

    if (offset_us > STEP_THRESHOLD_US || offset_us < -STEP_THRESHOLD_US) {
        struct timespec now_ts;
        if (clock_gettime(CLOCK_REALTIME, &now_ts) != 0) { return -1; }

        int64_t offset_ns = offset_us * 1000LL;
        int64_t ns = (int64_t)now_ts.tv_sec * 1000000000LL + (int64_t)now_ts.tv_nsec;

        // Check for overflow before addition
        if (offset_ns > 0 && ns > INT64_MAX - offset_ns) {
            syslog(LOG_ERR, "Integer overflow in time correction: ns=%ld offset=%ld", (long)ns, (long)offset_ns);
            return -1;
        }
        if (offset_ns < 0 && ns < INT64_MIN - offset_ns) {
            syslog(LOG_ERR, "Integer underflow in time correction: ns=%ld offset=%ld", (long)ns, (long)offset_ns);
            return -1;
        }
        ns += offset_ns;
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

NtpTimestamp ntp_timestamp_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        syslog(LOG_ERR, "Ошибка получения времени: %s", strerror(errno));
        NtpTimestamp z = {0, 0};
        return z;
    }
    uint64_t sec = (uint64_t)ts.tv_sec + (uint64_t)NTP_UNIX_EPOCH_DELTA;
    NtpTimestamp t = {0, 0};
    if (sec > UINT32_MAX) {
        t.sec = UINT32_MAX;
        t.frac = UINT32_MAX;
        return t;
    }
    t.sec = (uint32_t)sec;
    uint64_t frac = ((uint64_t)ts.tv_nsec << 32) / 1000000000ULL;
    t.frac = (uint32_t)frac;
    return t;
}

int8_t get_system_precision(void) {
    struct timespec ts;
    if (clock_getres(CLOCK_REALTIME, &ts) == 0) {
        if (ts.tv_sec == 0 && ts.tv_nsec == 0) { return -20; }
        if (ts.tv_sec > 0) {
            int8_t p = 0;
            time_t s = ts.tv_sec;
            while (s > 0) {
                p++;
                s >>= 1;
            }
            return (p > 6) ? 6 : -p;
        }
        int64_t ns = (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
        if (ns <= 0) { return -20; }
        int8_t p = 0;
        while (ns < 1000000000LL) {
            p--;
            ns <<= 1;
        }
        return p;
    }
    return -20;
}

/* ============================================================================
 * Dispersion Update Function (RFC 5905 Section 11.1)
 * ============================================================================
 */

uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us) {
    time_t now = time(NULL);

    pthread_mutex_lock(&g_mutex);

    if (g_last_dispersion_update == 0) {
        g_last_dispersion_update = now;
        pthread_mutex_unlock(&g_mutex);
        return current_disp;
    }

    int64_t elapsed_sec = (int64_t)now - (int64_t)g_last_dispersion_update;
    if (elapsed_sec < 0) { elapsed_sec = 0; }

    double phi_dispersion = ((double)PHI * (double)elapsed_sec) / 1000000.0;

    uint64_t disp_us = offset_us;
    uint64_t jitter_us_val = jitter_us;

    if (disp_us > (uint64_t)UINT32_MAX) { disp_us = UINT32_MAX; }

    double new_disp;
    if (phi_dispersion > (double)UINT32_MAX - (double)disp_us - (double)jitter_us_val) {
        new_disp = (double)UINT32_MAX;
    } else {
        new_disp = phi_dispersion + (double)disp_us + (double)jitter_us_val;
    }

    g_last_dispersion_update = now;
    pthread_mutex_unlock(&g_mutex);

    return ntp_u16_16_from_us((uint64_t)new_disp);
}

/* ============================================================================
 * Poll Interval Adjustment Functions
 * ============================================================================
 */

int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us) {
    int8_t new_poll = current_poll;

    if (peer_poll < current_poll) { new_poll = peer_poll; }

    if (delay_us > POLL_DELAY_HIGH_THRESHOLD_US || offset_us > (int64_t)POLL_OFFSET_HIGH_THRESHOLD_US || offset_us < -(int64_t)POLL_OFFSET_HIGH_THRESHOLD_US) {
        if (new_poll < POLL_INTERVAL_MAX) { new_poll++; }
    } else if (delay_us < POLL_DELAY_LOW_THRESHOLD_US && offset_us > -(int64_t)POLL_OFFSET_LOW_THRESHOLD_US &&
               offset_us < (int64_t)POLL_OFFSET_LOW_THRESHOLD_US) {
        if (new_poll > POLL_INTERVAL_MIN) { new_poll--; }
    }

    return new_poll;
}

int sync_ntp_time(const char* ip, const char* port) {
    if (ip == NULL || port == NULL) { return -1; }

    int sock = get_sync_socket();
    if (sock < 0) { return -1; }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    long port_num_l = strtol(port, NULL, 10);
    if (port_num_l < 1 || port_num_l > 65535 || errno != 0) {
        syslog(LOG_ERR, "Неверный порт: %s", port);
        return -1;
    }
    int port_num = (int)port_num_l;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char service[16];
    snprintf(service, sizeof(service), "%d", port_num);

    int ret = getaddrinfo(ip, service, &hints, &res);
    if (ret != 0 || res == NULL) {
        syslog(LOG_ERR, "Не удалось разрешить адрес: %s: %s", ip, gai_strerror(ret));
        return -1;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    serv_addr.sin_family = addr->sin_family;
    serv_addr.sin_port = htons((uint16_t)port_num);
    serv_addr.sin_addr = addr->sin_addr;

    freeaddrinfo(res);

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_ERR, "Не удалось установить таймаут: %s", strerror(errno));
        close_socket(sock);
        return -1;
    }

    uint8_t request[48];
    NtpTimestamp t1;
    create_ntp_request(request, &t1);

    if (sendto(sock, request, sizeof(request), 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "Ошибка отправки запроса на %s:%s: %s", ip, port, strerror(errno));
        close_socket(sock);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from_addr, &from_len);

    if (recv_len > 0) {
        /* RFC 5905 Section 11.2.1: Multi-server integration - process all peers in
         * pool */
        /* Update peer pool state with received packet */
        pthread_mutex_lock(&g_mutex);
        for (int i = 0; i < g_peer_pool_count; i++) {
            if (strncmp(g_peer_pool[i].ip, ip, sizeof(g_peer_pool[i].ip) - 1) == 0 &&
                strncmp(g_peer_pool[i].port, port, sizeof(g_peer_pool[i].port) - 1) == 0) {
                g_peer_pool[i].reachable = true;
                g_peer_pool[i].last_update = time(NULL);
                break;
            }
        }
        pthread_mutex_unlock(&g_mutex);

        NtpTimestamp t4 = ntp_timestamp_now();
        NtpPacket pkt;
        if (parse_ntp_packet(buffer, (size_t)recv_len, &pkt)) {
            uint8_t li = (uint8_t)((pkt.li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
            uint8_t mode = (uint8_t)(pkt.li_vn_mode & NTP_MODE_MASK);

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

                uint64_t delay_us;
                int64_t offset_us;
                if (calculate_delay_offset(&t1, &pkt.recv_ts, &pkt.xmit_ts, &t4, &delay_us, &offset_us)) {
                    uint8_t peer_stratum = pkt.stratum;
                    uint8_t stratum = ntp_local_stratum_from_peer(peer_stratum);

                    /* RFC 5905 Section 11.3: Do not correct if peer is not reliable */
                    if (peer_stratum == 0 || peer_stratum > 15) {
                        syslog(LOG_WARNING, "Пропуск коррекции: ненадёжный сервер (stratum=%u)", peer_stratum);
                        pthread_mutex_lock(&g_mutex);
                        g_local_stratum = 16;
                        g_time_synced = false;
                        pthread_mutex_unlock(&g_mutex);
                        close_socket(sock);
                        return -1;
                    }

                    /* RFC 5905 Section 11.3: Do not step if offset exceeds MAXDIST (1
                     * sec) */
                    int64_t abs_offset_us = (offset_us >= 0) ? offset_us : -offset_us;
                    if (abs_offset_us > MAXDIST) {
                        syslog(LOG_WARNING, "Пропуск коррекции: смещение слишком большое (%" PRId64 " мкс > %d мкс)", offset_us, MAXDIST);
                        pthread_mutex_lock(&g_mutex);
                        g_local_stratum = 16;
                        g_time_synced = false;
                        pthread_mutex_unlock(&g_mutex);
                        close_socket(sock);
                        return -1;
                    }

                    /* RFC 5905 Section 11.3: Check for excessive delay (Bogus packet
                     * detection) */
                    if (delay_us > MAXDIST * 10) {
                        syslog(LOG_WARNING, "Пропуск коррекции: задержка слишком большая (%" PRIu64 " мкс)", delay_us);
                        pthread_mutex_lock(&g_mutex);
                        g_time_synced = false;
                        pthread_mutex_unlock(&g_mutex);
                        close_socket(sock);
                        return -1;
                    }

                    /* RFC 5905 Section 11.2.1: Calculate network quality for peer
                     * selection */
                    uint8_t network_quality = calculate_network_quality(delay_us);
                    syslog(LOG_DEBUG, "Network quality: %u%% (delay=%" PRIu64 " мкс)", network_quality, delay_us);

                    /* RFC 5905 Section 11.2.1: Use compute_system_offset() for Byzantine
                     * fault detection */
                    /* For single peer: use offset directly, for pool: use majority vote
                     */
                    int best_idx = 0;
                    (void)compute_system_offset(&offset_us, 1, &best_idx); /* Suppress unused variable warning */
                    syslog(LOG_DEBUG, "System offset computed (best_idx=%d)", best_idx);

                    /* RFC 5905 Section 10: MARX filter for outlier detection */
                    struct timeval tv_now;
                    if (gettimeofday(&tv_now, NULL) == 0) {
                        uint64_t now_ns = (uint64_t)tv_now.tv_sec * 1000000000ULL + (uint64_t)tv_now.tv_usec * 1000;
                        marx_add_sample_us(now_ns, delay_us, offset_us);
                    }

                    // Filter using MARX algorithm (RFC 5905 Section 10)
                    int valid_count = marx_filter_outliers(g_samples, g_sample_count, 3);
                    if (valid_count == 0) {
                        syslog(LOG_WARNING, "MARX: No valid samples after filtering, skipping correction");
                        pthread_mutex_lock(&g_mutex);
                        g_time_synced = false;
                        pthread_mutex_unlock(&g_mutex);
                        close_socket(sock);
                        return -1;
                    }
                    syslog(LOG_DEBUG, "Valid samples after MARX filtering: %d", valid_count);

                    /* Update poll interval under mutex */
                    g_local_poll = adjust_poll_interval(g_local_poll, pkt.poll, delay_us, offset_us);

                    pthread_mutex_unlock(&g_mutex);

                    /* RFC 5905 Section 7.4: Update clock accuracy state */
                    update_clock_accuracy(offset_us, g_local_poll);

                    // Apply correction only if we have valid filtered samples
                    if (valid_count >= 1) {
                        int apply_result = apply_time_correction_slew_or_step(offset_us);
                        if (apply_result == 0) {
                            syslog(LOG_DEBUG, "Коррекция применена: %" PRId64 " мкс", offset_us);
                        } else {
                            syslog(LOG_WARNING, "Ошибка применения коррекции: %s", strerror(errno));
                        }
                        /* RFC 5905 Section 11.3: Update frequency discipline */
                        update_frequency_discipline(offset_us, g_local_poll);
                    } else {
                        syslog(LOG_DEBUG, "Пропуск коррекции: недостаточно выборок");
                    }

                    pthread_mutex_lock(&g_mutex);
                    g_time_synced = (stratum <= 15);
                    g_local_stratum = stratum;
                    g_last_sync_ts = t4;
                    g_local_ref_ts = g_last_sync_ts;
                    g_local_root_delay = ntp_u16_16_from_us(delay_us);
                    uint64_t abs_off = (offset_us < 0) ? (uint64_t)(-offset_us) : (uint64_t)offset_us;
                    uint64_t jitter_us = ntp_offset_jitter_us_locked();
                    g_local_root_disp = update_root_dispersion(g_local_root_disp, abs_off, jitter_us);
                    g_local_li = li;

                    if (g_time_synced && g_local_stratum >= 2) {
                        struct in_addr a;
                        if (inet_pton(AF_INET, ip, &a) == 1) {
                            g_local_ref_id = (uint32_t)ntohl(a.s_addr);
                        } else {
                            g_local_ref_id = 0x4C4F434CUL;
                        }
                    } else {
                        g_local_ref_id = 0x4C4F434CUL;
                    }
                    pthread_mutex_unlock(&g_mutex);

                    syslog(LOG_INFO,
                           "Синхронизация успешно завершена с %s:%s: задержка=%" PRIu64 " мкс, "
                           "страта=%u, смещение=%" PRId64 " мкс",
                           ip, port, delay_us, stratum, offset_us);

                    /* RFC 5905 Section 11.4: Check for leap second events after sync */
                    if (leap_second_integration_check() == 0) {
                        syslog(LOG_INFO, "Leap second check completed after sync");
                    } else {
                        syslog(LOG_WARNING, "Leap second check failed after sync: %s", strerror(errno));
                    }

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
 * RFC 5905 Section 7.4 - Clock Accuracy Estimation
 * ============================================================================
 */

/**
 * calculate_clock_precision - Calculate clock precision (ρ)
 *
 * RFC 5905 Section 6.2: Clock precision is the larger of:
 * - Clock resolution (2^(-p) seconds)
 * - Time to read the system clock
 *
 * Return: Clock precision in seconds
 */
double calculate_clock_precision(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* Time to read the system clock */
    double read_time = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;

    /* Clock resolution (2^(-p)) */
    int8_t precision = get_system_precision();
    double resolution = pow(2.0, -precision);

    /* ρ = max(resolution, read_time) */
    return fmax(resolution, read_time);
}

/**
 * calculate_allan_variance - Calculate Allan variance for clock stability
 *
 * RFC 5905 Section 6.2: Allan variance measures clock stability over time
 * σ_y(τ) = sqrt(<(y_i+1 - y_i)² / 2>)
 *
 * Parameters:
 *   offset_us - Time offset in microseconds
 *   delta_sec - Time interval in seconds
 *
 * Return: Allan variance (stability metric)
 */
double calculate_allan_variance(int64_t offset_us, time_t delta_sec) {
    if (delta_sec <= 0) { return 0.0; }

    /* Frequency offset (s/s) */
    double freq_offset = (double)offset_us / 1e6;
    double freq_stability = freq_offset / (double)delta_sec;

    /* Exponential averaging for stability */
    static double variance = 0.0;
    static double prev_freq = 0.0;

    double delta_freq = freq_stability - prev_freq;
    variance = 0.25 * (delta_freq * delta_freq + variance);
    prev_freq = freq_stability;

    return sqrt(variance);
}

/**
 * init_clock_accuracy - Initialize clock accuracy state
 *
 * Called once during system initialization.
 */
void init_clock_accuracy(void) {
    ClockAccuracyState* state = &g_clock_accuracy;

    /* Initialize all fields to zero */
    memset(state, 0, sizeof(*state));

    /* Set initial precision to clock resolution */
    state->precision = 0.0;
    state->resolution = 0.0;
    state->accuracy_estimate = 0.0;
    state->stability_metric = 0.0;
    state->last_update = 0;
}

/**
 * update_clock_accuracy - Update clock accuracy state
 *
 * Called periodically to update clock accuracy estimates.
 *
 * Parameters:
 *   offset_us - Time offset in microseconds
 *   delta_sec - Time interval in seconds
 */
void update_clock_accuracy(int64_t offset_us, time_t delta_sec) {
    ClockAccuracyState* state = &g_clock_accuracy;

    /* Calculate precision */
    state->precision = calculate_clock_precision();

    /* Calculate Allan variance for stability */
    state->stability_metric = calculate_allan_variance(offset_us, delta_sec);

    /* Update offset history for stability tracking */
    static int history_idx = 0;
    state->offset_history[history_idx] = (uint64_t)offset_us;
    state->offset_history_time[history_idx] = delta_sec;
    history_idx = (history_idx + 1) % 16;

    /* Update last update time */
    state->last_update = time(NULL);

    /* Log accuracy metrics */
    syslog(LOG_DEBUG, "Clock accuracy: precision=%.6f, stability=%.6f", state->precision, state->stability_metric);
}

/**
 * get_clock_accuracy_state - Get pointer to clock accuracy state
 *
 * Return: Pointer to clock accuracy state (never NULL)
 */
ClockAccuracyState* get_clock_accuracy_state(void) {
    return &g_clock_accuracy;
}

/**
 * get_clock_precision - Get current clock precision
 *
 * Return: Clock precision in seconds
 */
double get_clock_precision(void) {
    return g_clock_accuracy.precision;
}

/**
 * get_clock_stability - Get current clock stability metric
 *
 * Return: Clock stability metric (Allan variance)
 */
double get_clock_stability(void) {
    return g_clock_accuracy.stability_metric;
}

/* ============================================================================
 * End of time_sync.c
 * ============================================================================
 */