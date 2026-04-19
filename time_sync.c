#define _GNU_SOURCE
#include "ntpd.h"
#include <sys/timex.h>

/**
 * get_system_precision - Get system clock precision
 *
 * Returns clock precision as signed exponent (RFC 5905 Section 6):
 * Negative values = sub-second (e.g., -20 = ~1 microsecond)
 * Positive values = second+ (e.g., 4 = 16 seconds)
 *
 * Uses clock_getres(CLOCK_REALTIME) to determine resolution.
 * Returns -20 on error (typical for modern systems).
 *
 * Return: Precision as log2(seconds), or -20 on error
 */
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
        if (ns <= 0) return -20;
        int8_t p = 0;
        while (ns < 1000000000LL) {
            p--;
            ns <<= 1;
        }
        return p;
    }
    return -20;
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

/**
 * apply_time_correction_slew_or_step - Apply time correction using slew or step
 * @offset_us: Time offset in microseconds
 *
 * Applies time correction according to RFC 5905 Section 11.3:
 * - STEP (clock_settime): |offset| > 500ms (STEP_THRESHOLD_US)
 * - SLEW (adjtime): |offset| <= 500ms
 *
 * Checks for integer overflow before applying correction.
 *
 * Return: 0 on success, -1 on error
 */
int apply_time_correction_slew_or_step(int64_t offset_us) {
    if (offset_us > STEP_THRESHOLD_US || offset_us < -STEP_THRESHOLD_US) {
        struct timespec now_ts;
        if (clock_gettime(CLOCK_REALTIME, &now_ts) != 0) return -1;

        int64_t offset_ns = offset_us * 1000LL;
        int64_t ns = (int64_t)now_ts.tv_sec * 1000000000LL + (int64_t)now_ts.tv_nsec;

        if (offset_ns > 0 && ns > INT64_MAX - offset_ns) {
            syslog(LOG_ERR, "Integer overflow in time correction");
            return -1;
        }
        if (offset_ns < 0 && ns < INT64_MIN - offset_ns) {
            syslog(LOG_ERR, "Integer overflow in time correction");
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
    g_freq_state.state = FREQ_STATE_NSET;
    g_freq_state.last_update = 0;
    g_freq_state.last_offset_us = 0;
    return 0;
}

static double clamp_frequency(double ppm) {
    if (ppm > FREQ_OFFSET_MAX_PPM) return FREQ_OFFSET_MAX_PPM;
    if (ppm < -FREQ_OFFSET_MAX_PPM) return -FREQ_OFFSET_MAX_PPM;
    return ppm;
}

static double calculate_fll_ppm(int64_t offset_us, time_t delta_sec) {
    if (delta_sec <= 0) return 0.0;
    double offset_s = (double)offset_us / 1000000.0;
    double ppm = (offset_s / (double)delta_sec) * 1000000.0;
    return clamp_frequency(ppm);
}

static double calculate_pll_ppm(int64_t offset_us, time_t last_update) {
    if (last_update <= 0) return 0.0;
    time_t now = time(NULL);
    if (now <= last_update) return 0.0;
    time_t dt = now - last_update;
    double offset_s = (double)offset_us / 1000000.0;
    double ppm = (offset_s / (double)dt) * 1000000.0;
    return clamp_frequency(ppm);
}

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

int apply_frequency_adjustment(double ppm) {
    double clamped = clamp_frequency(ppm);
    if (fabs(clamped) < 0.001) { return 0; }
    if (apply_freq_adjtimex(clamped) == 0) {
        g_freq_state.ppm = clamped;
        return 0;
    }
    return apply_freq_adjtime(clamped);
}

double calculate_frequency_ppm(int64_t offset_us, time_t delta_sec) {
    if (delta_sec < FREQ_UPDATE_INTERVAL_MIN_SEC) { return calculate_pll_ppm(offset_us, (time_t)g_freq_state.last_update); }
    return calculate_fll_ppm(offset_us, delta_sec);
}

int update_frequency_discipline(int64_t offset_us, int poll_exp) {
    time_t now = time(NULL);
    time_t tc = 1LL << poll_exp;
    if (tc < FREQ_UPDATE_INTERVAL_MIN_SEC) { tc = FREQ_UPDATE_INTERVAL_MIN_SEC; }
    double new_ppm = 0.0;
    if (g_freq_state.state == FREQ_STATE_NSET) {
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            new_ppm = calculate_fll_ppm(offset_us, delta);
            g_freq_state.ppm = new_ppm;
            g_freq_state.state = FREQ_STATE_FSET;
        }
    } else if (g_freq_state.state == FREQ_STATE_FSET) {
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            double old_ppm = g_freq_state.ppm;
            double new_ppm_calc = calculate_fll_ppm(offset_us, delta);
            new_ppm = old_ppm + (new_ppm_calc - old_ppm) / (double)(1 << CLOCK_FLLGAIN);
            g_freq_state.ppm = new_ppm;
            g_freq_state.state = FREQ_STATE_SYNC;
        }
    } else {
        time_t delta = now - g_freq_state.last_update;
        if (delta >= tc) {
            double old_ppm = g_freq_state.ppm;
            double new_ppm_calc;
            if (poll_exp >= 11) {
                new_ppm_calc = calculate_fll_ppm(offset_us, delta);
            } else {
                int64_t total_offset = offset_us;
                time_t avg_dt = (delta + (time_t)g_freq_state.last_update) / 2;
                new_ppm_calc = calculate_pll_ppm(total_offset, avg_dt);
            }
            double gain = (double)(1 << CLOCK_PLLGAIN);
            new_ppm = old_ppm + (new_ppm_calc - old_ppm) / gain;
            g_freq_state.ppm = new_ppm;
        }
    }
    g_freq_state.last_update = now;
    g_freq_state.last_offset_us = offset_us;
    return apply_frequency_adjustment(g_freq_state.ppm);
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

                    g_local_poll = adjust_poll_interval(g_local_poll, g_peer_poll, delay_us, offset_us);

                    marx_add_sample_us((uint64_t)ntp_timestamp_to_ns(&t4), delay_us, offset_us);

                    pthread_mutex_lock(&g_mutex);
                    g_sample_count = marx_filter_outliers(g_samples, g_sample_count, MARX_K);

                    /* Get filtered offset from samples */
                    int64_t filtered_offset = offset_us;
                    if (g_sample_count > 0) { filtered_offset = g_samples[g_sample_count - 1].offset; }

                    /* Update poll interval under mutex */
                    g_local_poll = adjust_poll_interval(g_local_poll, pkt.poll, delay_us, offset_us);

                    pthread_mutex_unlock(&g_mutex);

                    /* Apply correction only if we have valid samples */
                    if (g_sample_count >= 1) {
                        int apply_result = apply_time_correction_slew_or_step(filtered_offset);
                        if (apply_result == 0) {
                            syslog(LOG_DEBUG, "Коррекция применена: %" PRId64 " мкс", filtered_offset);
                        } else {
                            syslog(LOG_WARNING, "Ошибка применения коррекции: %s", strerror(errno));
                        }
                        update_frequency_discipline(filtered_offset, g_local_poll);
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

                    close_socket(sock);
                    return 0;
                }
            }
        }
    }

    close_socket(sock);
    return -1;
}
