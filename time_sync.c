#include "ntpd.h"

int8_t get_system_precision(void) {
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

int apply_time_correction_slew_or_step(int64_t offset_us) {
    const int64_t step_threshold_us = 500000;

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

int sync_ntp_time(const char *ip, const char *port) {
    int sock = get_sync_socket();
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    int port_num = atoi(port);
    if (port_num <= 0 || port_num > 65535) {
        syslog(LOG_ERR, "Неверный порт: %s", port);
        return -1;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

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

    if (sendto(sock, request, sizeof(request), 0,
                (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "Ошибка отправки запроса на %s:%s: %s",
                ip, port, strerror(errno));
        close_socket(sock);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t recv_len = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&from_addr, &from_len);

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
                    g_peer_poll = pkt.poll;

                    uint8_t stratum = ntp_local_stratum_from_peer(pkt.stratum);

                    g_local_poll = adjust_poll_interval(g_local_poll, g_peer_poll, delay_us, offset_us);

                    marx_add_sample_us((uint64_t)ntp_timestamp_to_ns(&t4), delay_us, offset_us);

                    g_sample_count = marx_filter_outliers(g_samples, g_sample_count, MARX_K);

                    (void)apply_time_correction_slew_or_step(offset_us);

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