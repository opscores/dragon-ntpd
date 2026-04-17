#include "ntpd.h"
#include <stdlib.h>
#include <sys/select.h>

int g_sync_sock = -1;
static int g_tcp_sock = -1;
static pthread_mutex_t g_tcp_sock_mutex = PTHREAD_MUTEX_INITIALIZER;

int get_sync_socket(void) {
    if (g_sync_sock >= 0) return g_sync_sock;

    g_sync_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sync_sock < 0) {
        syslog(LOG_ERR, "Не удалось создать сокет синхронизации: %s", strerror(errno));
        return -1;
    }

    int reuse = 1;
    setsockopt(g_sync_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    return g_sync_sock;
}

int create_udp_socket(int port) {
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

    if (g_cli.interface != NULL) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, g_cli.interface, IFNAMSZ - 1);

        if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
            struct sockaddr_in *ifa_addr = (struct sockaddr_in *)&ifr.ifr_addr;
            addr.sin_addr = ifa_addr->sin_addr;
            syslog(LOG_INFO, "Привязка к интерфейсу %s: %s",
                 g_cli.interface, inet_ntoa(addr.sin_addr));
        } else {
            syslog(LOG_WARNING, "Не удалось получить адрес интерфейса %s: %s",
                  g_cli.interface, strerror(errno));
            addr.sin_addr.s_addr = INADDR_ANY;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Ошибка привязки сокета: %s", strerror(errno));
        close_socket(sock);
        return -1;
    }

    return sock;
}

void close_socket(int sock) {
    pthread_mutex_lock(&g_tcp_sock_mutex);
    int tcp_sock_copy = g_tcp_sock;
    pthread_mutex_unlock(&g_tcp_sock_mutex);

    if (sock >= 0 && sock != g_sync_sock && sock != tcp_sock_copy) {
        close(sock);
    }
}

int create_tcp_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка создания TCP сокета: %s", strerror(errno));
        return -1;
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        syslog(LOG_WARNING, "Не удалось установить SO_REUSEADDR: %s", strerror(errno));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Ошибка привязки TCP сокета: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 5) < 0) {
        syslog(LOG_ERR, "Ошибка listen на TCP сокете: %s", strerror(errno));
        close(sock);
        return -1;
    }

    syslog(LOG_INFO, "TCP listener на порту %d", port);
    return sock;
}

/**
 * Обработка входящего запроса в отдельном потоке (RFC 5905 Section 5)
 *
 * @param arg Указатель на структуру PeerRequestData
 *
 * @return void * (NULL) на успех
 */
static void *handle_peer_request_thread(void *arg) {
    PeerRequestData *data = (PeerRequestData *)arg;
    const void *buffer = data->buffer;
    size_t size = data->size;
    const char *ip = data->ip;
    const char *port = data->port;

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s запущен", ip, port);

    if (buffer == NULL || ip == NULL || port == NULL) {
        syslog(LOG_WARNING, "NULL указатель при обработке запроса клиента");
        return NULL;
    }

    if (size < 48) {
        syslog(LOG_WARNING, "Запрос клиента слишком мал: %zu байт", size);
        return NULL;
    }

    NtpPacket pkt;
    if (!parse_ntp_packet(buffer, size, &pkt)) {
        syslog(LOG_WARNING, "Ошибка парсинга запроса клиента");
        return NULL;
    }

    uint8_t li = (uint8_t)((pkt.li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    uint8_t vn = (uint8_t)((pkt.li_vn_mode & NTP_VN_MASK) >> NTP_VN_SHIFT);
    uint8_t mode = (uint8_t)(pkt.li_vn_mode & NTP_MODE_MASK);

    uint8_t response_mode = 4;
    if (mode == 1 || mode == 2) {
        response_mode = 2;
        syslog(LOG_INFO, "Symmetric mode %d от %s:%s", mode, ip, port);
    } else if (mode == 3) {
        response_mode = 4;
    } else if (mode == 5) {
        syslog(LOG_INFO, "Broadcast request от %s:%s", ip, port);
    } else {
        syslog(LOG_WARNING, "Неизвестный mode %u от %s:%s", mode, ip, port);
        return NULL;
    }

    if (vn != NTP_VN_4) {
        syslog(LOG_WARNING, "Неверная версия NTP: %u от %s:%s", vn, ip, port);
        return NULL;
    }

    if (ntp_is_kod(&pkt)) {
        char kod[5];
        kod[0] = (char)((pkt.ref_id >> 24) & 0xFF);
        kod[1] = (char)((pkt.ref_id >> 16) & 0xFF);
        kod[2] = (char)((pkt.ref_id >> 8) & 0xFF);
        kod[3] = (char)(pkt.ref_id & 0xFF);
        kod[4] = '\0';
        syslog(LOG_WARNING, "KoD пакет от %s:%s (code=%s) - отклонён", ip, port, kod);
        return NULL;
    }

    if (handle_leap_indicator(li)) {
        syslog(LOG_WARNING, "Пропускаем обработку из-за Leap Indicator");
        return NULL;
    }

    NtpTimestamp t2 = ntp_timestamp_now();

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

    uint8_t out_li = synced ? out_li_state : 3u;
    if (!synced) {
        out_stratum = 16u;
        out_ref_id = 0x4C4F434CUL;
        out_ref_ts.sec = 0;
        out_ref_ts.frac = 0;
        out_root_delay = 0;
        out_root_disp = 0;
    }

    response[0] = (uint8_t)((uint8_t)((out_li & 0x03u) << NTP_LI_SHIFT) |
                            (uint8_t)((uint8_t)NTP_VN_4 << NTP_VN_SHIFT) |
                            (uint8_t)response_mode);

    response[1] = out_stratum;
    response[2] = (uint8_t)pkt.poll;
    response[3] = (uint8_t)g_local_precision;

    write_u32be(&response[4], out_root_delay);
    write_u32be(&response[8], out_root_disp);
    write_u32be(&response[12], out_ref_id);

    write_u32be(&response[16], out_ref_ts.sec);
    write_u32be(&response[20], out_ref_ts.frac);

    write_u32be(&response[24], pkt.xmit_ts.sec);
    write_u32be(&response[28], pkt.xmit_ts.frac);

    write_u32be(&response[32], t2.sec);
    write_u32be(&response[36], t2.frac);

    NtpTimestamp t3 = ntp_timestamp_now();
    write_u32be(&response[40], t3.sec);
    write_u32be(&response[44], t3.frac);

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    char *endp = NULL;
    unsigned long port_ul = strtoul(port, &endp, 10);

    if (endp == port || *endp != '\0' || port_ul > 65535UL) {
        syslog(LOG_WARNING, "Невалидный порт от %s:%s", ip, port);
        return NULL;
    }

    client_addr.sin_port = htons((uint16_t)port_ul);

    if (inet_pton(AF_INET, ip, &client_addr.sin_addr) <= 0) {
        syslog(LOG_WARNING, "Невалидный IP от %s:%s", ip, port);
        return NULL;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_WARNING, "Ошибка создания сокетa: %s", strerror(errno));
        return NULL;
    }

    if (sendto(sock, response, sizeof(response), 0,
                (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        syslog(LOG_WARNING, "Ошибка отправки ответа клиенту: %s",
                strerror(errno));
        close(sock);
        return NULL;
    }

    close(sock);

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s завершён", ip, port);
    return NULL;
}

/**
 * Обработка входящего запроса от клиента
 *
 * @param buffer Буфер с данными запроса
 * @param size Размер буфера
 * @param ip IP-адрес клиента
 * @param port Порт клиента
 *
 * @return void
 */
void handle_client_request(const void *buffer, size_t size,
                           const char *ip, const char *port) {
    PeerRequestData *data = malloc(sizeof(PeerRequestData));
    if (data == NULL) {
        syslog(LOG_ERR, "Ошибка выделения памяти для PeerRequestData");
        return;
    }

    data->buffer = buffer;
    data->size = size;
    data->ip = ip;
    data->port = port;

    pthread_t thread;
    if (pthread_create(&thread, NULL, handle_peer_request_thread, data) != 0) {
        syslog(LOG_ERR, "Ошибка создания потока обработки запроса: %s", strerror(errno));
        free(data);
        return;
    }

    /* Очистка структуры после создания потока (не освобождать в потоке!) */
    pthread_detach(thread);
    free(data);

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s запущен", ip, port);
}

int get_tcp_socket(void) {
    return g_tcp_sock;
}

int start_tcp_listener(void) {
    pthread_mutex_lock(&g_tcp_sock_mutex);
    if (g_tcp_sock >= 0) {
        pthread_mutex_unlock(&g_tcp_sock_mutex);
        return g_tcp_sock;
    }
    g_tcp_sock = create_tcp_socket(DEFAULT_NTPQ_PORT);
    pthread_mutex_unlock(&g_tcp_sock_mutex);
    return g_tcp_sock;
}

void stop_tcp_listener(void) {
    pthread_mutex_lock(&g_tcp_sock_mutex);
    if (g_tcp_sock >= 0) {
        close(g_tcp_sock);
        g_tcp_sock = -1;
    }
    pthread_mutex_unlock(&g_tcp_sock_mutex);
}

static void handle_ntpq_request(int client_fd) {
    char buffer[1024];
    ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

    if (n <= 0) {
        if (n < 0) {
            syslog(LOG_WARNING, "Ошибка чтения от ntpq клиента: %s", strerror(errno));
        }
        close(client_fd);
        return;
    }

    buffer[n] = '\0';
    syslog(LOG_DEBUG, "ntpq запрос: %.*s", (int)n, buffer);

    char response[1024];
    int resp_len = 0;

    if (strncmp(buffer, "version", 7) == 0) {
        resp_len = snprintf(response, sizeof(response), "ntpd %s\r\n", VERSION);
    } else if (strncmp(buffer, "associations", 12) == 0) {
        pthread_mutex_lock(&g_mutex);
        bool synced = g_time_synced;
        uint8_t stratum = g_local_stratum;
        pthread_mutex_unlock(&g_mutex);
        resp_len = snprintf(response, sizeof(response),
            "ind\tassid\tstatus\tconf\treach\tcondition\tlast_event\n"
            "1\t1\t%s\t0\t377\tsynchronized\t1\n",
            synced ? (stratum <= 15 ? "6" : "3") : "3");
    } else if (strncmp(buffer, "sysinfo", 7) == 0) {
        pthread_mutex_lock(&g_mutex);
        uint8_t stratum = g_local_stratum;
        int8_t poll = g_local_poll;
        int8_t precision = g_local_precision;
        uint32_t root_delay = g_local_root_delay;
        uint32_t root_disp = g_local_root_disp;
        uint8_t local_li = g_local_li;
        pthread_mutex_unlock(&g_mutex);
        resp_len = snprintf(response, sizeof(response),
            "system peer: LOCAL(0)\n"
            "stratum: %u\n"
            "poll: %d\n"
            "precision: %d\n"
            "root delay: %u ms\n"
            "root dispersion: %u ms\n"
            "leap: %02x\n",
            stratum, (int)poll, (int)precision,
            ntohl(root_delay) >> 16,
            ntohl(root_disp) >> 16,
            local_li);
    } else if (strncmp(buffer, "quit", 4) == 0) {
        resp_len = snprintf(response, sizeof(response), "OK\r\n");
        send(client_fd, response, (size_t)resp_len, 0);
        close(client_fd);
        return;
    } else {
        resp_len = snprintf(response, sizeof(response), "OK\r\n");
    }

    if (resp_len > 0 && send(client_fd, response, (size_t)resp_len, 0) < 0) {
        syslog(LOG_WARNING, "Ошибка отправки ответа ntpq: %s", strerror(errno));
    }

    close(client_fd);
}

static void *tcp_accept_thread(void *arg) {
    (void)arg;

    syslog(LOG_INFO, "TCP accept thread запущен для ntpq");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_tcp_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_ERR, "Ошибка accept: %s", strerror(errno));
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        syslog(LOG_DEBUG, "ntpq подключение от %s:%d", client_ip, ntohs(client_addr.sin_port));

        handle_ntpq_request(client_fd);
    }

    return NULL;
}

int start_ntpq_thread(void) {
    if (g_tcp_sock < 0) {
        syslog(LOG_ERR, "TCP сокет не инициализирован");
        return -1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, tcp_accept_thread, NULL) != 0) {
        syslog(LOG_ERR, "Ошибка создания TCP потока: %s", strerror(errno));
        return -1;
    }

    pthread_detach(thread);
    syslog(LOG_INFO, "ntpq thread запущен");
    return 0;
}

