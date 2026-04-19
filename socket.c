#include "mode_handler.h"
#include "network.h"
#include "network4.h"
#include "network6.h"
#include "ntpd.h"
#include <stdlib.h>
#include <sys/select.h>

int g_sync_sock = -1;
static int g_tcp_sock = -1;
static pthread_mutex_t g_tcp_sock_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t g_last_broadcast = 0;

static int send_broadcast_response(const uint8_t* response, size_t len) {
    if (!g_cli.broadcast_mode) { return 0; }

    time_t now = time(NULL);
    if (g_cli.broadcast_interval > 0 && (now - g_last_broadcast) < g_cli.broadcast_interval) { return 0; }

    int sock = network4_create_socket(0);
    if (sock < 0) { return -1; }

    if (network4_enable_broadcast(sock) < 0) {
        network4_close_socket(sock);
        return -1;
    }

    struct sockaddr_in broadcast_addr;
    network4_set_broadcast_addr(&broadcast_addr, g_cli.broadcast_addr, NTP_PORT);

    ssize_t sent = network4_sendto(sock, response, len, &broadcast_addr);
    network4_close_socket(sock);

    if (sent < 0) {
        syslog(LOG_WARNING, "Broadcast send failed: %s", strerror(errno));
        return -1;
    }

    g_last_broadcast = now;
    syslog(LOG_INFO, "Broadcast response sent to %s:%d", g_cli.broadcast_addr ? g_cli.broadcast_addr : NETWORK4_BROADCAST_ADDR, NTP_PORT);

    return 0;
}

int get_sync_socket(void) {
    if (g_sync_sock >= 0) return g_sync_sock;

    if (g_cli.family_preference == 2) {
        g_sync_sock = network6_create_socket(0);
    } else {
        g_sync_sock = network4_create_socket(0);
    }

    if (g_sync_sock < 0) {
        syslog(LOG_ERR, "Не удалось создать сокет синхронизации: %s", strerror(errno));
        return -1;
    }

    network4_enable_reuseaddr(g_sync_sock);

    syslog(LOG_DEBUG, "Sync socket created with ephemeral port (RFC 9109)");

    return g_sync_sock;
}

int create_udp_socket(int port) {
    if (port <= 0 || port > 65535) {
        syslog(LOG_ERR, "Неверный порт для bind: %d", port);
        return -1;
    }

    int sock;
    if (g_cli.family_preference == 2) {
        sock = network6_create_socket((uint16_t)port);
    } else {
        sock = network4_create_socket((uint16_t)port);
    }

    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка создания сокета: %s", strerror(errno));
        return -1;
    }

    int ret;
    if (g_cli.family_preference == 2) {
        ret = network6_bind_socket(sock, g_cli.interface, (uint16_t)port);
    } else {
        ret = network4_bind_socket(sock, g_cli.interface, (uint16_t)port);
    }

    if (ret < 0) {
        syslog(LOG_ERR, "Ошибка привязки сокета: %s", strerror(errno));
        close_socket(sock);
        return -1;
    }

    return sock;
}

/**
 * close_socket - Close socket if not cached
 * @sock: Socket file descriptor to close
 *
 * Closes socket only if not g_sync_sock or g_tcp_sock.
 * Protects cached sockets from accidental close.
 */
void close_socket(int sock) {
    pthread_mutex_lock(&g_tcp_sock_mutex);
    int tcp_sock_copy = g_tcp_sock;
    pthread_mutex_unlock(&g_tcp_sock_mutex);

    if (sock >= 0 && sock != g_sync_sock && sock != tcp_sock_copy) { close(sock); }
}

int create_tcp_socket(int port) {
    int sock = network4_create_socket(NTP_PORT);
    if (sock < 0) {
        syslog(LOG_ERR, "Ошибка создания TCP сокета: %s", strerror(errno));
        return -1;
    }

    network4_enable_reuseaddr(sock);

    if (network4_bind_to_port(sock, (uint16_t)port) < 0) {
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
static void* handle_peer_request_thread(void* arg) {
    PeerRequestData* data = (PeerRequestData*)arg;
    const void* buffer = data->buffer;
    size_t size = data->size;
    const char* ip = data->ip;
    const char* port = data->port;

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s запущен", ip[0] ? ip : "unknown", port[0] ? port : "unknown");

    if (buffer == NULL || size < 48) {
        syslog(LOG_WARNING, "Некорректные параметры запроса");
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (ip[0] == '\0' || port[0] == '\0') {
        syslog(LOG_WARNING, "Пустой IP или порт");
        free(data->buffer);
        free(data);
        return NULL;
    }

    NtpPacket pkt;
    if (!parse_ntp_packet(buffer, size, &pkt)) {
        syslog(LOG_WARNING, "Ошибка парсинга запроса клиента");
        free(data->buffer);
        free(data);
        return NULL;
    }

    uint8_t li = (uint8_t)((pkt.li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    uint8_t vn = (uint8_t)((pkt.li_vn_mode & NTP_VN_MASK) >> NTP_VN_SHIFT);
    uint8_t mode = (uint8_t)(pkt.li_vn_mode & NTP_MODE_MASK);

    if (validate_ntp_version(vn) != 0) {
        syslog(LOG_WARNING, "Неверная версия NTP: %u от %s:%s", vn, ip, port);
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (validate_packet_authentication(buffer, size) == -ENOTSUP) {
        syslog(LOG_WARNING, "Authentication field present but auth disabled");
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (mode == NTP_MODE_CONTROL || mode == NTP_MODE_PRIVATE) {
        ModeConfig cfg;
        mode_handler_get_config(&cfg);
        if (!cfg.enable_control_messages) {
            syslog(LOG_DEBUG, "Mode %u отклонён (отключён): %s:%s", mode, ip, port);
            free(data->buffer);
            free(data);
            return NULL;
        }
    }

    if (!acl_check_client(ip, mode)) {
        syslog(LOG_WARNING, "ACL отклонён: mode=%u от %s:%s", mode, ip, port);
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (rate_limit_check(ip)) {
        syslog(LOG_WARNING, "Rate limit превышен: %s:%s", ip, port);
        free(data->buffer);
        free(data);
        return NULL;
    }

    uint8_t response_mode = 0;
    if (mode == NTP_MODE_CLIENT) {
        response_mode = NTP_MODE_SERVER;
    } else if (mode == NTP_MODE_SYMMETRIC_ACTIVE || mode == NTP_MODE_SYMMETRIC_PASSIVE) {
        response_mode = NTP_MODE_SYMMETRIC_PASSIVE;
    } else if (mode == NTP_MODE_BROADCAST) {
        if (!g_cli.broadcast_mode) {
            syslog(LOG_DEBUG, "Broadcast mode disabled, ignoring broadcast request");
            free(data->buffer);
            free(data);
            return NULL;
        }
        response_mode = NTP_MODE_BROADCAST;
    } else {
        syslog(LOG_WARNING, "Неизвестный mode %u от %s:%s", mode, ip, port);
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (response_mode == 0) {
        free(data->buffer);
        free(data);
        return NULL;
    }

    if (validate_packet_mode(response_mode, size, 48) != 0) {
        syslog(LOG_WARNING, "Response size exceeds max_response_ratio");
        free(data->buffer);
        free(data);
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
    out_stratum = mode_get_default_stratum();
    out_ref_id = mode_get_default_ref_id();
    out_ref_ts = g_local_ref_ts;
    out_root_delay = g_local_root_delay;
    out_root_disp = g_local_root_disp;
    out_li_state = mode_get_default_li();
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

    response[0] = (uint8_t)((uint8_t)((out_li & 0x03u) << NTP_LI_SHIFT) | (uint8_t)((uint8_t)NTP_VN_4 << NTP_VN_SHIFT) | (uint8_t)response_mode);

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

    errno = 0;
    char* endp = NULL;
    unsigned long port_ul = strtoul(port, &endp, 10);

    if (endp == port || *endp != '\0' || errno == ERANGE || port_ul > 65535UL) {
        syslog(LOG_WARNING, "Невалидный порт от %s:%s", ip, port);
        return NULL;
    }

    if (network4_parse_address(ip, (uint16_t)port_ul, &client_addr) < 0) {
        syslog(LOG_WARNING, "Невалидный IP от %s:%s", ip, port);
        return NULL;
    }

    int sock = network4_create_socket(0);
    if (sock < 0) {
        syslog(LOG_WARNING, "Ошибка создания сокетa: %s", strerror(errno));
        return NULL;
    }

    if (network4_sendto(sock, response, sizeof(response), &client_addr) < 0) {
        syslog(LOG_WARNING, "Ошибка отправки ответа клиенту: %s", strerror(errno));
        network4_close_socket(sock);
        return NULL;
    }

    network4_close_socket(sock);

    if (response_mode == NTP_MODE_BROADCAST) { send_broadcast_response(response, sizeof(response)); }

    rate_limit_update(ip);

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s завершён", ip, port);

    free(data->buffer);
    free(data);
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
void handle_client_request(const void* buffer, size_t size, const char* ip, const char* port) {
    PeerRequestData* data = malloc(sizeof(PeerRequestData));
    if (data == NULL) {
        syslog(LOG_ERR, "Ошибка выделения памяти для PeerRequestData");
        return;
    }

    memset(data, 0, sizeof(*data));
    data->buffer = malloc(size);
    if (data->buffer == NULL) {
        syslog(LOG_ERR, "Ошибка выделения памяти для буфера");
        free(data);
        return;
    }
    memcpy(data->buffer, buffer, size);
    data->size = size;

    snprintf(data->ip, sizeof(data->ip), "%s", ip ? ip : "");
    snprintf(data->port, sizeof(data->port), "%s", port ? port : "");

    pthread_t thread;
    if (pthread_create(&thread, NULL, handle_peer_request_thread, data) != 0) {
        syslog(LOG_ERR, "Ошибка создания потока обработки запроса: %s", strerror(errno));
        free(data->buffer);
        free(data);
        return;
    }

    pthread_detach(thread);
    free(data);

    syslog(LOG_INFO, "Поток обработки запроса от %s:%s запущен", ip, port);
}

int get_tcp_socket(void) {
    int sock_copy;
    pthread_mutex_lock(&g_tcp_sock_mutex);
    sock_copy = g_tcp_sock;
    pthread_mutex_unlock(&g_tcp_sock_mutex);
    return sock_copy;
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
        if (n < 0) { syslog(LOG_WARNING, "Ошибка чтения от ntpq клиента: %s", strerror(errno)); }
        close(client_fd);
        return;
    }

    buffer[n] = '\0';
    syslog(LOG_DEBUG, "ntpq запрос: %.*s", (int)n, buffer);

    char response[1024];
    int resp_len = 0;

    if (strncmp(buffer, "version", 7) == 0) {
        resp_len = snprintf(response, sizeof(response), "dntpd %s\r\n", VERSION);
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
                            stratum, (int)poll, (int)precision, ntohl(root_delay) >> 16, ntohl(root_disp) >> 16, local_li);
    } else if (strncmp(buffer, "quit", 4) == 0) {
        resp_len = snprintf(response, sizeof(response), "OK\r\n");
        send(client_fd, response, (size_t)resp_len, 0);
        close(client_fd);
        return;
    } else {
        resp_len = snprintf(response, sizeof(response), "OK\r\n");
    }

    if (resp_len > 0 && send(client_fd, response, (size_t)resp_len, 0) < 0) { syslog(LOG_WARNING, "Ошибка отправки ответа ntpq: %s", strerror(errno)); }

    close(client_fd);
}

static void* tcp_accept_thread(void* arg) {
    (void)arg;

    syslog(LOG_INFO, "TCP accept thread запущен для ntpq");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_tcp_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) { continue; }
            syslog(LOG_ERR, "Ошибка accept: %s", strerror(errno));
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        network4_format_address(&client_addr, client_ip, sizeof(client_ip));
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
