/*
 * network4.c - IPv4 network operations for NTP daemon
 *
 * Implements IPv4-specific network functions.
 * Part of RFC 5905 compliance for NTP packet handling.
 *
 * Author: DNTPD Development Team
 * License: BSD-style
 */

#include "network4.h"
#include "ntpd.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int network4_create_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_ERR, "IPv4: failed to create socket: %s", strerror(errno));
        return -1;
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) { syslog(LOG_WARNING, "IPv4: SO_REUSEADDR failed: %s", strerror(errno)); }

    syslog(LOG_DEBUG, "IPv4: socket created (port=%u)", port);

    return sock;
}

int network4_bind_socket(int sock, const char* interface, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (interface != NULL && interface[0] != '\0') {
        if (inet_pton(AF_INET, interface, &addr.sin_addr) <= 0) {
            syslog(LOG_ERR, "IPv4: invalid interface address: %s", interface);
            return -1;
        }
        syslog(LOG_INFO, "IPv4: binding to interface %s", interface);
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "IPv4: bind failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    syslog(LOG_INFO, "IPv4: bound to port %u", port);
    return 0;
}

int network4_bind_to_port(int sock, uint16_t port) {
    return network4_bind_socket(sock, NULL, port);
}

ssize_t network4_sendto(int sock, const void* buf, size_t len, const struct sockaddr_in* dest) {
    if (sock < 0 || buf == NULL || dest == NULL) { return -1; }

    ssize_t sent = sendto(sock, buf, len, 0, (struct sockaddr*)dest, sizeof(*dest));

    if (sent < 0) { syslog(LOG_DEBUG, "IPv4: sendto failed: %s", strerror(errno)); }

    return sent;
}

ssize_t network4_recvfrom(int sock, void* buf, size_t len, struct sockaddr_in* src_addr) {
    if (sock < 0 || buf == NULL) { return -1; }

    socklen_t addr_len = sizeof(*src_addr);
    memset(src_addr, 0, sizeof(*src_addr));

    ssize_t received = recvfrom(sock, buf, len, 0, (struct sockaddr*)src_addr, &addr_len);

    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) { syslog(LOG_DEBUG, "IPv4: recvfrom failed: %s", strerror(errno)); }
        return -1;
    }

    return received;
}

int network4_parse_address(const char* addr_str, uint16_t port, struct sockaddr_in* addr) {
    if (addr_str == NULL || addr == NULL) { return -1; }

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if (inet_pton(AF_INET, addr_str, &addr->sin_addr) <= 0) { return -1; }

    return 0;
}

size_t network4_format_address(const struct sockaddr_in* addr, char* buf, size_t buf_size) {
    if (addr == NULL || buf == NULL || buf_size == 0) { return 0; }

    char addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr->sin_addr, addr_str, sizeof(addr_str)) == NULL) {
        buf[0] = '\0';
        return 0;
    }

    strncpy(buf, addr_str, buf_size - 1);
    buf[buf_size - 1] = '\0';
    return strlen(buf);
}

bool network4_is_loopback(const struct sockaddr_in* addr) {
    if (addr == NULL) { return false; }

    in_addr_t ina = ntohl(addr->sin_addr.s_addr);
    return (ina >> 24) == 127;
}

bool network4_is_multicast(const struct sockaddr_in* addr) {
    if (addr == NULL) { return false; }

    in_addr_t ina = ntohl(addr->sin_addr.s_addr);
    return (ina >> 28) == 0xE;
}

bool network4_addresses_equal(const struct sockaddr_in* a, const struct sockaddr_in* b) {
    if (a == NULL || b == NULL) { return false; }

    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

int network4_enable_reuseaddr(int sock) {
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        syslog(LOG_WARNING, "IPv4: SO_REUSEADDR failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int network4_set_timeout(int sock, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_WARNING, "IPv4: SO_RCVTIMEO failed: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        syslog(LOG_WARNING, "IPv4: SO_SNDTIMEO failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

void network4_close_socket(int sock) {
    if (sock >= 0) { close(sock); }
}

int network4_enable_broadcast(int sock) {
    if (sock < 0) { return -1; }

    int broadcast = 1;
    socklen_t optlen = sizeof(broadcast);

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, optlen) < 0) {
        syslog(LOG_WARNING, "IPv4: SO_BROADCAST failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int network4_set_broadcast_addr(struct sockaddr_in* addr, const char* broadcast_ip, uint16_t port) {
    if (addr == NULL) { return -1; }

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);

    if (broadcast_ip != NULL && broadcast_ip[0] != '\0') {
        if (inet_pton(AF_INET, broadcast_ip, &addr->sin_addr) <= 0) {
            syslog(LOG_WARNING, "IPv4: invalid broadcast address '%s', using default", broadcast_ip);
            addr->sin_addr.s_addr = htonl(INADDR_BROADCAST);
        }
    } else {
        addr->sin_addr.s_addr = htonl(INADDR_BROADCAST);
    }

    return 0;
}