/*
 * network4.h - IPv4 network operations for NTP daemon
 *
 * Implements IPv4-specific network functions:
 * - Socket creation and binding
 * - UDP packet send/receive
 * - Address parsing and formatting
 * - RFC 5905 compliance
 *
 * Author: DNTPD Development Team
 * License: BSD-style
 */

#ifndef NTPD_NETWORK4_H
#define NTPD_NETWORK4_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#define NETWORK4_MAX_ADDR_LEN 16
#define NETWORK4_PORT 123
#define NETWORK4_BROADCAST_PORT 123

#define NETWORK4_BROADCAST_ADDR "255.255.255.255"
#define NETWORK4_DEFAULT_BROADCAST_INTERVAL 64

#define NETWORK4_MIN_BROADCAST_INTERVAL 32
#define NETWORK4_MAX_BROADCAST_INTERVAL 128

typedef struct {
    struct sockaddr_in addr;
    char address_str[NETWORK4_MAX_ADDR_LEN];
    uint16_t port;
    bool is_loopback;
    bool is_multicast;
} Network4Address;

typedef struct {
    int fd;
    struct sockaddr_in local_addr;
    uint16_t port;
    bool bound;
} Network4Socket;

int network4_create_socket(uint16_t port);

int network4_bind_socket(int sock, const char* interface, uint16_t port);

int network4_bind_to_port(int sock, uint16_t port);

ssize_t network4_sendto(int sock, const void* buf, size_t len,
                        const struct sockaddr_in* dest);

ssize_t network4_recvfrom(int sock, void* buf, size_t len,
                          struct sockaddr_in* src_addr);

int network4_parse_address(const char* addr_str, uint16_t port,
                           struct sockaddr_in* addr);

size_t network4_format_address(const struct sockaddr_in* addr, char* buf,
                               size_t buf_size);

bool network4_is_loopback(const struct sockaddr_in* addr);

bool network4_is_multicast(const struct sockaddr_in* addr);

bool network4_addresses_equal(const struct sockaddr_in* a,
                              const struct sockaddr_in* b);

int network4_enable_reuseaddr(int sock);

int network4_set_timeout(int sock, int seconds);

int network4_enable_broadcast(int sock);

int network4_set_broadcast_addr(struct sockaddr_in* addr,
                                const char* broadcast_ip, uint16_t port);

void network4_close_socket(int sock);

#endif /* NTPD_NETWORK4_H */
