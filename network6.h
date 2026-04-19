/*
 * network6.h - IPv6 network operations for NTP daemon
 *
 * Implements IPv6-specific network functions:
 * - Socket creation and binding
 * - UDP packet send/receive
 * - Address parsing and formatting
 * - Multicast group management (MLDv2)
 * - RFC 5905 compliance
 *
 * Author: DNTPD Development Team
 * License: BSD-style
 */

#ifndef NTPD_NETWORK6_H
#define NTPD_NETWORK6_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NETWORK6_MAX_ADDR_LEN  46
#define NETWORK6_PORT           123
#define NETWORK6_MAX_MULTICAST_GROUPS 16

typedef struct {
    struct sockaddr_in6 addr;
    char address_str[NETWORK6_MAX_ADDR_LEN];
    uint16_t port;
    uint32_t scope_id;
    bool is_loopback;
    bool is_multicast;
    bool is_link_local;
} Network6Address;

typedef struct {
    int fd;
    struct sockaddr_in6 local_addr;
    uint16_t port;
    bool bound;
    bool v6only;
    int multicast_groups_count;
    struct {
        struct sockaddr_in6 group_addr;
        int interface_index;
    } multicast_groups[NETWORK6_MAX_MULTICAST_GROUPS];
} Network6Socket;

int network6_create_socket(uint16_t port);

int network6_bind_socket(int sock, const char *interface, uint16_t port);

int network6_bind_to_port(int sock, uint16_t port);

int network6_set_v6only(int sock, bool v6only);

ssize_t network6_sendto(int sock, const void *buf, size_t len,
                        const struct sockaddr_in6 *dest);

ssize_t network6_recvfrom(int sock, void *buf, size_t len,
                          struct sockaddr_in6 *src_addr);

int network6_parse_address(const char *addr_str, uint16_t port,
                           struct sockaddr_in6 *addr);

size_t network6_format_address(const struct sockaddr_in6 *addr,
                               char *buf, size_t buf_size);

bool network6_is_loopback(const struct sockaddr_in6 *addr);

bool network6_is_multicast(const struct sockaddr_in6 *addr);

bool network6_is_link_local(const struct sockaddr_in6 *addr);

bool network6_addresses_equal(const struct sockaddr_in6 *a,
                              const struct sockaddr_in6 *b);

int network6_enable_reuseaddr(int sock);

int network6_set_timeout(int sock, int seconds);

int network6_join_multicast(int sock, const char *group_addr,
                            int interface_index);

int network6_leave_multicast(int sock, const char *group_addr,
                             int interface_index);

void network6_close_socket(int sock);

const char *network6_get_family_name(void);

#endif /* NTPD_NETWORK6_H */