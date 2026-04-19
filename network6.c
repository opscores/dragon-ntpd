/*
 * network6.c - IPv6 network operations for NTP daemon
 *
 * Implements IPv6-specific network functions.
 * Part of RFC 5905 compliance for NTP packet handling.
 * Includes multicast support (MLDv2).
 *
 * Author: DNTPD Development Team
 * License: BSD-style
 */

#include "network6.h"
#include "ntpd.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int network6_create_socket(uint16_t port) {
  int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    syslog(LOG_ERR, "IPv6: failed to create socket: %s", strerror(errno));
    return -1;
  }

  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    syslog(LOG_WARNING, "IPv6: SO_REUSEADDR failed: %s", strerror(errno));
  }

  int v6only = 0;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) <
      0) {
    syslog(LOG_WARNING, "IPv6: IPV6_V6ONLY failed: %s", strerror(errno));
  }

  syslog(LOG_DEBUG, "IPv6: socket created (port=%u)", port);

  return sock;
}

int network6_bind_socket(int sock, const char *interface, uint16_t port) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  addr.sin6_addr = in6addr_any;

  if (interface != NULL && interface[0] != '\0') {
    unsigned int ifindex = if_nametoindex(interface);
    if (ifindex > 0) {
      addr.sin6_scope_id = ifindex;
      syslog(LOG_INFO, "IPv6: binding to interface %s (index=%u)", interface,
             ifindex);
    } else {
      syslog(LOG_WARNING, "IPv6: unknown interface: %s", interface);
    }
  }

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "IPv6: bind failed: %s", strerror(errno));
    close(sock);
    return -1;
  }

  syslog(LOG_INFO, "IPv6: bound to port %u", port);
  return 0;
}

int network6_bind_to_port(int sock, uint16_t port) {
  return network6_bind_socket(sock, NULL, port);
}

int network6_set_v6only(int sock, bool v6only) {
  int val = v6only ? 1 : 0;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
    syslog(LOG_WARNING, "IPv6: IPV6_V6ONLY failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

ssize_t network6_sendto(int sock, const void *buf, size_t len,
                        const struct sockaddr_in6 *dest) {
  if (sock < 0 || buf == NULL || dest == NULL) {
    return -1;
  }

  ssize_t sent =
      sendto(sock, buf, len, 0, (struct sockaddr *)dest, sizeof(*dest));

  if (sent < 0) {
    syslog(LOG_DEBUG, "IPv6: sendto failed: %s", strerror(errno));
  }

  return sent;
}

ssize_t network6_recvfrom(int sock, void *buf, size_t len,
                          struct sockaddr_in6 *src_addr) {
  if (sock < 0 || buf == NULL) {
    return -1;
  }

  socklen_t addr_len = sizeof(*src_addr);
  memset(src_addr, 0, sizeof(*src_addr));

  ssize_t received =
      recvfrom(sock, buf, len, 0, (struct sockaddr *)src_addr, &addr_len);

  if (received < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      syslog(LOG_DEBUG, "IPv6: recvfrom failed: %s", strerror(errno));
    }
    return -1;
  }

  return received;
}

int network6_parse_address(const char *addr_str, uint16_t port,
                           struct sockaddr_in6 *addr) {
  if (addr_str == NULL || addr == NULL) {
    return -1;
  }

  memset(addr, 0, sizeof(*addr));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(port);

  if (inet_pton(AF_INET6, addr_str, &addr->sin6_addr) <= 0) {
    return -1;
  }

  return 0;
}

size_t network6_format_address(const struct sockaddr_in6 *addr, char *buf,
                               size_t buf_size) {
  if (addr == NULL || buf == NULL || buf_size == 0) {
    return 0;
  }

  char addr_str[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &addr->sin6_addr, addr_str, sizeof(addr_str)) ==
      NULL) {
    buf[0] = '\0';
    return 0;
  }

  strncpy(buf, addr_str, buf_size - 1);
  buf[buf_size - 1] = '\0';
  return strlen(buf);
}

bool network6_is_loopback(const struct sockaddr_in6 *addr) {
  if (addr == NULL) {
    return false;
  }

  return IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr);
}

bool network6_is_multicast(const struct sockaddr_in6 *addr) {
  if (addr == NULL) {
    return false;
  }

  return IN6_IS_ADDR_MULTICAST(&addr->sin6_addr);
}

bool network6_is_link_local(const struct sockaddr_in6 *addr) {
  if (addr == NULL) {
    return false;
  }

  return IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr);
}

bool network6_addresses_equal(const struct sockaddr_in6 *a,
                              const struct sockaddr_in6 *b) {
  if (a == NULL || b == NULL) {
    return false;
  }

  return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0 &&
         a->sin6_port == b->sin6_port;
}

int network6_enable_reuseaddr(int sock) {
  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    syslog(LOG_WARNING, "IPv6: SO_REUSEADDR failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

int network6_set_timeout(int sock, int seconds) {
  struct timeval tv;
  tv.tv_sec = seconds;
  tv.tv_usec = 0;

  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    syslog(LOG_WARNING, "IPv6: SO_RCVTIMEO failed: %s", strerror(errno));
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    syslog(LOG_WARNING, "IPv6: SO_SNDTIMEO failed: %s", strerror(errno));
    return -1;
  }

  return 0;
}

int network6_join_multicast(int sock, const char *group_addr,
                            int interface_index) {
  if (sock < 0 || group_addr == NULL) {
    return -1;
  }

  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));

  if (inet_pton(AF_INET6, group_addr, &mreq.ipv6mr_multiaddr) <= 0) {
    syslog(LOG_ERR, "IPv6: invalid multicast address: %s", group_addr);
    return -1;
  }

  mreq.ipv6mr_interface =
      (interface_index > 0) ? (unsigned int)interface_index : 0;

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) <
      0) {
    syslog(LOG_ERR, "IPv6: IPV6_JOIN_GROUP failed: %s", strerror(errno));
    return -1;
  }

  syslog(LOG_INFO, "IPv6: joined multicast group %s", group_addr);
  return 0;
}

int network6_leave_multicast(int sock, const char *group_addr,
                             int interface_index) {
  if (sock < 0 || group_addr == NULL) {
    return -1;
  }

  struct ipv6_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));

  if (inet_pton(AF_INET6, group_addr, &mreq.ipv6mr_multiaddr) <= 0) {
    return -1;
  }

  mreq.ipv6mr_interface =
      (interface_index > 0) ? (unsigned int)interface_index : 0;

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) <
      0) {
    syslog(LOG_WARNING, "IPv6: IPV6_LEAVE_GROUP failed: %s", strerror(errno));
    return -1;
  }

  syslog(LOG_INFO, "IPv6: left multicast group %s", group_addr);
  return 0;
}

void network6_close_socket(int sock) {
  if (sock >= 0) {
    close(sock);
  }
}

const char *network6_get_family_name(void) { return "IPv6"; }
