/*
 * network.h - Network layer for NTP daemon (IPv4/IPv6 dual-stack)
 *
 * Implements POSIX-compliant network functions with:
 * - Dual-stack support (AF_INET6 for unified IPv4/IPv6 handling)
 * - RFC 5905 compliance for NTP packet handling
 * - CERT C Security guidelines
 * - Linux Kernel coding style
 *
 * Author: NTPD Development Team
 * License: BSD-style
 */

#ifndef NTPD_NETWORK_H
#define NTPD_NETWORK_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * ============================================================================
 * Configuration Constants (POSIX-compliant, CERT C compliant)
 * ============================================================================
 */

/* Maximum socket buffer size (SO_RCVBUF/SO_SNDBUF) */
#define NETWORK_MAX_BUFFER_SIZE (4 * 1024 * 1024) /* 4 MB */

/* Maximum address string length (RFC 5952 for IPv6) */
#define NETWORK_MAX_ADDR_LEN 128

/* Maximum interface name length */
#ifndef IFNAMSIZ
#define NETWORK_MAX_IFNAME_LEN 16
#else
#define NETWORK_MAX_IFNAME_LEN IFNAMSIZ
#endif

/* Default backlog for listen() (RFC 5905 recommends 5) */
#define NETWORK_DEFAULT_BACKLOG 5

/* Default receive timeout (5 seconds) */
#define NETWORK_DEFAULT_TIMEOUT_SEC 5

/* Maximum number of multicast groups */
#define NETWORK_MAX_MULTICAST_GROUPS 16

/*
 * ============================================================================
 * Network Address Structure (RFC 5905 / RFC 5906)
 * ============================================================================
 */

/**
 * Network address abstraction supporting IPv4 and IPv6
 *
 * Uses AF_INET6 for dual-stack capability:
 * - IPv4 addresses are stored as mapped IPv6 addresses (::ffff:x.x.x.x)
 * - Allows unified socket operations with AF_INET6
 * - Compatible with standard POSIX socket API
 */
typedef struct {
  int family;    /* AF_INET or AF_INET6 (hot field) */
  uint16_t port; /* Network byte order (hot field) */
  int is_v6;     /* 1 if IPv6 address, 0 otherwise (hot field) */
  union {
    struct sockaddr_in addr_in4;  /* IPv4 address */
    struct sockaddr_in6 addr_in6; /* IPv6 address */
  } addr; /* 28 bytes, placed last for cache alignment */
} NetworkAddress;

/*
 * ============================================================================
 * Network Socket Structure
 * ============================================================================
 */

/**
 * Network socket abstraction with state tracking
 *
 * Tracks socket type (UDP/TCP), protocol preferences,
 * and multicast group memberships for RFC 5905 compliance.
 */
typedef struct {
  int fd;              /* Socket file descriptor */
  int family;          /* AF_INET or AF_INET6 */
  int type;            /* SOCK_DGRAM or SOCK_STREAM */
  int protocol;        /* IPPROTO_UDP or IPPROTO_TCP */
  uint16_t local_port; /* Local port (network byte order) */
  bool is_udp;         /* True for UDP (NTP primary) */
  bool is_tcp;         /* True for TCP (ntpq secondary) */
  bool is_dual_stack;  /* True if AF_INET6 (supports both) */

  /* Multicast support (RFC 5905 Section 5.2) */
  struct {
    bool enabled; /* Multicast enabled */
    struct {
      char address[INET6_ADDRSTRLEN]; /* Multicast address */
      uint16_t port;                  /* Multicast port */
      int ttl;                        /* Time-to-live */
      int interface_index;            /* Interface index */
    } mcast;
    struct {
      int count; /* Number of groups */
      struct {
        struct ipv6_mreq mreq; /* IPv6 multicast group */
        time_t join_time;      /* When joined */
      } groups[NETWORK_MAX_MULTICAST_GROUPS];
    } memberships;
  } multicast;

  /* Transition mechanisms (RFC 6052 / RFC 6147) */
  struct {
    bool nat64_enabled;    /* NAT64 support */
    bool dns64_enabled;    /* DNS64 support */
    char nat64_prefix[64]; /* NAT64 prefix (::ip6.arpa) */
  } transition;
} NetworkSocket;

/*
 * ============================================================================
 * Network Configuration Structure
 * ============================================================================
 */

/**
 * Network configuration for socket creation
 *
 * Supports:
 * - IPv4-only, IPv6-only, or dual-stack mode
 * - Interface binding
 * - Multicast configuration
 * - Transition mechanisms
 */
typedef struct {
  /* Address family preference */
  enum {
    NETWORK_FAMILY_IPV4_ONLY,
    NETWORK_FAMILY_IPV6_ONLY,
    NETWORK_FAMILY_DUAL_STACK /* Default: AF_INET6 */
  } family_preference;

  /* Port configuration */
  uint16_t ntp_port;  /* NTP UDP port (default: 123) */
  uint16_t ntpq_port; /* NTPQ TCP port (default: 323) */

  /* Interface binding */
  char interface[NETWORK_MAX_IFNAME_LEN]; /* Empty = any interface */

  /* Multicast configuration (RFC 5905 Section 5.2) */
  struct {
    bool enabled;                   /* Enable multicast */
    char address[INET6_ADDRSTRLEN]; /* Multicast address */
    uint16_t port;                  /* Multicast port */
    int ttl;                        /* Time-to-live (0 = default) */
    int interface_index;            /* Interface index (-1 = default) */
  } multicast;

  /* Transition mechanisms (RFC 6052 / RFC 6147) */
  struct {
    bool nat64_enabled;    /* Enable NAT64 */
    bool dns64_enabled;    /* Enable DNS64 */
    char nat64_prefix[64]; /* NAT64 prefix */
  } transition;

  /* Socket options */
  struct {
    bool reuse_address;   /* SO_REUSEADDR */
    bool ipv6_v6only;     /* IPV6_V6ONLY (false for dual-stack) */
    int recv_timeout_sec; /* Receive timeout */
    int send_buffer_size; /* SO_SNDBUF */
    int recv_buffer_size; /* SO_RCVBUF */
  } options;

  /* Flags */
  bool bind_to_interface; /* Bind to specific interface */
  bool enable_multicast;  /* Enable multicast */
  bool enable_transition; /* Enable transition mechanisms */
} NetworkConfig;

/*
 * ============================================================================
 * Network Client Information Structure
 * ============================================================================
 */

/**
 * Network client information extracted from socket operations
 *
 * Used for ACL checking, rate limiting, and logging.
 */
typedef struct {
  NetworkAddress address;                 /* Client address */
  char address_str[NETWORK_MAX_ADDR_LEN]; /* Human-readable address */
  char address_family_str[32];            /* "IPv4" or "IPv6" */
  uint16_t port;                          /* Client port */
  bool is_v6;                             /* True if IPv6 */
} NetworkClientInfo;

/*
 * ============================================================================
 * Function Declarations
 * ============================================================================
 */

/**
 * Create a network socket with dual-stack support
 *
 * Creates a socket using AF_INET6 for unified IPv4/IPv6 handling.
 * Implements RFC 5905 Section 5 for NTP packet reception.
 *
 * @param config Network configuration
 * @param error_buf Buffer for error message (NULL if not needed)
 * @param error_buf_size Size of error buffer
 *
 * @return Socket file descriptor on success, -1 on error
 *
 * @note Uses AF_INET6 for dual-stack capability (RFC 6052)
 * @note Socket is created in UDP mode (NTP primary protocol)
 * @note Caller must call close() on returned file descriptor
 */
int create_network_socket(const NetworkConfig *config, char *error_buf,
                          size_t error_buf_size);

/**
 * Bind socket to local address and port
 *
 * Binds socket to specified interface and port.
 * Supports IPv4-mapped IPv6 addresses for dual-stack.
 *
 * @param sock Socket file descriptor
 * @param config Network configuration
 *
 * @return 0 on success, -1 on error
 *
 * @note Uses SO_REUSEADDR to allow port reuse
 * @note Falls back to IPv4 if IPv6 binding fails
 */
int bind_network_socket(int sock, const NetworkConfig *config);

/**
 * Accept incoming network connection
 *
 * For UDP: extracts client address from recvfrom()
 * For TCP: uses accept() to establish connection
 *
 * @param sock Socket file descriptor
 * @param client_info Pointer to client info structure
 *
 * @return 0 on success, -1 on error
 *
 * @note For UDP, client_info is populated from recvfrom()
 * @note For TCP, client_info is populated from accept()
 */
int accept_network_connection(int sock, NetworkClientInfo *client_info);

/**
 * Send data to network address
 *
 * Supports both UDP (broadcast/multicast) and TCP (unicast).
 * Implements RFC 5905 Section 5 for NTP responses.
 *
 * @param sock Socket file descriptor
 * @param buffer Data buffer
 * @param length Data length
 * @param dest Address of destination
 *
 * @return Number of bytes sent on success, -1 on error
 *
 * @note For UDP, uses sendto()
 * @note For TCP, uses send() (connection-oriented)
 */
ssize_t sendto_network(int sock, const void *buffer, size_t length,
                       const NetworkAddress *dest);

/**
 * Receive data from network address
 *
 * Supports both UDP (broadcast/multicast) and TCP (unicast).
 * Implements RFC 5905 Section 5 for NTP requests.
 *
 * @param sock Socket file descriptor
 * @param buffer Data buffer
 * @param length Maximum data length
 * @param client_info Pointer to client info structure
 * @param flags Socket flags (MSG_PEEK, MSG_TRUNC, etc.)
 *
 * @return Number of bytes received on success, -1 on error
 *
 * @note For UDP, uses recvfrom() to get client address
 * @note For TCP, uses recv() (connection-oriented)
 */
ssize_t recvfrom_network(int sock, void *buffer, size_t length,
                         NetworkClientInfo *client_info, int flags);

/**
 * Parse network address string to NetworkAddress structure
 *
 * Supports:
 * - IPv4: "192.168.1.1"
 * - IPv6: "2001:db8::1"
 * - IPv4-mapped IPv6: "[::ffff:192.168.1.1]"
 * - Hostname resolution (getaddrinfo)
 *
 * @param addr_str Address string
 * @param port Port number (network byte order)
 * @param family Preferred address family (AF_INET or AF_INET6)
 *
 * @return 0 on success, -1 on error
 *
 * @note Returns AF_INET for IPv4 addresses
 * @note Returns AF_INET6 for IPv6 addresses
 * @note Uses inet_pton() for address parsing (RFC 5952)
 */
int parse_network_address(const char *addr_str, uint16_t port, int family,
                          NetworkAddress *addr);

/**
 * Format NetworkAddress structure to string
 *
 * Formats address for logging and display.
 * Uses RFC 5952 for IPv6 address formatting.
 *
 * @param addr Address structure
 * @param buf Output buffer
 * @param buf_size Buffer size
 *
 * @return Number of characters written (excluding null terminator)
 *
 * @note IPv4 addresses shown as-is
 * @note IPv6 addresses formatted per RFC 5952
 * @note Port appended in brackets for IPv6
 */
size_t format_network_address(const NetworkAddress *addr, char *buf,
                              size_t buf_size);

/**
 * Check if address is loopback
 *
 * @param addr Address to check
 *
 * @return True if loopback address
 */
bool is_loopback_address(const NetworkAddress *addr);

/**
 * Check if address is local (same host)
 *
 * @param addr1 First address
 * @param addr2 Second address
 *
 * @return True if addresses are equal
 */
bool addresses_equal(const NetworkAddress *addr1, const NetworkAddress *addr2);

/**
 * Close network socket
 *
 * Safely closes socket file descriptor.
 *
 * @param sock Socket file descriptor
 *
 * @note Ignores if sock < 0
 */
void close_network_socket(int sock);

/**
 * Join multicast group (IPv6 only)
 *
 * Implements RFC 5905 Section 5.2 for multicast NTP.
 * Uses MLDv2 for IPv6 multicast group management.
 *
 * @param sock Socket file descriptor
 * @param group Multicast group address
 * @param port Multicast port
 * @param ttl Time-to-live
 * @param interface_index Interface index (-1 = default)
 *
 * @return 0 on success, -1 on error
 *
 * @note Only works with AF_INET6 sockets
 * @note Uses setsockopt() with IPV6_JOIN_GROUP
 */
int join_multicast_group(int sock, const char *group, uint16_t port, int ttl,
                         int interface_index);

/**
 * Leave multicast group (IPv6 only)
 *
 * @param sock Socket file descriptor
 * @param group Multicast group address
 * @param port Multicast port
 *
 * @return 0 on success, -1 on error
 */
int leave_multicast_group(int sock, const char *group, uint16_t port);

/**
 * Set socket receive timeout
 *
 * @param sock Socket file descriptor
 * @param seconds Timeout in seconds
 *
 * @return 0 on success, -1 on error
 */
int set_network_timeout(int sock, int seconds);

/**
 * Set socket buffer sizes
 *
 * @param sock Socket file descriptor
 * @param send_size Send buffer size
 * @param recv_size Receive buffer size
 *
 * @return 0 on success, -1 on error
 */
int set_network_buffers(int sock, int send_size, int recv_size);

/**
 * Enable TCP_NODELAY for TCP sockets
 *
 * Disables Nagle's algorithm for low-latency NTPQ responses.
 *
 * @param sock Socket file descriptor
 *
 * @return 0 on success, -1 on error
 */
int enable_tcp_nodelay(int sock);

/**
 * Enable SO_REUSEADDR socket option
 *
 * Allows socket to bind to address in TIME_WAIT state.
 *
 * @param sock Socket file descriptor
 *
 * @return 0 on success, -1 on error
 */
int enable_reuse_address(int sock);

/**
 * Enable IPv6_V6ONLY socket option
 *
 * Restricts socket to IPv6-only (prevents IPv4 fallback).
 *
 * @param sock Socket file descriptor
 * @param v6only Enable IPv6-only mode
 *
 * @return 0 on success, -1 on error
 */
int enable_ipv6_v6only(int sock, bool v6only);

/**
 * Get network address family string
 *
 * @param family Address family
 *
 * @return Human-readable family name
 */
const char *network_family_name(int family);

/**
 * Get network address type string
 *
 * @param addr Address structure
 *
 * @return Human-readable address type ("IPv4" or "IPv6")
 */
const char *network_address_type(const NetworkAddress *addr);

/**
 * Initialize network configuration with defaults
 *
 * @param config Configuration structure
 *
 * @note Sets default values for all fields
 * @note family_preference defaults to NETWORK_FAMILY_DUAL_STACK
 */
void network_config_init(NetworkConfig *config);

/**
 * Validate network configuration
 *
 * @param config Configuration to validate
 *
 * @return 0 if valid, -1 if invalid
 *
 * @note Checks port ranges, interface name length, etc.
 */
int network_config_validate(const NetworkConfig *config);

/**
 * Initialize multicast group memberships
 *
 * @param sock Socket file descriptor
 * @param config Network configuration
 *
 * @return 0 on success, -1 on error
 */
int network_init_multicast(int sock, const NetworkConfig *config);

/**
 * Cleanup multicast group memberships
 *
 * @param sock Socket file descriptor
 *
 * @return 0 on success, -1 on error
 */
int network_cleanup_multicast(int sock);

/**
 * Enable NAT64 transition mechanism
 *
 * Implements RFC 6052 for IPv4-to-IPv6 translation.
 *
 * @param sock Socket file descriptor
 * @param prefix NAT64 prefix
 *
 * @return 0 on success, -1 on error
 */
int network_enable_nat64(int sock, const char *prefix);

/**
 * Enable DNS64 transition mechanism
 *
 * Implements RFC 6147 for synthetic AAAA record generation.
 *
 * @param sock Socket file descriptor
 *
 * @return 0 on success, -1 on error
 */
int network_enable_dns64(int sock);

/**
 * Check if socket supports dual-stack
 *
 * @param sock Socket file descriptor
 *
 * @return True if socket supports both IPv4 and IPv6
 */
bool network_socket_is_dual_stack(int sock);

/**
 * Get socket family
 *
 * @param sock Socket file descriptor
 *
 * @return Address family (AF_INET or AF_INET6)
 */
int network_socket_get_family(int sock);

/**
 * Get socket type
 *
 * @param sock Socket file descriptor
 *
 * @return Socket type (SOCK_DGRAM or SOCK_STREAM)
 */
int network_socket_get_type(int sock);

/**
 * Get socket protocol
 *
 * @param sock Socket file descriptor
 *
 * @return Protocol (IPPROTO_UDP or IPPROTO_TCP)
 */
int network_socket_get_protocol(int sock);

#endif /* NTPD_NETWORK_H */
