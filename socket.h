/*
 * socket.h - High-level socket API for NTP daemon
 *
 * This layer provides high-level socket operations abstracted from IPv4/IPv6.
 * Uses network4.h for IPv4 and network6.h for IPv6 operations.
 *
 * Architecture:
 * - socket.h/c: High-level API (create_udp_socket, get_sync_socket, etc.)
 * - network4.h/c: IPv4 specific operations
 * - network6.h/c: IPv6 specific operations
 *
 * Author: DNTPD Development Team
 * License: BSD-style
 */

#ifndef NTPD_SOCKET_H
#define NTPD_SOCKET_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* ============================================================================
 * Network Constants
 * ============================================================================
 */

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifndef INET_SOCKADDR_LEN
#define INET_SOCKADDR_LEN sizeof(struct sockaddr_in)
#endif

#ifndef INET6_SOCKADDR_LEN
#define INET6_SOCKADDR_LEN sizeof(struct sockaddr_in6)
#endif

#define NETWORK_MAX_ADDR_LEN 128
#define NETWORK_MAX_IFNAME_LEN 16
#define NETWORK_DEFAULT_BACKLOG 5
#define NETWORK_DEFAULT_TIMEOUT_SEC 5
#define NETWORK_MAX_MULTICAST_GROUPS 16
#define NETWORK_MAX_BUFFER_SIZE (4 * 1024 * 1024)

/* Address family preference */
enum { NETWORK_FAMILY_IPV4_ONLY = 0, NETWORK_FAMILY_IPV6_ONLY = 1, NETWORK_FAMILY_DUAL_STACK = 2 };

/* ============================================================================
 * Network Structures
 * ============================================================================
 */

/**
 * Network Address Structure (RFC 5905 / RFC 5906)
 */
typedef struct {
    int family;    /* AF_INET or AF_INET6 */
    uint16_t port; /* Network byte order */
    int is_v6;     /* 1 if IPv6 address, 0 if IPv4 */
    union {
        struct sockaddr_in addr_in4;  /* IPv4 address */
        struct sockaddr_in6 addr_in6; /* IPv6 address */
    } addr;
} NetworkAddress;

/**
 * Network Client Information Structure
 */
typedef struct {
    NetworkAddress address;                 /* Client address */
    char address_str[NETWORK_MAX_ADDR_LEN]; /* Human-readable address */
    char address_family_str[32];            /* "IPv4" or "IPv6" */
    uint16_t port;                          /* Client port */
    bool is_v6;                             /* True if IPv6 */
} NetworkClientInfo;

/**
 * Network Configuration Structure
 */
typedef struct {
    /* Address family preference */
    int family_preference;

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
        int ttl;                        /* Time-to-live */
        int interface_index;            /* Interface index */
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
        bool ipv6_v6only;     /* IPV6_V6ONLY */
        int recv_timeout_sec; /* Receive timeout */
        int send_buffer_size; /* SO_SNDBUF */
        int recv_buffer_size; /* SO_RCVBUF */
    } options;

    /* Flags */
    bool bind_to_interface; /* Bind to specific interface */
    bool enable_multicast;  /* Enable multicast */
    bool enable_transition; /* Enable transition mechanisms */
} NetworkConfig;

/**
 * Peer Request Data (for thread passing)
 */
typedef struct {
    void* buffer;
    size_t size;
    char ip[INET_ADDRSTRLEN];
    char port[16];
} PeerRequestData;

/* Global socket descriptor for NTP sync operations */
extern int g_sync_sock;

/* ============================================================================
 * Socket Creation and Management
 * ============================================================================
 */

/**
 * Create UDP socket and bind to port
 *
 * @param port Port number (1-65535)
 *
 * @return Socket file descriptor on success, -1 on error
 */
int create_udp_socket(int port);

/**
 * Close socket if not cached
 *
 * Does not close g_sync_sock or cached TCP socket.
 *
 * @param sock Socket file descriptor to close
 */
void close_socket(int sock);

/**
 * Get or create sync socket
 *
 * Creates socket with ephemeral port if not already created.
 *
 * @return Socket file descriptor on success, -1 on error
 */
int get_sync_socket(void);

/**
 * Create TCP socket and start listening
 *
 * @param port Port number
 *
 * @return Socket file descriptor on success, -1 on error
 */
int create_tcp_socket(int port);

/**
 * Get TCP listener socket
 *
 * @return TCP socket file descriptor, -1 if not started
 */
int get_tcp_socket(void);

/* ============================================================================
 * Request Handling
 * ============================================================================
 */

/**
 * Handle incoming NTP client request
 *
 * @param buffer Request data
 * @param size Data size
 * @param ip Client IP address string
 * @param port Client port string
 */
void handle_client_request(const void* buffer, size_t size, const char* ip, const char* port);

/* ============================================================================
 * TCP Listener Management
 * ============================================================================
 */

/**
 * Start TCP listener thread
 *
 * @return 0 on success, -1 on error
 */
int start_tcp_listener(void);
void stop_tcp_listener(void);

int start_ntpq_thread(void);

/* ============================================================================
 * Network Utility Functions
 * ============================================================================
 */

#endif /* NTPD_SOCKET_H */
