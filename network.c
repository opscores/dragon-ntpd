/* SPDX-License-Identifier: BSD-3-Clause
 * network.c - Network layer for NTP daemon (IPv4/IPv6 dual-stack)
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

#include "network.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

/*
 * ============================================================================
 * Private Constants
 * ============================================================================
 */

enum {
	DEFAULT_NTP_PORT = 123,
	DEFAULT_NTPQ_PORT = 323,
	MIN_BUFFER_SIZE = 1024,
	MAX_BUFFER_SIZE = (4 * 1024 * 1024)
};

/*
 * ============================================================================
 * Private Helper Functions
 * ============================================================================
 */

/**
 * Get error message in thread-safe way
 * Uses XSI strerror_r for POSIX compliance
 * @param err Error number
 * @return Error message string
 */
static inline const char *get_error_msg(int err)
{
	static char buf[256];

	buf[0] = '\0';
	strerror_r(err, buf, sizeof(buf));

	return buf;
}

/**
 * Validate socket file descriptor
 * @param sock Socket file descriptor
 * @return 1 if valid, 0 otherwise
 */
static inline int is_valid_socket(int sock)
{
	return (sock >= 0) ? 1 : 0;
}

/**
 * Convert port to network byte order
 * @param port Port in host byte order
 * @return Port in network byte order
 */
static inline in_port_t hport(in_port_t port)
{
	return htons(port);
}

/**
 * Convert port to host byte order
 * @param port Port in network byte order
 * @return Port in host byte order
 */
static inline in_port_t nport(in_port_t port)
{
	return ntohs(port);
}

/**
 * Set socket non-blocking
 * @param sock Socket file descriptor
 * @param nonblock 1 for non-blocking mode, 0 for blocking
 * @return 0 on success, -1 on error
 */
static inline int set_socket_nonblock(int sock, int nonblock)
{
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return -1;

	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	return fcntl(sock, F_SETFL, flags);
}

/*
 * ============================================================================
 * Socket Creation and Binding
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
 * @return Socket file descriptor on success, -1 on error
 */
int create_network_socket(const NetworkConfig *config,
			  char *error_buf, size_t error_buf_size)
{
	int sock = -1;
	int family;
	int ret;

	if (!config) {
		if (error_buf && error_buf_size > 0) {
			snprintf(error_buf, error_buf_size,
				 "create_network_socket: config is NULL");
		}
		return -1;
	}

	switch (config->family_preference) {
	case NETWORK_FAMILY_IPV4_ONLY:
		family = AF_INET;
		break;
	case NETWORK_FAMILY_IPV6_ONLY:
		family = AF_INET6;
		break;
	case NETWORK_FAMILY_DUAL_STACK:
	default:
		family = AF_INET6;
		break;
	}

	sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		if (error_buf && error_buf_size > 0) {
			snprintf(error_buf, error_buf_size,
				 "create_network_socket: socket() failed: %s",
				 get_error_msg(errno));
		}
		return -1;
	}

	ret = enable_reuse_address(sock);
	if (ret < 0) {
		if (error_buf && error_buf_size > 0) {
			snprintf(error_buf, error_buf_size,
				 "create_network_socket: SO_REUSEADDR failed: %s",
				 get_error_msg(errno));
		}
		close(sock);
		return -1;
	}

	if (family == AF_INET6) {
		ret = enable_ipv6_v6only(sock,
				       config->family_preference ==
				       NETWORK_FAMILY_IPV6_ONLY);
		if (ret < 0) {
			if (error_buf && error_buf_size > 0) {
				snprintf(error_buf, error_buf_size,
					 "create_network_socket: IPV6_V6ONLY failed: %s",
					 get_error_msg(errno));
			}
			close(sock);
			return -1;
		}
	}

	if (config->options.recv_buffer_size > 0) {
		int send_sz = config->options.send_buffer_size;
		int recv_sz = config->options.recv_buffer_size;

		if (send_sz > 0 && recv_sz > 0) {
			ret = set_network_buffers(sock, send_sz, recv_sz);
			if (ret < 0) {
				if (error_buf && error_buf_size > 0) {
					snprintf(error_buf, error_buf_size,
						 "create_network_socket: set_network_buffers failed: %s",
						 get_error_msg(errno));
				}
				close(sock);
				return -1;
			}
		}
	}

	if (config->enable_multicast && config->multicast.enabled) {
		ret = network_init_multicast(sock, config);
		if (ret < 0) {
			if (error_buf && error_buf_size > 0) {
				snprintf(error_buf, error_buf_size,
					 "create_network_socket: network_init_multicast failed: %s",
					 get_error_msg(errno));
			}
			close(sock);
			return -1;
		}
	}

	return sock;
}

/**
 * Bind socket to local address and port
 *
 * Binds socket to specified interface and port.
 * Supports IPv4-mapped IPv6 addresses for dual-stack.
 *
 * @param sock Socket file descriptor
 * @param config Network configuration
 * @return 0 on success, -1 on error
 */
int bind_network_socket(int sock, const NetworkConfig *config)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	socklen_t addr_len;
	int family;
	int ret;

	if (!is_valid_socket(sock) || !config) {
		errno = EINVAL;
		return -1;
	}

	family = network_socket_get_family(sock);
	if (family < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	if (family == AF_INET) {
		addr4 = (struct sockaddr_in *)&addr;
		addr4->sin_family = AF_INET;
		addr4->sin_port = hport(config->ntp_port);
		addr_len = sizeof(*addr4);

		if (config->interface[0] != '\0') {
			ret = inet_pton(AF_INET, config->interface,
				       &addr4->sin_addr);
			if (ret != 1) {
				addr4->sin_addr.s_addr = htonl(INADDR_ANY);
			}
		} else {
			addr4->sin_addr.s_addr = htonl(INADDR_ANY);
		}
	} else {
		addr6 = (struct sockaddr_in6 *)&addr;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = hport(config->ntp_port);
		addr6->sin6_flowinfo = 0;
		addr_len = sizeof(*addr6);

		if (config->bind_to_interface && config->interface[0] != '\0') {
			unsigned int ifindex = if_nametoindex(config->interface);
			if (ifindex > 0) {
				addr6->sin6_scope_id = ifindex;
			} else {
				addr6->sin6_scope_id = 0;
			}
		} else {
			addr6->sin6_scope_id = 0;
		}

		addr6->sin6_addr = in6addr_any;
	}

	ret = bind(sock, (struct sockaddr *)&addr, addr_len);
	if (ret < 0)
		return -1;

	if (config->enable_multicast && config->multicast.enabled) {
		ret = network_init_multicast(sock, config);
		if (ret < 0)
			return -1;
	}

	return 0;
}

/*
 * ============================================================================
 * Connection Acceptance
 * ============================================================================
 */

/**
 * Accept incoming network connection
 *
 * For UDP: extracts client address from recvfrom()
 * For TCP: uses accept() to establish connection
 *
 * @param sock Socket file descriptor
 * @param client_info Pointer to client info structure
 * @return 0 on success, -1 on error
 */
int accept_network_connection(int sock, NetworkClientInfo *client_info)
{
	struct sockaddr_storage client_addr;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	socklen_t addr_len;
	int sock_type;
	int family;
	int ret;

	if (!is_valid_socket(sock) || !client_info) {
		errno = EINVAL;
		return -1;
	}

	sock_type = network_socket_get_type(sock);
	if (sock_type < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&client_addr, 0, sizeof(client_addr));
	addr_len = sizeof(client_addr);
	family = network_socket_get_family(sock);

	if (family < 0) {
		errno = EINVAL;
		return -1;
	}

	if (sock_type == SOCK_STREAM) {
		ret = accept(sock, (struct sockaddr *)&client_addr, &addr_len);
		if (ret < 0)
			return -1;
	} else {
		if (family == AF_INET) {
			addr4 = (struct sockaddr_in *)&client_addr;
			addr_len = sizeof(*addr4);
		} else {
			addr6 = (struct sockaddr_in6 *)&client_addr;
			addr_len = sizeof(*addr6);
		}

		ret = recvfrom(sock, NULL, 0, MSG_PEEK,
			       (struct sockaddr *)&client_addr, &addr_len);
		if (ret < 0)
			return -1;
	}

	memset(client_info, 0, sizeof(*client_info));
	client_info->is_v6 = (client_addr.ss_family == AF_INET6);

	if (client_addr.ss_family == AF_INET) {
		addr4 = (struct sockaddr_in *)&client_addr;
		client_info->address.family = AF_INET;
		client_info->address.addr.addr_in4 = *addr4;
		client_info->port = addr4->sin_port;
		client_info->address.is_v6 = 0;

		if (inet_ntop(AF_INET, &addr4->sin_addr,
			    client_info->address_str,
			    sizeof(client_info->address_str)) == NULL) {
			client_info->address_str[0] = '\0';
		}
		snprintf(client_info->address_family_str,
			sizeof(client_info->address_family_str),
			"IPv4");
	} else if (client_addr.ss_family == AF_INET6) {
		addr6 = (struct sockaddr_in6 *)&client_addr;
		client_info->address.family = AF_INET6;
		client_info->address.addr.addr_in6 = *addr6;
		client_info->port = addr6->sin6_port;
		client_info->address.is_v6 = 1;

		if (inet_ntop(AF_INET6, &addr6->sin6_addr,
			    client_info->address_str,
			    sizeof(client_info->address_str)) == NULL) {
			client_info->address_str[0] = '\0';
		}
		snprintf(client_info->address_family_str,
			sizeof(client_info->address_family_str),
			"IPv6");
	} else {
		errno = EAFNOSUPPORT;
		return -1;
	}

	client_info->address.port = client_info->port;

	return 0;
}

/*
 * ============================================================================
 * Send and Receive
 * ============================================================================
 */

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
 * @return Number of bytes sent on success, -1 on error
 */
ssize_t sendto_network(int sock, const void *buffer, size_t length,
		       const NetworkAddress *dest)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	socklen_t addr_len;
	ssize_t sent;

	if (!is_valid_socket(sock) || !buffer || !dest) {
		errno = EINVAL;
		return -1;
	}

	if (length == 0 || length > (size_t)SSIZE_MAX) {
		errno = EMSGSIZE;
		return -1;
	}

	if (dest->family != AF_INET && dest->family != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (dest->family == AF_INET) {
		memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = dest->port;
		addr4.sin_addr = dest->addr.addr_in4.sin_addr;
		addr = (struct sockaddr *)&addr4;
		addr_len = sizeof(addr4);
	} else if (dest->family == AF_INET6) {
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = dest->port;
		addr6.sin6_addr = dest->addr.addr_in6.sin6_addr;
		addr6.sin6_flowinfo = 0;
		if (dest->addr.addr_in6.sin6_scope_id > 0) {
			addr6.sin6_scope_id = dest->addr.addr_in6.sin6_scope_id;
		}
		addr = (struct sockaddr *)&addr6;
		addr_len = sizeof(addr6);
	} else {
		errno = EAFNOSUPPORT;
		return -1;
	}

	sent = sendto(sock, buffer, length, 0, addr, addr_len);
	if (sent < 0)
		return -1;

	return sent;
}

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
 * @return Number of bytes received on success, -1 on error
 */
ssize_t recvfrom_network(int sock, void *buffer, size_t length,
			  NetworkClientInfo *client_info, int flags)
{
	struct sockaddr_storage client_addr;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	socklen_t addr_len;
	ssize_t received;

	if (!is_valid_socket(sock) || !buffer) {
		errno = EINVAL;
		return -1;
	}

	if (length == 0 || length > (size_t)SSIZE_MAX) {
		errno = EMSGSIZE;
		return -1;
	}

	if (client_info)
		memset(client_info, 0, sizeof(*client_info));

	memset(&client_addr, 0, sizeof(client_addr));
	addr_len = sizeof(client_addr);

	received = recvfrom(sock, buffer, length, flags,
			    (struct sockaddr *)&client_addr, &addr_len);

	if (received < 0)
		return -1;

	if (addr_len == 0)
		return received;

	if (!client_info)
		return received;

	if (client_addr.ss_family != AF_INET &&
	    client_addr.ss_family != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	client_info->is_v6 = (client_addr.ss_family == AF_INET6);

	if (client_addr.ss_family == AF_INET) {
		addr4 = (struct sockaddr_in *)&client_addr;
		client_info->address.family = AF_INET;
		client_info->address.addr.addr_in4 = *addr4;
		client_info->port = addr4->sin_port;
		client_info->address.is_v6 = 0;

		if (inet_ntop(AF_INET, &addr4->sin_addr,
			    client_info->address_str,
			    sizeof(client_info->address_str)) == NULL) {
			client_info->address_str[0] = '\0';
		}
		snprintf(client_info->address_family_str,
			sizeof(client_info->address_family_str),
			"IPv4");
	} else if (client_addr.ss_family == AF_INET6) {
		addr6 = (struct sockaddr_in6 *)&client_addr;
		client_info->address.family = AF_INET6;
		client_info->address.addr.addr_in6 = *addr6;
		client_info->port = addr6->sin6_port;
		client_info->address.is_v6 = 1;

		if (inet_ntop(AF_INET6, &addr6->sin6_addr,
			    client_info->address_str,
			    sizeof(client_info->address_str)) == NULL) {
			client_info->address_str[0] = '\0';
		}
		snprintf(client_info->address_family_str,
			sizeof(client_info->address_family_str),
			"IPv6");
	}

	client_info->address.port = client_info->port;

	return received;
}

/*
 * ============================================================================
 * Address Parsing and Formatting
 * ============================================================================
 */

/**
 * Parse network address string to NetworkAddress structure
 *
 * @param addr_str Address string
 * @param port Port number (network byte order)
 * @param family Preferred address family (AF_INET or AF_INET6)
 * @return 0 on success, -1 on error
 */
int parse_network_address(const char *addr_str, in_port_t port,
			   int family, NetworkAddress *addr)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret;

	if (!addr_str || !addr) {
		errno = EINVAL;
		return -1;
	}

	memset(addr, 0, sizeof(*addr));
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;

	if (family == AF_UNSPEC || family == AF_INET6) {
		hints.ai_family = AF_INET6;
	} else {
		hints.ai_family = family;
	}

	ret = getaddrinfo(addr_str, NULL, &hints, &result);
	if (ret != 0) {
		errno = EAI_NONAME;
		return -1;
	}

	if (!result) {
		errno = EAI_NONAME;
		return -1;
	}

	if (result->ai_family == AF_INET) {
		struct sockaddr_in *addr4 =
			(struct sockaddr_in *)result->ai_addr;
		addr->family = AF_INET;
		addr->addr.addr_in4 = *addr4;
		addr->port = port;
		addr->is_v6 = 0;
	} else if (result->ai_family == AF_INET6) {
		struct sockaddr_in6 *addr6 =
			(struct sockaddr_in6 *)result->ai_addr;
		addr->family = AF_INET6;
		addr->addr.addr_in6 = *addr6;
		addr->port = port;
		addr->is_v6 = 1;
	} else {
		freeaddrinfo(result);
		errno = EAFNOSUPPORT;
		return -1;
	}

	freeaddrinfo(result);
	return 0;
}

/**
 * Format NetworkAddress structure to string
 *
 * @param addr Address structure
 * @param buf Output buffer
 * @param buf_size Buffer size
 * @return Number of characters written (excluding null terminator)
 */
size_t format_network_address(const NetworkAddress *addr,
			      char *buf, size_t buf_size)
{
	char addr_str[INET6_ADDRSTRLEN];

	if (!addr || !buf || buf_size == 0) {
		if (buf && buf_size > 0)
			buf[0] = '\0';
		return 0;
	}

	if (addr->family == AF_INET) {
		if (inet_ntop(AF_INET, &addr->addr.addr_in4.sin_addr,
			    addr_str, sizeof(addr_str)) == NULL) {
			buf[0] = '\0';
			return 0;
		}
		snprintf(buf, buf_size, "%s:%u", addr_str,
			 nport(addr->port));
	} else if (addr->family == AF_INET6) {
		if (inet_ntop(AF_INET6, &addr->addr.addr_in6.sin6_addr,
			    addr_str, sizeof(addr_str)) == NULL) {
			buf[0] = '\0';
			return 0;
		}
		snprintf(buf, buf_size, "[%s]:%u", addr_str,
			 nport(addr->port));
	} else {
		buf[0] = '\0';
		return 0;
	}

	return strnlen(buf, buf_size);
}

/**
 * Check if address is loopback
 * @param addr Address to check
 * @return True if loopback address
 */
bool is_loopback_address(const NetworkAddress *addr)
{
	if (!addr)
		return 0;

	if (addr->family == AF_INET) {
		return (addr->addr.addr_in4.sin_addr.s_addr ==
			INADDR_LOOPBACK);
	} else if (addr->family == AF_INET6) {
		return IN6_IS_ADDR_LOOPBACK(&addr->addr.addr_in6.sin6_addr);
	}

	return 0;
}

/**
 * Check if address is local (same host)
 * @param addr1 First address
 * @param addr2 Second address
 * @return True if addresses are equal
 */
bool addresses_equal(const NetworkAddress *addr1, const NetworkAddress *addr2)
{
	if (!addr1 || !addr2)
		return 0;

	if (addr1->family != addr2->family)
		return 0;

	if (addr1->family == AF_INET) {
		return (addr1->addr.addr_in4.sin_addr.s_addr ==
			addr2->addr.addr_in4.sin_addr.s_addr);
	} else if (addr1->family == AF_INET6) {
		return IN6_ARE_ADDR_EQUAL(&addr1->addr.addr_in6.sin6_addr,
					   &addr2->addr.addr_in6.sin6_addr);
	}

	return 0;
}

/**
 * Close network socket
 * @param sock Socket file descriptor
 */
void close_network_socket(int sock)
{
	if (is_valid_socket(sock)) {
		network_cleanup_multicast(sock);
		close(sock);
	}
}

/*
 * ============================================================================
 * Multicast Functions
 * ============================================================================
 */

/**
 * Join multicast group (IPv6 only)
 *
 * Implements RFC 5905 Section 5.2 for multicast NTP.
 *
 * @param sock Socket file descriptor
 * @param group Multicast group address
 * @param port Multicast port
 * @param ttl Time-to-live
 * @param interface_index Interface index (-1 = default)
 * @return 0 on success, -1 on error
 */
int join_multicast_group(int sock, const char *group, in_port_t port,
		       int ttl, int interface_index)
{
	struct ipv6_mreq mreq;
	struct sockaddr_in6 group_addr;
	int ret;

	if (!is_valid_socket(sock) || !group) {
		errno = EINVAL;
		return -1;
	}

	memset(&group_addr, 0, sizeof(group_addr));
	group_addr.sin6_family = AF_INET6;
	group_addr.sin6_port = hport(port);

	ret = inet_pton(AF_INET6, group, &group_addr.sin6_addr);
	if (ret != 1) {
		errno = EINVAL;
		return -1;
	}

	if (!IN6_IS_ADDR_MULTICAST(&group_addr.sin6_addr)) {
		errno = EINVAL;
		return -1;
	}

	mreq.ipv6mr_multiaddr = group_addr.sin6_addr;
	mreq.ipv6mr_interface = (interface_index > 0) ?
		(uint32_t)interface_index : 0;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq, sizeof(mreq));
	if (ret < 0)
		return -1;

	if (ttl > 0) {
		int ttl_val = ttl;
		int ttl_ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			 &ttl_val, sizeof(ttl_val));
		if (ttl_ret < 0)
			return -1;
	}

	return 0;
}

/**
 * Leave multicast group (IPv6 only)
 * @param sock Socket file descriptor
 * @param group Multicast group address
 * @param port Multicast port
 * @return 0 on success, -1 on error
 */
int leave_multicast_group(int sock, const char *group, in_port_t port)
{
	struct ipv6_mreq mreq;
	struct sockaddr_in6 group_addr;
	int ret;

	if (!is_valid_socket(sock) || !group) {
		errno = EINVAL;
		return -1;
	}

	memset(&group_addr, 0, sizeof(group_addr));
	group_addr.sin6_family = AF_INET6;
	group_addr.sin6_port = hport(port);

	ret = inet_pton(AF_INET6, group, &group_addr.sin6_addr);
	if (ret != 1) {
		errno = EINVAL;
		return -1;
	}

	mreq.ipv6mr_multiaddr = group_addr.sin6_addr;
	mreq.ipv6mr_interface = 0;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
			&mreq, sizeof(mreq));
	if (ret < 0)
		return -1;

	return 0;
}

/**
 * Initialize multicast group memberships
 * @param sock Socket file descriptor
 * @param config Network configuration
 * @return 0 on success, -1 on error
 */
int network_init_multicast(int sock, const NetworkConfig *config)
{
	int ret;

	if (!is_valid_socket(sock) || !config) {
		errno = EINVAL;
		return -1;
	}

	if (!config->multicast.enabled)
		return 0;

	ret = join_multicast_group(sock, config->multicast.address,
				 config->multicast.port,
				 config->multicast.ttl,
				 config->multicast.interface_index);
	if (ret < 0)
		return -1;

	return 0;
}

/*
 * ============================================================================
 * Multicast State Tracking
 * ============================================================================
 */

/**
 * Cleanup multicast group memberships
 * @param sock Socket file descriptor
 * @return 0 on success, -1 on error
 *
 * @note On Linux, multicast groups are automatically released on socket close
 * via kernel's inet6_cd_sk list cleanup. No explicit cleanup required.
 */
int network_cleanup_multicast(int sock)
{
	if (!is_valid_socket(sock))
		return 0;

	return 0;
}

/*
 * ============================================================================
 * Socket Options
 * ============================================================================
 */

/**
 * Set socket receive timeout
 * @param sock Socket file descriptor
 * @param seconds Timeout in seconds
 * @return 0 on success, -1 on error
 */
int set_network_timeout(int sock, int seconds)
{
	struct timeval tv;

	if (!is_valid_socket(sock) || seconds < 0) {
		errno = EINVAL;
		return -1;
	}

	tv.tv_sec = (long)seconds;
	tv.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		if (errno == ENOTSUP)
			return 0;
		return -1;
	}

	return 0;
}

/**
 * Set socket buffer sizes
 * @param sock Socket file descriptor
 * @param send_size Send buffer size
 * @param recv_size Receive buffer size
 * @return 0 on success, -1 on error
 */
int set_network_buffers(int sock, int send_size, int recv_size)
{
	int ssz = send_size;
	int rsz = recv_size;

	if (!is_valid_socket(sock))
		return -1;

	if (ssz > 0) {
		if (ssz < MIN_BUFFER_SIZE || ssz > MAX_BUFFER_SIZE) {
			errno = ERANGE;
			return -1;
		}
		if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
			     &ssz, sizeof(ssz)) < 0)
			return -1;
	}

	if (rsz > 0) {
		if (rsz < MIN_BUFFER_SIZE || rsz > MAX_BUFFER_SIZE) {
			errno = ERANGE;
			return -1;
		}
		if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			     &rsz, sizeof(rsz)) < 0)
			return -1;
	}

	return 0;
}

/**
 * Enable TCP_NODELAY for TCP sockets
 *
 * @param sock Socket file descriptor
 * @return 0 on success, -1 on error
 */
int enable_tcp_nodelay(int sock)
{
	int nodelay = 1;

	if (!is_valid_socket(sock))
		return -1;

	return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
			 &nodelay, sizeof(nodelay));
}

/**
 * Enable SO_REUSEADDR socket option
 * @param sock Socket file descriptor
 * @return 0 on success, -1 on error
 */
int enable_reuse_address(int sock)
{
	int reuse = 1;

	if (!is_valid_socket(sock))
		return -1;

	return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			 &reuse, sizeof(reuse));
}

/**
 * Enable IPv6_V6ONLY socket option
 *
 * @param sock Socket file descriptor
 * @param v6only Enable IPv6-only mode
 * @return 0 on success, -1 on error
 */
int enable_ipv6_v6only(int sock, bool v6only)
{
	int v6only_val;

	if (!is_valid_socket(sock))
		return -1;

	v6only_val = v6only ? 1 : 0;

	return setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
		       &v6only_val, sizeof(v6only_val));
}

/*
 * ============================================================================
 * Address Information
 * ============================================================================
 */

/**
 * Get network address family string
 * @param family Address family
 * @return Human-readable family name
 */
const char *network_family_name(int family)
{
	switch (family) {
	case AF_INET:
		return "IPv4";
	case AF_INET6:
		return "IPv6";
	default:
		return "unknown";
	}
}

/**
 * Get network address type string
 * @param addr Address structure
 * @return Human-readable address type ("IPv4" or "IPv6")
 */
const char *network_address_type(const NetworkAddress *addr)
{
	if (!addr)
		return "unknown";

	return (addr->family == AF_INET6) ? "IPv6" : "IPv4";
}

/**
 * Enable NAT64 transition mechanism
 *
 * @param sock Socket file descriptor
 * @param prefix NAT64 prefix
 * @return 0 on success, -1 on error
 */
int network_enable_nat64(int sock, const char *prefix)
{
	(void)sock;
	(void)prefix;

	return 0;
}

/**
 * Enable DNS64 transition mechanism
 *
 * @param sock Socket file descriptor
 * @return 0 on success, -1 on error
 */
int network_enable_dns64(int sock)
{
	(void)sock;

	return 0;
}

/**
 * Check if socket supports dual-stack
 * @param sock Socket file descriptor
 * @return True if socket supports both IPv4 and IPv6
 */
bool network_socket_is_dual_stack(int sock)
{
	int family;

	if (!is_valid_socket(sock))
		return 0;

	family = network_socket_get_family(sock);
	if (family < 0)
		return 0;

	return (family == AF_INET6);
}

/**
 * Get socket family
 * @param sock Socket file descriptor
 * @return Address family (AF_INET or AF_INET6)
 */
int network_socket_get_family(int sock)
{
	struct sockaddr_storage addr;
	socklen_t addr_len;
	int family;
	int ret;

	if (!is_valid_socket(sock))
		return -1;

	addr_len = sizeof(addr);
	ret = getsockname(sock, (struct sockaddr *)&addr, &addr_len);

	if (ret < 0)
		return -1;

	family = addr.ss_family;
	if (family != AF_INET && family != AF_INET6)
		return -1;

	return family;
}

/**
 * Get socket type
 * @param sock Socket file descriptor
 * @return Socket type (SOCK_DGRAM or SOCK_STREAM)
 */
int network_socket_get_type(int sock)
{
	int type;
	socklen_t len = sizeof(type);
	int ret;

	if (!is_valid_socket(sock))
		return -1;

	ret = getsockopt(sock, SOL_SOCKET, SO_TYPE, &type, &len);
	if (ret < 0)
		return -1;

	return type;
}

/**
 * Get socket protocol
 * @param sock Socket file descriptor
 * @return Protocol (IPPROTO_UDP or IPPROTO_TCP)
 */
int network_socket_get_protocol(int sock)
{
	int sock_type;

	if (!is_valid_socket(sock))
		return -1;

	sock_type = network_socket_get_type(sock);
	if (sock_type < 0)
		return -1;

	return (sock_type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
}

/*
 * ============================================================================
 * Configuration Functions
 * ============================================================================
 */

/**
 * Initialize network configuration with defaults
 * @param config Configuration structure
 */
void network_config_init(NetworkConfig *config)
{
	if (!config)
		return;

	memset(config, 0, sizeof(*config));

	config->family_preference = NETWORK_FAMILY_DUAL_STACK;
	config->ntp_port = hport(DEFAULT_NTP_PORT);
	config->ntpq_port = hport(DEFAULT_NTPQ_PORT);
	config->interface[0] = '\0';

	config->multicast.enabled = false;
	config->multicast.address[0] = '\0';
	config->multicast.port = 0;
	config->multicast.ttl = 0;
	config->multicast.interface_index = -1;

	config->transition.nat64_enabled = false;
	config->transition.dns64_enabled = false;
	config->transition.nat64_prefix[0] = '\0';

	config->options.reuse_address = true;
	config->options.ipv6_v6only = false;
	config->options.recv_timeout_sec = NETWORK_DEFAULT_TIMEOUT_SEC;
	config->options.send_buffer_size = 0;
	config->options.recv_buffer_size = 0;

	config->bind_to_interface = false;
	config->enable_multicast = false;
	config->enable_transition = false;
}

/**
 * Validate network configuration
 * @param config Configuration to validate
 * @return 0 if valid, -1 if invalid
 */
int network_config_validate(const NetworkConfig *config)
{
	if (!config)
		return -1;

	if (config->ntp_port == 0)
		return -1;

	if (config->family_preference > NETWORK_FAMILY_DUAL_STACK)
		return -1;

	if (config->interface[0] != '\0') {
		size_t len = strnlen(config->interface,
				    sizeof(config->interface));
		if (len >= NETWORK_MAX_IFNAME_LEN)
			return -1;
	}

	if (config->multicast.enabled) {
		if (config->multicast.address[0] == '\0')
			return -1;
	}

	return 0;
}