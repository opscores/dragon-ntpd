#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "ntpd.h"

/* ============================================================================
 * Thread Context Structures (RFC 5905 Section 5)
 * ============================================================================
 */

typedef struct {
    int interval_ms;
    pthread_mutex_t clock_mutex;
    pthread_cond_t clock_cond;
    bool running;
    pthread_t thread_id;
    int64_t last_offset_us;
    int last_correction;
} ClockThreadContext;

typedef struct {
    int idx;
    int sock_fd;
    char ip[INET_ADDRSTRLEN];
    char port[16];
    pthread_mutex_t sock_mutex;
    struct sockaddr_storage client_addr_storage;
    socklen_t client_addr_len;
    PeerState* peer_state;
    atomic_bool sock_valid;
} PeerThreadContext;

/* ============================================================================
 * Peer Thread Functions
 * ============================================================================
 */

int start_peer_thread(int sock_fd, const char* ip, const char* port,
                      void* peer_state, int idx);
void stop_peer_thread(void);
void cleanup_peer_thread(void);

/* ============================================================================
 * Clock Thread Functions
 * ============================================================================
 */

int start_clock_thread(int interval_sec);
void stop_clock_thread(void);
void cleanup_clock_thread(void);

/* ============================================================================
 * Clock Thread Utilities
 * ============================================================================
 */

int clock_thread_notify(void);
int64_t clock_thread_get_last_offset(void);
int clock_thread_get_last_correction(void);

/* ============================================================================
 * NTPQ Thread Functions
 * ============================================================================
 */

/* Note: start_ntpq_thread() is declared in socket.h */

/* ============================================================================
 * Thread Context Global Variables
 * ============================================================================
 */

extern ClockThreadContext g_clock_ctx;
extern PeerThreadContext g_peer_ctx[MAX_PEERS];

#endif /* THREADS_H */
