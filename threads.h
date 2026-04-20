#ifndef THREADS_H
#define THREADS_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * Peer Thread Functions
 * ============================================================================
 */

int start_peer_thread(int sock_fd, const char* ip, const char* port, void* peer_state, int idx);
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

#endif /* THREADS_H */
