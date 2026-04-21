#ifndef NTPD_H
#define NTPD_H

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "ido.h"

#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(SIZE_MAX / 2))
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

#ifndef IFNAMSZ
#define IFNAMSZ 16
#endif

/* ============================================================================
 * Version and Configuration
 * ============================================================================
 */

#define VERSION "1.0.0"
#define CONFIG_DIR "/etc/dntpd"
#define CONFIG_FILE CONFIG_DIR "/dntpd.conf"
#define MODES_CONFIG_FILE CONFIG_DIR "/modes.conf"
#define STATE_DIR "/var/lib/dntpd"
#define NTP_PORT 123
#define NTPQ_PORT 323
#define BUFFER_SIZE 1024
#define SYNC_INTERVAL_SECONDS 30
#define MAX_DEBUG_LEVEL 3
#define MIN_TIMEOUT_SEC 1
#define MAX_TIMEOUT_SEC 86400
#define MAX_SERVERS 64
#define MAX_SAMPLES 64
#define MAX_PEERS 8
#define MARX_K 3
#define PHI 15
#define MAXDIST 1000000
#define STEP_THRESHOLD_US 500000
#define POLL_DELAY_HIGH_THRESHOLD_US 100000
#define POLL_DELAY_LOW_THRESHOLD_US 10000
#define POLL_OFFSET_HIGH_THRESHOLD_US 50000
#define POLL_OFFSET_LOW_THRESHOLD_US 10000
#define POLL_INTERVAL_MIN 4
#define POLL_INTERVAL_MAX 12
#define DEFAULT_PID_FILE "/var/run/dntpd.pid"
#define DEFAULT_LOG_FILE "/var/log/dntpd.log"
#define SYNC_RETRY_INTERVAL_SEC 15
#define DEFAULT_NTPQ_PORT 323

/* Buffer constants */
#define MIN_BUFFER_SIZE 1024
#define MAX_BUFFER_SIZE (4 * 1024 * 1024)

/* Jitter thresholds (RFC 5905 Section 11.2.1) */
#define JITTER_THRESHOLD_US 100000 /* 100ms - exclude high-jitter peers */

/* ============================================================================
 * RFC 5905 Section 11.3 - Clock Discipline Constants
 * Note: These constants are now defined in time_sync.h
 * ============================================================================
 */

/* ============================================================================
 * Frequency Discipline Constants
 * ============================================================================
 */
#define FREQ_FILE STATE_DIR "/frequency"
#define FREQ_OFFSET_MAX_PPM 128.0 /* Max frequency offset (PPM) */

#define NTP_LI_MASK 0xC0
#define NTP_VN_MASK 0x38
#define NTP_MODE_MASK 0x07
#define NTP_MODE_CLIENT 3 /* NTP client mode (RFC 5905) */
#define NTP_MODE_SERVER 4
#define NTP_MODE_SYMMETRIC_ACTIVE 1
#define NTP_MODE_SYMMETRIC_PASSIVE 2
#define NTP_MODE_BROADCAST 5
#define NTP_MODE_CONTROL 6
#define NTP_MODE_PRIVATE 7
#define NTP_VN_SHIFT 3
#define NTP_LI_SHIFT 6
#define NTP_VN_4 4
#define NTP_UNIX_EPOCH_DELTA 2208988800UL

/* ============================================================================
 * Leap Second Handling (RFC 5905 Section 11.4)
 * ============================================================================
 */
#define LEAP_SECOND_DIR_POSITIVE 1 /* +1s at end of minute */
#define LEAP_SECOND_DIR_NEGATIVE 2 /* -1s at end of minute */
#define LEAP_SECOND_FILE_DIR_POSITIVE 1
#define LEAP_SECOND_FILE_DIR_NEGATIVE 2
#define LEAP_SECOND_FILE_DIR "/etc/ntp"
#define LEAP_SECOND_FILE_PREFIX "leap-"
#define LEAP_SECOND_FILE_SUFFIX ".s"
#define LEAP_SECOND_EVENT_INTERVAL_SEC 60
#define LEAP_SECOND_CHECK_INTERVAL_SEC 300

/* ============================================================================
 * Thread Context Structures (RFC 5905 Section 5)
 * ============================================================================
 */

/* ============================================================================
 * Type Definitions
 * ============================================================================
 */

typedef struct {
    uint32_t sec;
    uint32_t frac;
} NtpTimestamp;

typedef struct {
    uint8_t li_vn_mode;
    uint8_t stratum;
    int8_t poll;
    int8_t precision;
    uint32_t root_delay;
    uint32_t root_disp;
    uint32_t ref_id;
    NtpTimestamp ref_ts;
    NtpTimestamp orig_ts;
    NtpTimestamp recv_ts;
    NtpTimestamp xmit_ts;
    size_t extension_len;
    uint8_t key_id;         /* Key identifier (8 bits) */
    uint8_t mac_digest[20]; /* HMAC-SHA1 digest (20 bytes) */
} NtpPacket;

typedef struct {
    char* ip;
    char* port;
    time_t next_allowed_sync;
} ServerConfig;

typedef struct {
    uint64_t ts;
    uint64_t delay;
    int64_t offset;
} NtpSample;

typedef struct {
    char ip[64];
    char port[16];
    uint8_t stratum;
    uint64_t delay_us;
    int64_t offset_us;
    uint64_t jitter_us;
    uint32_t root_disp;
    time_t last_update;
    bool reachable;
    /* RFC 5905 Section 8.4 / RFC 5906: I-DO/Autokey authentication state */
    IdoState ido_state;
} PeerState;

/* Clock discipline states */
#define FREQ_STATE_NSET 0
#define FREQ_STATE_FSET 1
#define FREQ_STATE_SYNC 2
#define FREQ_STATE_RECOVER 3

typedef struct {
    double ppm;
    time_t last_update;
    int64_t last_offset_us;
    int state;

    /* RFC 5905 Section 11.3 - Loop filter state */
    double ppm_filter;         /* Filtered PPM (exponential average) */
    double ppm_error_history;  /* Error history for integration */
    time_t last_filter_update; /* Last filter update time */

    /* State machine */
    int pll_stable_count;   /* PLL stability counter */
    int fll_recovery_count; /* FLL recovery counter */

    /* Dynamic gain scheduling */
    double dynamic_pll_gain;   /* Adaptive PLL gain */
    double dynamic_fll_gain;   /* Adaptive FLL gain */
    uint64_t recent_jitter_us; /* Recent jitter (for gain adaptation) */

    /* Loop filter state */
    double filtered_ppm; /* Filtered PPM from loop filter */

    /* Protection */
    int64_t last_applied_ppm; /* Last applied PPM (for rate limiting) */
    time_t last_apply_time;   /* Last apply time */
} FreqState;

/* ============================================================================
 * RFC 5905 Section 7.4 - Clock Accuracy State
 * ============================================================================
 */

typedef struct {
    double precision;               /* Clock precision (ρ) - RFC 5905 */
    double resolution;              /* Clock resolution (2^(-p)) */
    double accuracy_estimate;       /* Clock accuracy estimate */
    double stability_metric;        /* Clock stability metric (Allan variance) */
    time_t last_update;             /* Last accuracy update time */
    uint64_t offset_history[16];    /* Offset history for stability tracking */
    time_t offset_history_time[16]; /* Corresponding times */
} ClockAccuracyState;

/* ============================================================================
 * Global Variables
 * ============================================================================
 */

extern ServerConfig* g_servers;
extern int g_server_count;
extern NtpSample g_samples[MAX_SAMPLES];
extern int g_sample_count;

/* Thread contexts are declared in threads.h */

/* RFC 5905 Section 11.2.1 - Byzantine Fault Detection */
extern PeerState g_peer_pool[MAX_PEERS];
extern int g_peer_pool_count;

extern bool g_time_synced;
extern uint8_t g_local_stratum;
extern uint32_t g_local_ref_id;
extern NtpTimestamp g_local_ref_ts;
extern NtpTimestamp g_last_sync_ts;
extern uint32_t g_local_root_delay;
extern uint32_t g_local_root_disp;
extern uint8_t g_local_li;
extern time_t g_last_dispersion_update;

extern int8_t g_local_precision;
extern int8_t g_local_poll;
extern int8_t g_peer_poll;
extern FreqState g_freq_state;

extern pthread_mutex_t g_mutex;

#endif /* NTPD_H */
