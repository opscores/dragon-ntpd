#ifndef NTPD_H
#define NTPD_H

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "ido.h"
#include "mode_handler.h"
#include "socket.h"
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

#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(SIZE_MAX / 2))
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

#ifndef IFNAMSZ
#define IFNAMSZ 16
#endif

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

/* RFC 5905 Section 11.3 - Clock Discipline */
#define CLOCK_PHI 15e-6            /* Max frequency error (s/s) = 15 PPM */
#define CLOCK_PLLGAIN 8            /* PLL loop gain (log2) */
#define CLOCK_FLLGAIN 4            /* FLL loop gain (log2) */
#define CLOCK_ALLAN_INTERCEPT 2048 /* Allan intercept (sec), poll >= 11 */
#define FREQ_UPDATE_INTERVAL_MIN_SEC 64
#define FREQ_FILE STATE_DIR "/frequency"
#define FREQ_OFFSET_MAX_PPM 128.0 /* Max frequency offset (PPM) */

/* RFC 5905 Section 11.3 - Loop filter constants */
#define FLL_ALPHA 0.1                    /* FLL filter coefficient (0.1 = tau = 10x poll) */
#define PLL_ALPHA 0.01                   /* PLL filter coefficient (0.01 = tau = 100x poll) */
#define FREQ_DEADBAND_PPM 0.001          /* Deadband for small errors (1 mPPM) */
#define FREQ_MAX_STEP_PPM 10.0           /* Max PPM step per update (rate limiting) */
#define PLL_STABLE_COUNT 5               /* PLL stability counter threshold */
#define FLL_HIGH_GAIN 0.5                /* High FLL gain for recovery */
#define FLL_LOW_GAIN 0.1                 /* Low FLL gain for stability */
#define PLL_HIGH_GAIN 0.1                /* High PLL gain for fast convergence */
#define PLL_NOMINAL_GAIN 0.01            /* Nominal PLL gain (standard) */
#define PLL_LOW_GAIN 0.001               /* Low PLL gain for stability */
#define FLL_RECOVERY_THRESHOLD_US 500000 /* Threshold for PLL->FLL transition (500ms) */
#define PLL_THRESHOLD_US 10000           /* Threshold for FLL->PLL transition (10ms) */
#define JITTER_HIGH_THRESHOLD_US 200000  /* 200ms - high jitter */
#define JITTER_LOW_THRESHOLD_US 50000    /* 50ms - low jitter */

#define NTP_LI_MASK 0xC0
#define NTP_VN_MASK 0x38
#define NTP_MODE_MASK 0x07
#define NTP_MODE_CLIENT 3 /* NTP client mode (RFC 5905) */
#define NTP_VN_SHIFT 3
#define NTP_LI_SHIFT 6
#define NTP_VN_4 4
#define NTP_UNIX_EPOCH_DELTA 2208988800UL

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
} PeerState;

typedef struct {
    void* buffer;
    size_t size;
    char ip[INET_ADDRSTRLEN];
    char port[16];
} PeerRequestData;

/* Clock discipline states */
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

/* Clock discipline states */
#define FREQ_STATE_NSET 0
#define FREQ_STATE_FSET 1
#define FREQ_STATE_SYNC 2
#define FREQ_STATE_RECOVER 3

typedef struct {
    char* config_file;
    char* pid_file;
    char* log_file;
    char* run_user;
    char* interface;
    int foreground;
    int debug_level;
    int no_daemonize;
    int timeout_sec;
    int quit_after_sync;
    int family_preference; /* 0=dual-stack, 1=IPv4-only, 2=IPv6-only */

    /* RFC 5905 Section 5.2 - Broadcast mode */
    int broadcast_mode;     /* 0=disabled, 1=enabled */
    char* broadcast_addr;   /* Custom broadcast address (NULL = default) */
    int broadcast_interval; /* Interval in seconds (32-128, default: 64) */
} CliConfig;

extern ServerConfig* g_servers;
extern int g_server_count;
extern NtpSample g_samples[MAX_SAMPLES];
extern int g_sample_count;

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
extern IdoState g_ido_state; /* I-DO state (RFC 5905 Section 8.4) */

extern CliConfig g_cli;

extern pthread_mutex_t g_mutex;

/* Network utility functions */
uint16_t nport(uint16_t port);
int npton(uint16_t port, char* buf, size_t buf_size);

void print_usage(const char* prog);
void print_version(void);
int parse_arguments(int argc, char* argv[]);
int load_server_config(void);
void cleanup_resources(void);
int apply_user_privileges(const char* username);

uint32_t read_u32be(const uint8_t* p);
void write_u32be(uint8_t* p, uint32_t v);
bool parse_ntp_packet(const void* buffer, size_t size, NtpPacket* pkt);
void create_ntp_request(void* buffer, NtpTimestamp* xmit_out);
bool ntp_is_kod(const NtpPacket* pkt);

int64_t ntp_timestamp_to_ns(const NtpTimestamp* ts);
bool calculate_delay_offset(const NtpTimestamp* t1, const NtpTimestamp* t2, const NtpTimestamp* t3, const NtpTimestamp* t4, uint64_t* delay_us,
                            int64_t* offset_us);
bool handle_leap_indicator(uint8_t li);
uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum);
uint8_t compute_system_offset(const int64_t* offsets, int count, int* best_idx);
int select_best_peers(const int64_t* offsets, const uint64_t* jitter, int count, int* valid_indices, int* valid_count);
int64_t majority_vote(const int64_t* offsets, int count);
bool is_false_ticker(int64_t peer_offset, int64_t cluster_offset);
uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us);
int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us);
uint32_t ntp_u16_16_from_us(uint64_t us);

uint8_t calculate_network_quality(uint64_t delay_us);

void marx_add_sample_us(uint64_t ts_ns, uint64_t delay_us, int64_t offset_us);
void marx_remove_sample(int index);
uint64_t marx_median(uint64_t* arr, int count);
int marx_filter_outliers(NtpSample* samples, int count, int k);
uint64_t ntp_offset_jitter_us_locked(void);

/* ============================================================================
 * Time synchronization (RFC 5905 Section 11.3)
 * ============================================================================ */
/* Frequency discipline */
int init_frequency_discipline(void);
int load_frequency_persistent(void);
int save_frequency_persistent(void);
int apply_frequency_adjustment(double ppm);
int update_frequency_discipline(int64_t offset_us, int poll_exp);
double calculate_frequency_ppm(int64_t offset_us, time_t delta_sec);

/* Time correction */
int apply_time_correction_slew_or_step(int64_t offset_us);
int sync_ntp_time(const char* ip, const char* port);
NtpTimestamp ntp_timestamp_now(void);
int8_t get_system_precision(void);

/* ============================================================================
 * Network functions - now in socket.h
 * ============================================================================ */

/* Threads functions (RFC 5905 Section 5) */
int start_clock_thread(int interval_sec);
void stop_clock_thread(void);
void cleanup_clock_thread(void);
int start_peer_thread(int sock_fd, const char* ip, const char* port, PeerState* peer_state, int idx);
void stop_peer_thread(void);
void cleanup_peer_thread(void);

/* Mode handler and ACL (Security-First) */
int mode_handler_init(void);
void mode_handler_cleanup(void);
int mode_handler_set_config(const ModeConfig* config);
int mode_handler_get_config(ModeConfig* config);
int acl_add_entry(const char* network, uint8_t flags);
int acl_check_client(const char* client_ip, uint8_t packet_mode);
uint8_t acl_get_client_flags(const char* client_ip);
int rate_limit_check(const char* client_ip);
void rate_limit_update(const char* client_ip);
uint8_t mode_get_default_li(void);
uint8_t mode_get_default_stratum(void);
uint32_t mode_get_default_ref_id(void);
int validate_packet_mode(uint8_t mode, size_t req_size, size_t resp_size);
int validate_packet_authentication(const void* buffer, size_t size);
int check_panic_condition(int64_t time_offset);
int mode_handler_parse_config(const char* config_file);

#endif
