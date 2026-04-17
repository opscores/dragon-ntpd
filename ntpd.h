#ifndef NTPD_H
#define NTPD_H

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <pwd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <grp.h>

#ifndef IFNAMSZ
#define IFNAMSZ 16
#endif

#define VERSION "1.0.0"
#define CONFIG_DIR "/etc/time_sync"
#define CONFIG_FILE CONFIG_DIR "/servers.conf"
#define NTP_PORT 123
#define BUFFER_SIZE 1024
#define SYNC_INTERVAL_SECONDS 30
#define MAX_SERVERS 64
#define MAX_SAMPLES 64
#define MAX_PEERS 8
#define MARX_K 3
#define PHI 15
#define DEFAULT_CONFIG_FILE "/etc/time_sync/servers.conf"
#define DEFAULT_PID_FILE "/var/run/ntpd.pid"
#define DEFAULT_LOG_FILE "/var/log/ntpd.log"

#define NTP_LI_MASK   0xC0
#define NTP_VN_MASK   0x38
#define NTP_MODE_MASK 0x07
#define NTP_MODE_CLIENT 3  /* NTP client mode (RFC 5905) */
#define NTP_VN_SHIFT  3
#define NTP_LI_SHIFT  6
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

/* I-DO Capability Negotiation State (RFC 5905 Section 8.4) */
typedef struct {
    uint8_t  ido_state;              /* I-DO state machine */
    uint8_t  ido_offer_received;     /* I-DO Offer received from server */
    uint8_t  ido_response_sent;      /* I-DO Response sent to server */
    uint8_t  ido_capabilities;       /* Capability flags */
    uint32_t ido_key_id;             /* Key identifier */
    uint8_t  ido_key[16];            /* MAC key (128-bit) */
    bool     ido_enabled;            /* I-DO enabled */
    bool     ido_authenticated;      /* Authentication established */
} IdoState;

/* I-DO State Machine States (RFC 5905 Section 8.4) */
#define IDO_STATE_IDLE              0
#define IDO_STATE_OFFER_RECEIVED    1
#define IDO_STATE_RESPONSE_SENT     2
#define IDO_STATE_AUTHENTICATED     3
#define IDO_STATE_REJECTED          4

/* I-DO Capability Flags (RFC 5905 Section 8.4) */
#define IDO_CAP_OFFER               (1 << 0)  /* I-DO Offer capability */
#define IDO_CAP_RESPONSE            (1 << 1)  /* I-DO Response capability */
#define IDO_CAP_RESERVED            (1 << 2)  /* Reserved */

typedef struct {
    char *ip;
    char *port;
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
    const void *buffer;
    size_t size;
    const char *ip;
    const char *port;
} PeerRequestData;

typedef struct {
    char *config_file;
    char *pid_file;
    char *log_file;
    char *run_user;
    char *interface;
    int foreground;
    int debug_level;
    int no_daemonize;
    int timeout_sec;
    int quit_after_sync;
} CliConfig;

extern ServerConfig *g_servers;
extern int g_server_count;
extern NtpSample g_samples[MAX_SAMPLES];
extern int g_sample_count;

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
extern IdoState g_ido_state;  /* I-DO state (RFC 5905 Section 8.4) */

extern CliConfig g_cli;

extern int g_sync_sock;
extern pthread_mutex_t g_mutex;

void print_usage(const char *prog);
void print_version(void);
int parse_arguments(int argc, char *argv[]);
int load_server_config(void);
void cleanup_resources(void);

uint32_t read_u32be(const uint8_t *p);
void write_u32be(uint8_t *p, uint32_t v);
bool parse_ntp_packet(const void *buffer, size_t size, NtpPacket *pkt);
void create_ntp_request(void *buffer, NtpTimestamp *xmit_out);
bool ntp_is_kod(const NtpPacket *pkt);

int64_t ntp_timestamp_to_ns(const NtpTimestamp *ts);
bool calculate_delay_offset(const NtpTimestamp *t1, const NtpTimestamp *t2,
                             const NtpTimestamp *t3, const NtpTimestamp *t4,
                             uint64_t *delay_us, int64_t *offset_us);
bool handle_leap_indicator(uint8_t li);
uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum);
uint8_t compute_system_offset(int8_t *offsets, int count, int *best_idx);
uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us);
int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us);
uint32_t ntp_u16_16_from_us(uint64_t us);

void marx_add_sample_us(uint64_t ts_ns, uint64_t delay_us, int64_t offset_us);
void marx_remove_sample(int index);
uint64_t marx_median(uint64_t *arr, int count);
int marx_filter_outliers(NtpSample *samples, int count, int k);
uint64_t ntp_offset_jitter_us_locked(void);

NtpTimestamp ntp_timestamp_now(void);
int8_t get_system_precision(void);
int apply_time_correction_slew_or_step(int64_t offset_us);
int sync_ntp_time(const char *ip, const char *port);

int create_udp_socket(int port);
void close_socket(int sock);
int get_sync_socket(void);
void handle_client_request(const void *buffer, size_t size, const char *ip, const char *port);

/* I-DO functions (RFC 5905 Section 8.4) */
void ido_state_init(IdoState *state);
void ido_state_cleanup(IdoState *state);
int process_ido_offer(const uint8_t *data, size_t len, IdoState *state);
int process_ido_response(const uint8_t *data, size_t len, IdoState *state);
int ido_state_machine(IdoState *state, bool offer_received, bool response_sent);
bool ido_is_authenticated(void);
void ido_log_state(void);

/* Threads functions (RFC 5905 Section 5) */
int start_clock_thread(int interval_sec);
void stop_clock_thread(void);
void cleanup_clock_thread(void);
int start_peer_thread(int sock_fd, const char *ip, const char *port,
                      PeerState *peer_state);
void stop_peer_thread(void);
void cleanup_peer_thread(void);

#endif