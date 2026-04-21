#ifndef MODE_HANDLER_H
#define MODE_HANDLER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define NTP_STRATUM_UNSYNC 16
#define NTP_LI_ALARM 3
#define NTP_REF_ID_INIT 0

#define ACL_FLAG_NOQUERY (1 << 0)
#define ACL_FLAG_NOSERVE (1 << 1)
#define ACL_FLAG_LIMITED (1 << 2)
#define ACL_FLAG_NOPEER (1 << 3)
#define ACL_FLAG_NOTRUST (1 << 4)
#define ACL_FLAG_KOD (1 << 5)

#define DEFAULT_ACL_FLAGS                                                      \
    (ACL_FLAG_NOQUERY | ACL_FLAG_NOSERVE | ACL_FLAG_LIMITED)

#define DEFAULT_RATE_LIMIT_INTERVAL 2
#define DEFAULT_MAX_RESPONSE_RATIO 1.0f
#define DEFAULT_PANIC_THRESHOLD 1000
#define DEFAULT_INITIAL_STRATUM 16

#define DEFAULT_ENABLE_NTP_AUTH 0

typedef struct {
    uint8_t enable_control_messages;
    uint8_t enable_symmetric_mode;
    uint8_t enable_broadcast;
    uint8_t drop_unauthenticated_control;
    uint8_t enable_ntp_auth;
    uint8_t acl_default_policy;
    uint8_t rate_limit_interval;
    float max_response_ratio;
    uint8_t initial_stratum;
    uint16_t panic_threshold;
} ModeConfig;

typedef struct {
    in_addr_t ip;
    in_addr_t mask;
    uint8_t flags;
    char* comment;
} AclEntry;

typedef struct {
    in_addr_t ip;
    time_t last_request;
    uint8_t count;
} RateLimitEntry;

int mode_handler_init(void);
void mode_handler_cleanup(void);

int mode_handler_set_config(const ModeConfig* config);
int mode_handler_get_config(ModeConfig* config);

int acl_add_entry(const char* network, uint8_t flags);
int acl_remove_entry(const char* network);
int acl_clear_entries(void);
int acl_get_entry_count(void);

int acl_check_client(const char* client_ip, uint8_t packet_mode);
uint8_t acl_get_client_flags(const char* client_ip);

int rate_limit_check(const char* client_ip);
void rate_limit_update(const char* client_ip);
void rate_limit_cleanup(void);

uint8_t mode_get_default_li(void);
uint8_t mode_get_default_stratum(void);
uint32_t mode_get_default_ref_id(void);

int validate_packet_mode(uint8_t mode, size_t req_size, size_t resp_size);
int validate_ntp_version(uint8_t version);

int mode_handler_parse_config(const char* config_file);

int validate_packet_authentication(const void* buffer, size_t size);
int check_panic_condition(int64_t time_offset);

#endif
