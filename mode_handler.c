#include "mode_handler.h"
#include "ntpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define MAX_ACL_ENTRIES 256
#define MAX_RATE_LIMIT_ENTRIES 1024
#define MAX_CONFIG_LINE 256

static ModeConfig g_mode_config = {.enable_control_messages = 0,
                                   .enable_symmetric_mode = 1,
                                   .enable_broadcast = 0,
                                   .drop_unauthenticated_control = 1,
                                   .enable_ntp_auth = DEFAULT_ENABLE_NTP_AUTH,
                                   .acl_default_policy = DEFAULT_ACL_FLAGS,
                                   .rate_limit_interval = DEFAULT_RATE_LIMIT_INTERVAL,
                                   .max_response_ratio = DEFAULT_MAX_RESPONSE_RATIO,
                                   .initial_stratum = DEFAULT_INITIAL_STRATUM,
                                   .panic_threshold = DEFAULT_PANIC_THRESHOLD};

static AclEntry g_acl_entries[MAX_ACL_ENTRIES];
static int g_acl_entry_count = 0;

static RateLimitEntry g_rate_limit_entries[MAX_RATE_LIMIT_ENTRIES];
static int g_rate_limit_entry_count = 0;

static pthread_mutex_t g_mode_mutex = PTHREAD_MUTEX_INITIALIZER;

static in_addr_t parse_network(const char* network, in_addr_t* mask) {
    char buf[64];
    const char* slash;
    in_addr_t ip = 0;
    unsigned int prefix_len = 32;

    if (network == NULL) return 0;

    slash = strchr(network, '/');
    if (slash != NULL) {
        size_t len = (size_t)(slash - network);
        if (len >= sizeof(buf)) return 0;
        memcpy(buf, network, len);
        buf[len] = '\0';
        if (sscanf(slash + 1, "%u", &prefix_len) != 1 || prefix_len > 32) return 0;
    } else {
        if (strlen(network) >= sizeof(buf)) return 0;
        snprintf(buf, sizeof(buf), "%s", network);
    }

    ip = inet_addr(buf);
    if (ip == INADDR_NONE && strcmp(buf, "255.255.255.255") != 0) return 0;

    *mask = prefix_len == 0 ? 0 : htonl(0xFFFFFFFFUL << (32 - prefix_len));
    return ip;
}

static in_addr_t parse_ip(const char* ip_str) {
    if (ip_str == NULL) return 0;
    return inet_addr(ip_str);
}

static int ip_in_network(in_addr_t ip, in_addr_t net, in_addr_t mask) {
    return (ip & mask) == (net & mask);
}

static RateLimitEntry* rate_limit_find(const char* client_ip) {
    in_addr_t ip;
    int i;

    if (client_ip == NULL) return NULL;

    ip = parse_ip(client_ip);
    if (ip == 0) return NULL;

    for (i = 0; i < g_rate_limit_entry_count; i++) {
        if (g_rate_limit_entries[i].ip == ip) return &g_rate_limit_entries[i];
    }
    return NULL;
}

static RateLimitEntry* rate_limit_insert(const char* client_ip) {
    in_addr_t ip;
    RateLimitEntry* entry;

    if (client_ip == NULL) return NULL;

    ip = parse_ip(client_ip);
    if (ip == 0) return NULL;

    entry = rate_limit_find(client_ip);
    if (entry != NULL) return entry;

    if (g_rate_limit_entry_count >= MAX_RATE_LIMIT_ENTRIES) {
        syslog(LOG_WARNING, "Rate limit table full, evicting oldest entry");
        memmove(g_rate_limit_entries, g_rate_limit_entries + 1, (MAX_RATE_LIMIT_ENTRIES - 1) * sizeof(RateLimitEntry));
        g_rate_limit_entry_count--;
    }

    entry = &g_rate_limit_entries[g_rate_limit_entry_count++];
    entry->ip = ip;
    entry->last_request = 0;
    entry->count = 0;
    return entry;
}

int mode_handler_init(void) {
    pthread_mutex_lock(&g_mode_mutex);
    g_acl_entry_count = 0;
    g_rate_limit_entry_count = 0;
    pthread_mutex_unlock(&g_mode_mutex);

    syslog(LOG_INFO, "Mode handler initialized with secure defaults");
    return 0;
}

void mode_handler_cleanup(void) {
    pthread_mutex_lock(&g_mode_mutex);
    g_acl_entry_count = 0;
    g_rate_limit_entry_count = 0;
    pthread_mutex_unlock(&g_mode_mutex);
}

int mode_handler_set_config(const ModeConfig* config) {
    if (config == NULL) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);
    memcpy(&g_mode_config, config, sizeof(g_mode_config));
    pthread_mutex_unlock(&g_mode_mutex);

    syslog(LOG_INFO, "Mode handler config updated");
    return 0;
}

int mode_handler_get_config(ModeConfig* config) {
    if (config == NULL) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);
    memcpy(config, &g_mode_config, sizeof(g_mode_config));
    pthread_mutex_unlock(&g_mode_mutex);

    return 0;
}

int acl_add_entry(const char* network, uint8_t flags) {
    in_addr_t net;
    in_addr_t mask;
    AclEntry* entry;

    if (network == NULL) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);

    if (g_acl_entry_count >= MAX_ACL_ENTRIES) {
        pthread_mutex_unlock(&g_mode_mutex);
        syslog(LOG_ERR, "ACL table full");
        return -ENOMEM;
    }

    net = parse_network(network, &mask);
    if (net == 0) {
        pthread_mutex_unlock(&g_mode_mutex);
        syslog(LOG_ERR, "Invalid network address: %s", network);
        return -EINVAL;
    }

    entry = &g_acl_entries[g_acl_entry_count++];
    entry->ip = net;
    entry->mask = mask;
    entry->flags = flags;
    entry->comment = NULL;

    pthread_mutex_unlock(&g_mode_mutex);

    syslog(LOG_INFO, "ACL entry added: %s flags=0x%02x", network, flags);
    return 0;
}

int acl_remove_entry(const char* network) {
    in_addr_t net;
    in_addr_t mask;
    int i;

    if (network == NULL) return -EINVAL;

    net = parse_network(network, &mask);
    if (net == 0) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);

    for (i = 0; i < g_acl_entry_count; i++) {
        if (g_acl_entries[i].ip == net && g_acl_entries[i].mask == mask) {
            memmove(&g_acl_entries[i], &g_acl_entries[i + 1], (size_t)(g_acl_entry_count - i - 1) * sizeof(AclEntry));
            g_acl_entry_count--;
            pthread_mutex_unlock(&g_mode_mutex);
            syslog(LOG_INFO, "ACL entry removed: %s", network);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_mode_mutex);
    return -ENOENT;
}

int acl_clear_entries(void) {
    pthread_mutex_lock(&g_mode_mutex);
    g_acl_entry_count = 0;
    pthread_mutex_unlock(&g_mode_mutex);
    syslog(LOG_INFO, "ACL cleared");
    return 0;
}

int acl_get_entry_count(void) {
    int count;
    pthread_mutex_lock(&g_mode_mutex);
    count = g_acl_entry_count;
    pthread_mutex_unlock(&g_mode_mutex);
    return count;
}

int acl_check_client(const char* client_ip, uint8_t packet_mode) {
    uint8_t flags;
    in_addr_t ip;
    AclEntry* entry = NULL;
    int i;
    int result = 0;

    if (client_ip == NULL) return 0;

    ip = parse_ip(client_ip);
    if (ip == 0) return 0;

    if (packet_mode == NTP_MODE_SYMMETRIC_ACTIVE || packet_mode == NTP_MODE_SYMMETRIC_PASSIVE) {
        pthread_mutex_lock(&g_mode_mutex);
        if (!g_mode_config.enable_symmetric_mode) {
            pthread_mutex_unlock(&g_mode_mutex);
            return 0;
        }
        pthread_mutex_unlock(&g_mode_mutex);
    }

    if (packet_mode == NTP_MODE_BROADCAST) {
        pthread_mutex_lock(&g_mode_mutex);
        if (!g_mode_config.enable_broadcast) {
            pthread_mutex_unlock(&g_mode_mutex);
            return 0;
        }
        pthread_mutex_unlock(&g_mode_mutex);
    }

    pthread_mutex_lock(&g_mode_mutex);

    for (i = 0; i < g_acl_entry_count; i++) {
        if (ip_in_network(ip, g_acl_entries[i].ip, g_acl_entries[i].mask)) {
            entry = &g_acl_entries[i];
            break;
        }
    }

    flags = entry ? entry->flags : g_mode_config.acl_default_policy;

    switch (packet_mode) {
    case NTP_MODE_CONTROL:
    case NTP_MODE_PRIVATE: result = (flags & ACL_FLAG_NOQUERY) == 0; break;
    case NTP_MODE_CLIENT:
    case NTP_MODE_SERVER:
    case NTP_MODE_SYMMETRIC_ACTIVE:
    case NTP_MODE_SYMMETRIC_PASSIVE: result = (flags & ACL_FLAG_NOSERVE) == 0; break;
    case NTP_MODE_BROADCAST: result = (flags & ACL_FLAG_NOSERVE) == 0; break;
    default: result = 0; break;
    }

    pthread_mutex_unlock(&g_mode_mutex);
    return result;
}

uint8_t acl_get_client_flags(const char* client_ip) {
    in_addr_t ip;
    AclEntry* entry = NULL;
    int i;

    if (client_ip == NULL) return g_mode_config.acl_default_policy;

    ip = parse_ip(client_ip);
    if (ip == 0) return g_mode_config.acl_default_policy;

    pthread_mutex_lock(&g_mode_mutex);

    for (i = 0; i < g_acl_entry_count; i++) {
        if (ip_in_network(ip, g_acl_entries[i].ip, g_acl_entries[i].mask)) {
            entry = &g_acl_entries[i];
            break;
        }
    }

    pthread_mutex_unlock(&g_mode_mutex);

    return entry ? entry->flags : g_mode_config.acl_default_policy;
}

int rate_limit_check(const char* client_ip) {
    RateLimitEntry* entry;
    time_t now;
    int interval;

    if (client_ip == NULL) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);
    interval = g_mode_config.rate_limit_interval;
    pthread_mutex_unlock(&g_mode_mutex);

    entry = rate_limit_find(client_ip);
    if (entry == NULL) return 0;

    now = time(NULL);
    if (now - entry->last_request < interval) return 1;

    return 0;
}

void rate_limit_update(const char* client_ip) {
    RateLimitEntry* entry;

    if (client_ip == NULL) return;

    entry = rate_limit_insert(client_ip);
    if (entry != NULL) {
        entry->last_request = time(NULL);
        entry->count++;
    }
}

void rate_limit_cleanup(void) {
    pthread_mutex_lock(&g_mode_mutex);
    g_rate_limit_entry_count = 0;
    pthread_mutex_unlock(&g_mode_mutex);
}

uint8_t mode_get_default_li(void) {
    uint8_t li;
    pthread_mutex_lock(&g_mode_mutex);
    li = g_time_synced ? g_local_li : NTP_LI_ALARM;
    pthread_mutex_unlock(&g_mode_mutex);
    return li;
}

uint8_t mode_get_default_stratum(void) {
    uint8_t stratum;
    pthread_mutex_lock(&g_mode_mutex);
    stratum = g_time_synced ? g_local_stratum : g_mode_config.initial_stratum;
    pthread_mutex_unlock(&g_mode_mutex);
    return stratum;
}

uint32_t mode_get_default_ref_id(void) {
    uint32_t ref_id;
    pthread_mutex_lock(&g_mode_mutex);
    ref_id = g_time_synced ? g_local_ref_id : NTP_REF_ID_INIT;
    pthread_mutex_unlock(&g_mode_mutex);
    return ref_id;
}

int validate_packet_mode(uint8_t mode, size_t req_size, size_t resp_size) {
    float max_ratio;

    if (mode > NTP_MODE_PRIVATE) return -EINVAL;

    pthread_mutex_lock(&g_mode_mutex);
    max_ratio = g_mode_config.max_response_ratio;
    pthread_mutex_unlock(&g_mode_mutex);

    if (resp_size > (size_t)((double)req_size * (double)max_ratio)) {
        syslog(LOG_WARNING, "Response size %zu exceeds ratio from request %zu", resp_size, req_size);
        return -E2BIG;
    }

    return 0;
}

int validate_ntp_version(uint8_t version) {
    return version == NTP_VN_4 ? 0 : -EINVAL;
}

static int parse_bool(const char* val) {
    if (val == NULL) return -EINVAL;
    if (strcmp(val, "1") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 || strcmp(val, "on") == 0) return 1;
    if (strcmp(val, "0") == 0 || strcmp(val, "no") == 0 || strcmp(val, "false") == 0 || strcmp(val, "off") == 0) return 0;
    return -EINVAL;
}

static int parse_uint8(const char* val, uint8_t* out) {
    long long int result;
    char* endptr;

    if (val == NULL || out == NULL) return -EINVAL;

    errno = 0;
    result = strtoll(val, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || result < 0 || result > 255) return -EINVAL;

    *out = (uint8_t)result;
    return 0;
}

static int parse_float(const char* val, float* out) {
    double result;
    char* endptr;

    if (val == NULL || out == NULL) return -EINVAL;

    errno = 0;
    result = strtod(val, &endptr);
    if (errno != 0 || *endptr != '\0' || result < 0) return -EINVAL;

    *out = (float)result;
    return 0;
}

int mode_handler_parse_config(const char* config_file) {
    FILE* fp;
    char line[MAX_CONFIG_LINE];
    char key[64];
    char val[128];
    int lineno = 0;

    if (config_file == NULL) return -EINVAL;

    fp = fopen(config_file, "r");
    if (fp == NULL) {
        syslog(LOG_WARNING, "Config file not found: %s", config_file);
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;

        char* comment = strchr(line, '#');
        if (comment != NULL) *comment = '\0';

        if (sscanf(line, " %63s %127s ", key, val) != 2) continue;

        if (strcmp(key, "enable_control_messages") == 0) {
            int b = parse_bool(val);
            if (b >= 0) g_mode_config.enable_control_messages = (uint8_t)b;
        } else if (strcmp(key, "enable_symmetric_mode") == 0) {
            int b = parse_bool(val);
            if (b >= 0) g_mode_config.enable_symmetric_mode = (uint8_t)b;
        } else if (strcmp(key, "enable_broadcast") == 0) {
            int b = parse_bool(val);
            if (b >= 0) g_mode_config.enable_broadcast = (uint8_t)b;
        } else if (strcmp(key, "drop_unauthenticated_control") == 0) {
            int b = parse_bool(val);
            if (b >= 0) g_mode_config.drop_unauthenticated_control = (uint8_t)b;
        } else if (strcmp(key, "enable_ntp_auth") == 0) {
            int b = parse_bool(val);
            if (b >= 0) g_mode_config.enable_ntp_auth = (uint8_t)b;
        } else if (strcmp(key, "acl_default_policy") == 0) {
            uint8_t flags = 0;
            char* p = val;
            while (*p) {
                if (strncmp(p, "noquery", 7) == 0)
                    flags |= ACL_FLAG_NOQUERY;
                else if (strncmp(p, "noserve", 6) == 0)
                    flags |= ACL_FLAG_NOSERVE;
                else if (strncmp(p, "limited", 7) == 0)
                    flags |= ACL_FLAG_LIMITED;
                else if (strncmp(p, "nopeer", 5) == 0)
                    flags |= ACL_FLAG_NOPEER;
                else if (strncmp(p, "notrust", 6) == 0)
                    flags |= ACL_FLAG_NOTRUST;
                p += strcspn(p, ",");
                if (*p == ',')
                    p++;
                else
                    break;
            }
            g_mode_config.acl_default_policy = flags;
        } else if (strcmp(key, "rate_limit_interval") == 0) {
            uint8_t interval;
            if (parse_uint8(val, &interval) == 0) g_mode_config.rate_limit_interval = interval;
        } else if (strcmp(key, "max_response_ratio") == 0) {
            float ratio;
            if (parse_float(val, &ratio) == 0) g_mode_config.max_response_ratio = ratio;
        } else if (strcmp(key, "initial_stratum") == 0) {
            uint8_t stratum;
            if (parse_uint8(val, &stratum) == 0) g_mode_config.initial_stratum = stratum;
        } else if (strcmp(key, "panic_threshold") == 0) {
            long long int t;
            char* endptr;
            errno = 0;
            t = strtoll(val, &endptr, 10);
            if (errno == 0 && *endptr == '\0' && t > 0 && t <= 65535) g_mode_config.panic_threshold = (uint16_t)t;
        } else if (strcmp(key, "acl_allow") == 0) {
            acl_add_entry(val, 0);
        }
    }

    fclose(fp);
    syslog(LOG_INFO, "Parsed %d lines from config", lineno);
    return 0;
}

int validate_packet_authentication(const void* buffer, size_t size) {
    const uint8_t* data;
    uint16_t field_type;
    uint16_t field_len;
    size_t pos;

    if (buffer == NULL || size < 48) return 0;

    data = (const uint8_t*)buffer;

    if (size > 48) {
        pos = 48;
        while (pos + 4 <= size) {
            field_type = (uint16_t)(data[pos] << 8) | data[pos + 1];
            field_len = (uint16_t)(data[pos + 2] << 8) | data[pos + 3];

            if (field_len < 4 || pos + field_len > size) break;

            if (field_type == 0x0003) {
                pthread_mutex_lock(&g_mode_mutex);
                uint8_t auth_enabled = g_mode_config.enable_ntp_auth;
                pthread_mutex_unlock(&g_mode_mutex);

                if (!auth_enabled) {
                    syslog(LOG_WARNING, "Authentication MAC present but NTP auth disabled");
                    return -ENOTSUP;
                }
                return 1;
            }

            pos += ((field_len + 3) & ~3u);
            if (field_type == 0x0008) break;
        }
    }

    return 0;
}

int check_panic_condition(int64_t time_offset) {
    uint16_t threshold;

    if (time_offset == 0) return 0;

    pthread_mutex_lock(&g_mode_mutex);
    threshold = g_mode_config.panic_threshold;
    pthread_mutex_unlock(&g_mode_mutex);

    if (time_offset < 0) time_offset = -time_offset;

    if (time_offset > (int64_t)threshold * 1000000000LL) {
        syslog(LOG_CRIT, "PANIC: time offset %lld exceeds threshold %d", (long long)time_offset, threshold);
        return 1;
    }

    return 0;
}