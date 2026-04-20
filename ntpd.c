#include "ntpd.h"

/* ============================================================================
 * Clock Accuracy State (RFC 5905 Section 7.4)
 * ============================================================================
 */

/* RFC 5905 Section 7.4: Clock accuracy state */
ClockAccuracyState g_clock_accuracy;

/* ============================================================================
 * End of ntpd.c
 * ============================================================================
 */

uint32_t read_u32be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void write_u32be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/* Note: All other utility functions are defined in their respective modules:
 * - nport(), npton(), print_usage(), print_version(), parse_arguments() → config.c
 * - load_server_config(), cleanup_resources(), apply_user_privileges() → main.c
 * - MARX filter functions → filter.c
 * - Time functions (ntp_timestamp_now, get_system_precision) → time_sync.c
 * - Network quality (calculate_network_quality) → ntp_algorithms.c
 * - Dispersion/poll functions → time_sync.c
 * - Timestamp conversion (ntp_timestamp_to_ns) → ntp_algorithms.c
 */
