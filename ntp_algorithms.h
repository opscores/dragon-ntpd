#ifndef NTP_ALGORITHMS_H
#define NTP_ALGORITHMS_H

#include "ntpd.h"

/* ============================================================================
 * Byzantine Fault Detection Functions (RFC 5905 Section 11.2.1)
 * ============================================================================
 */

uint8_t compute_system_offset(const int64_t* offsets, int count, int* best_idx);
int select_best_peers(const int64_t* offsets, const uint64_t* jitter, int count, int* valid_indices, int* valid_count);
int64_t majority_vote(const int64_t* offsets, int count);
bool is_false_ticker(int64_t peer_offset, int64_t cluster_offset);

/* ============================================================================
 * Network Quality Functions
 * ============================================================================
 */

uint8_t calculate_network_quality(uint64_t delay_us);

/* ============================================================================
 * Time Conversion Functions
 * ============================================================================
 */

int64_t ntp_timestamp_to_ns(const NtpTimestamp* t);

/* ============================================================================
 * NTP Utility Functions
 * ============================================================================
 */

uint32_t ntp_u16_16_from_us(uint64_t us);
bool calculate_delay_offset(const NtpTimestamp* t1, const NtpTimestamp* t2, const NtpTimestamp* t3, const NtpTimestamp* t4, uint64_t* delay_us,
                            int64_t* offset_us);
bool handle_leap_indicator(uint8_t li);
uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum);

#endif /* NTP_ALGORITHMS_H */
