#ifndef TIME_SYNC_H
#define TIME_SYNC_H

#include "ntpd.h"

/* ============================================================================
 * Frequency Discipline Functions (RFC 5905 Section 11.3)
 * ============================================================================
 */

int init_frequency_discipline(void);
int load_frequency_persistent(void);
int save_frequency_persistent(void);
int apply_frequency_adjustment(double ppm);
int update_frequency_discipline(int64_t offset_us, int poll_exp);
double calculate_frequency_ppm(int64_t offset_us, time_t delta_sec);

/* ============================================================================
 * Time Correction Functions
 * ============================================================================
 */

int apply_time_correction_slew_or_step(int64_t offset_us);
int sync_ntp_time(const char* ip, const char* port);
NtpTimestamp ntp_timestamp_now(void);
int8_t get_system_precision(void);

/* Note: Leap second functions are declared in leap_second.h */

/* ============================================================================
 * Dispersion Update Function
 * ============================================================================
 */

uint32_t update_root_dispersion(uint32_t root_disp, uint64_t offset_us, uint64_t jitter_us);

/* ============================================================================
 * Poll Interval Adjustment Functions
 * ============================================================================
 */

int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us);

#endif /* TIME_SYNC_H */
