#ifndef FILTER_H
#define FILTER_H

#include "ntpd.h"

/* ============================================================================
 * MARX Filter Functions (RFC 5905 Section 10)
 * ============================================================================
 */

void marx_add_sample_us(uint64_t ts_ns, uint64_t delay_us, int64_t offset_us);
void marx_remove_sample(int index);
uint64_t marx_median(uint64_t* arr, int count);
int marx_filter_outliers(NtpSample* samples, int count, int k);
uint64_t ntp_offset_jitter_us_locked(void);

#endif /* FILTER_H */
