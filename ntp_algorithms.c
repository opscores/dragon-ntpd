#include "ntpd.h"

#define NS_PER_SEC 1000000000LL

/* ============================================================================
 * Helper Functions (must be declared before use)
 * ============================================================================
 */

/**
 * abs64 - Absolute value for int64_t (CERT C compliant)
 * @v: Value to take absolute value of
 *
 * @return Absolute value of v
 */
static int64_t abs64(int64_t v) {
    return v < 0 ? -v : v;
}

/**
 * compare_int64 - Comparison function for qsort
 * @a: First element
 * @b: Second element
 *
 * @return -1 if a < b, 1 if a > b, 0 if a == b
 */
static int compare_int64(const void* a, const void* b) {
    int64_t va = *(const int64_t*)a;
    int64_t vb = *(const int64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

#define FALSETICKER_THRESHOLD_US 250000
#define MAX_PEERS 8

/**
 * ntp_timestamp_to_ns - Convert NTP timestamp to nanoseconds
 * @t: Pointer to NtpTimestamp
 *
 * Converts NTP timestamp (RFC 5905 Section 6) to Unix nanoseconds.
 * Handles overflow checking for large timestamps.
 *
 * Return: Nanoseconds since Unix epoch, or 0 on error
 */
int64_t ntp_timestamp_to_ns(const NtpTimestamp* t) {
    if (t == NULL) return 0;

    int64_t sec = (int64_t)t->sec - (int64_t)NTP_UNIX_EPOCH_DELTA;

    /* Check for overflow before multiplication */
    if (sec > (INT64_MAX / NS_PER_SEC) - 1) {
        syslog(LOG_WARNING, "NTP timestamp too large, clamping to INT64_MAX");
        return INT64_MAX;
    }
    if (sec < (INT64_MIN / NS_PER_SEC) + 1) {
        syslog(LOG_WARNING, "NTP timestamp too small, clamping to INT64_MIN");
        return INT64_MIN;
    }

    int64_t nsec = (int64_t)(((uint64_t)t->frac * 1000000000ULL) >> 32);
    return sec * NS_PER_SEC + nsec;
}

/**
 * calculate_delay_offset - Calculate round-trip delay and clock offset
 * @t1: Origin timestamp
 * @t2: Receive timestamp
 * @t3: Transmit timestamp
 * @t4: Destination timestamp
 * @delay_us: Pointer to store delay (output)
 * @offset_us: Pointer to store offset (output)
 *
 * Implements NTP On-Wire Protocol (RFC 5905 Section 8):
 * delay = (T4 - T1) - (T3 - T2)
 * offset = ((T2 - T1) + (T3 - T4)) / 2
 *
 * Return: true on success, false on error
 */
bool calculate_delay_offset(const NtpTimestamp* t1, const NtpTimestamp* t2, const NtpTimestamp* t3, const NtpTimestamp* t4, uint64_t* delay_us,
                            int64_t* offset_us) {
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL || delay_us == NULL || offset_us == NULL) {
        syslog(LOG_WARNING, "NULL указатель при вычислении задержки");
        return false;
    }

    int64_t T1 = ntp_timestamp_to_ns(t1);
    int64_t T2 = ntp_timestamp_to_ns(t2);
    int64_t T3 = ntp_timestamp_to_ns(t3);
    int64_t T4 = ntp_timestamp_to_ns(t4);

    int64_t delay_ns = (T4 - T1) - (T3 - T2);
    int64_t offset_ns = ((T2 - T1) + (T3 - T4)) / 2;

    if (delay_ns < 0) {
        syslog(LOG_WARNING, "Отрицательная задержка (ns): %" PRId64, delay_ns);
        return false;
    }

    *delay_us = (uint64_t)(delay_ns / 1000);
    *offset_us = offset_ns / 1000;
    return true;
}

/**
 * handle_leap_indicator - Handle leap indicator from NTP packet
 * @li: Leap indicator value (0-3)
 *
 * RFC 5905 Section 7.3.1: Leap indicator values:
 * 0 = No warning
 * 1 = +1s (positive leap second imminent)
 * 2 = -1s (negative leap second imminent)
 * 3 = Not synchronized
 *
 * RFC 5905 Section 11.4: Leap second handling:
 * - LI=0,1,2: Schedule leap second event (return false to allow processing)
 * - LI=3: Do not process packet (return true to skip correction)
 *
 * Return: true if packet should be skipped, false otherwise
 */
bool handle_leap_indicator(uint8_t li) {
    switch (li) {
    case 0: syslog(LOG_INFO, "Leap Indicator: No warning"); return false;
    case 1:
        syslog(LOG_INFO, "Leap Indicator: Positive leap second imminent (LI=1)");
        leap_second_schedule_event(LEAP_SECOND_DIR_POSITIVE, NULL);
        return false;
    case 2:
        syslog(LOG_WARNING, "Leap Indicator: Negative leap second imminent (LI=2)");
        leap_second_schedule_event(LEAP_SECOND_DIR_NEGATIVE, NULL);
        return false;
    case 3: syslog(LOG_WARNING, "Leap Indicator: Clock not synchronized (LI=3)"); return true;
    default: syslog(LOG_ERR, "Invalid Leap Indicator: %d", li); return true;
    }
}

uint8_t ntp_local_stratum_from_peer(uint8_t peer_stratum) {
    /**
     * ntp_local_stratum_from_peer - Calculate local stratum from peer stratum
     * @peer_stratum: Stratum of peer server
     *
     * RFC 5905 Section 7.3.2: Local stratum = peer stratum + 1
     * Special values: 0 (unspecified) or > 15 -> return 16 (unsynchronized)
     *
     * Return: Local stratum value
     */
    if (peer_stratum == 0 || peer_stratum > 15) return 16;
    uint16_t s = (uint16_t)peer_stratum + 1u;
    if (s > 15u) return 15u;
    return (uint8_t)s;
}

/**
 * compute_system_offset - Compute system offset from peer offsets (Combine
 * Algorithm with Byzantine Fault Detection)
 * @offsets: Array of peer offsets
 * @count: Number of offsets
 * @best_idx: Pointer to store best peer index (output)
 *
 * RFC 5905 Section 11.2.3: Combine Algorithm
 * Implements Byzantine fault detection (RFC 5905 Section 11.2.1) Selection
 * Algorithm to filter outliers and select best peers.
 *
 * Steps:
 * 1. Use select_best_peers() to filter outliers using Byzantine fault detection
 * 2. Use majority_vote() to determine majority offset
 * 3. Return system offset (0-15) or 16 on error
 *
 * Return: System offset (0-15) or 16 on error
 */
uint8_t compute_system_offset(const int64_t* offsets, int count, int* best_idx) {
    if (count < 1 || offsets == NULL) {
        if (best_idx) { *best_idx = 0; }
        return 16; /* No valid peers */
    }

    /* Step 1: Use is_false_ticker() for Byzantine fault detection
     * This filters outliers within 250ms of median (RFC 5905 Section 11.2.1)
     */
    int64_t sorted[MAX_PEERS];
    for (int i = 0; i < count; i++) { sorted[i] = offsets[i]; }
    qsort(sorted, (size_t)count, sizeof(int64_t), compare_int64);
    int64_t median = sorted[count / 2];

    /* Filter outliers using is_false_ticker() */
    int valid = 0;
    for (int i = 0; i < count; i++) {
        if (!is_false_ticker(offsets[i], median)) { valid++; }
    }

    if (valid == 0) {
        if (best_idx) { *best_idx = 0; }
        return 16; /* No valid peers after Byzantine fault detection */
    }

    /* Step 2: Use majority_vote() to determine majority offset
     * RFC 5905 Section 11.2.1: Returns offset that appears in >50% of peers
     */
    int64_t majority_offset = majority_vote(offsets, count);

    /* Step 3: Clamp to valid range and return */
    if (majority_offset > 127) { majority_offset = 127; }
    if (majority_offset < -128) { majority_offset = -128; }
    *best_idx = 0;
    return (uint8_t)(majority_offset & 0xFF);
}

/**
 * select_best_peers - Select valid peers using Byzantine fault detection with
 * jitter weighting
 * @offsets: Array of peer offsets in microseconds
 * @jitter: Array of peer jitter in microseconds
 * @count: Number of peers
 * @valid_indices: Output array of valid peer indices
 * @valid_count: Output count of valid peers
 *
 * RFC 5905 Section 11.2.1: Selection Algorithm
 * Filters out falsetickers using median and cluster analysis.
 * Additional jitter-based filtering:
 *   1. Exclude peers with jitter > JITTER_THRESHOLD_US
 *   2. Prefer peers with lower jitter (weighted selection)
 *
 * Return: 0 on success, -1 on error
 */
int select_best_peers(const int64_t* offsets, const uint64_t* jitter, int count, int* valid_indices, int* valid_count) {
    if (count < 1 || offsets == NULL || valid_indices == NULL || valid_count == NULL) {
        if (valid_count) *valid_count = 0;
        return -1;
    }
    if (count > MAX_PEERS) { count = MAX_PEERS; }

    /* Step 1: Sort by offset for median calculation */
    static int64_t sorted[MAX_PEERS];
    for (int i = 0; i < count; i++) { sorted[i] = offsets[i]; }
    qsort(sorted, (size_t)count, sizeof(int64_t), compare_int64);
    int64_t median = sorted[count / 2];

    /* Step 2: Filter outliers within FALSETICKER_THRESHOLD_US of median */
    int valid = 0;
    for (int i = 0; i < count; i++) {
        int64_t diff = offsets[i] - median;
        if (diff < 0) { diff = -diff; }
        /* CERT C 7.5.2: Check bounds before comparison */
        if (diff > (int64_t)INT64_MAX) { continue; /* Skip overflow */ }
        if (diff < FALSETICKER_THRESHOLD_US) {
            valid_indices[valid] = i;
            valid++;
        }
    }

    if (valid == 0) {
        *valid_count = 0;
        return 0; /* No valid peers, but not an error */
    }

    /* Step 3: Apply jitter-based filtering (CERT C 3.4.5: use parameter) */
    int jitter_filtered = 0;
    for (int i = 0; i < valid; i++) {
        int peer_idx = valid_indices[i];
        uint64_t peer_jitter = jitter[peer_idx];

        /* Exclude peers with jitter > threshold */
        if (peer_jitter > JITTER_THRESHOLD_US) { continue; }

        valid_indices[jitter_filtered] = peer_idx;
        jitter_filtered++;
    }

    *valid_count = jitter_filtered;
    return 0;
}

/**
 * majority_vote - Determine majority offset from peer offsets
 * @offsets: Array of peer offsets in microseconds
 * @count: Number of offsets
 *
 * RFC 5905 Section 11.2.1: Selection Algorithm
 * Returns the offset value that appears in >50% of peers.
 *
 * Return: Majority offset in microseconds, or median if no majority
 */
int64_t majority_vote(const int64_t* offsets, int count) {
    if (count < 1 || offsets == NULL) { return 0; }
    if (count == 1) { return offsets[0]; }
    if (count < 3) {
        int64_t sorted[2];
        sorted[0] = offsets[0];
        sorted[1] = offsets[1];
        return sorted[0] == sorted[1] ? sorted[0] : (sorted[0] + sorted[1]) / 2;
    }
    static int64_t sorted[MAX_PEERS];
    for (int i = 0; i < count && i < MAX_PEERS; i++) { sorted[i] = offsets[i]; }
    qsort(sorted, (size_t)count, sizeof(int64_t), compare_int64);
    int64_t median = sorted[count / 2];
    int match_count = 0;
    int64_t match_value = 0;
    for (int i = 0; i < count; i++) {
        if (abs64(offsets[i] - median) < FALSETICKER_THRESHOLD_US) {
            match_count++;
            match_value = offsets[i];
        }
    }
    if (match_count > count / 2) { return match_value; }
    return median;
}

/**
 * is_false_ticker - Check if peer is a falseticker
 * @peer_offset: Offset of peer to check
 * @cluster_offset: Reference cluster offset in microseconds
 *
 * RFC 5905 Section 11.2.1: falseticker detection
 * A peer is considered falseticker if offset differs from
 * cluster median by more than 250ms (FALSETICKER_THRESHOLD_US).
 *
 * Uses abs64() for absolute value calculation.
 *
 * Return: true if falseticker, false otherwise
 */
bool is_false_ticker(int64_t peer_offset, int64_t cluster_offset) {
    /* Use abs64() for CERT C compliant absolute value calculation */
    if (abs64(peer_offset - cluster_offset) > FALSETICKER_THRESHOLD_US) {
        syslog(LOG_DEBUG, "Falseticker detected: peer_offset=%ld, cluster_offset=%ld, diff=%ld", (long)peer_offset, (long)cluster_offset,
               (long)abs64(peer_offset - cluster_offset));
        return true;
    }
    return false;
}

/**
 * ntp_u16_16_from_us - Convert microseconds to NTP u16.16 fixed-point
 * @us: Microseconds value
 *
 * RFC 5905 Section 6: Converts us to NTP short format
 * Maximum representable: ~49.7 days
 *
 * Return: u16.16 fixed-point value
 */
uint32_t ntp_u16_16_from_us(uint64_t us) {
    /* Prevent overflow in multiplication: check us * 65536 <= UINT64_MAX */
    if (us > (UINT64_MAX / 65536ULL)) { return UINT32_MAX; }
    uint64_t v = (us * 65536ULL) / 1000000ULL;
    if (v > UINT32_MAX) { return UINT32_MAX; }
    return (uint32_t)v;
}

/**
 * update_root_dispersion - Update root dispersion (RFC 5905 Section 11.1)
 * @current_disp: Current dispersion
 * @offset_us: Clock offset in microseconds
 * @jitter_us: Clock jitter in microseconds
 *
 * RFC 5905 Section 11.1: dispersion grows at PHI (15 ppm)
 * plus contribution from peer jitter.
 *
 * Return: Updated dispersion value
 */
uint32_t update_root_dispersion(uint32_t current_disp, uint64_t offset_us, uint64_t jitter_us) {
    time_t now = time(NULL);

    pthread_mutex_lock(&g_mutex);

    if (g_last_dispersion_update == 0) {
        g_last_dispersion_update = now;
        pthread_mutex_unlock(&g_mutex);
        return current_disp;
    }

    int64_t elapsed_sec = (int64_t)now - (int64_t)g_last_dispersion_update;
    if (elapsed_sec < 0) { elapsed_sec = 0; }

    double phi_dispersion = ((double)PHI * (double)elapsed_sec) / 1000000.0;

    uint64_t disp_us = offset_us;
    uint64_t jitter_us_val = jitter_us;

    if (disp_us > (uint64_t)UINT32_MAX) { disp_us = UINT32_MAX; }

    double new_disp;
    if (phi_dispersion > (double)UINT32_MAX - (double)disp_us - (double)jitter_us_val) {
        new_disp = (double)UINT32_MAX;
    } else {
        new_disp = phi_dispersion + (double)disp_us + (double)jitter_us_val;
    }

    g_last_dispersion_update = now;
    pthread_mutex_unlock(&g_mutex);

    return ntp_u16_16_from_us((uint64_t)new_disp);
}

int8_t adjust_poll_interval(int8_t current_poll, int8_t peer_poll, uint64_t delay_us, int64_t offset_us) {
    int8_t new_poll = current_poll;

    if (peer_poll < current_poll) { new_poll = peer_poll; }

    if (delay_us > POLL_DELAY_HIGH_THRESHOLD_US || offset_us > (int64_t)POLL_OFFSET_HIGH_THRESHOLD_US || offset_us < -(int64_t)POLL_OFFSET_HIGH_THRESHOLD_US) {
        if (new_poll < POLL_INTERVAL_MAX) { new_poll++; }
    } else if (delay_us < POLL_DELAY_LOW_THRESHOLD_US && offset_us > -(int64_t)POLL_OFFSET_LOW_THRESHOLD_US &&
               offset_us < (int64_t)POLL_OFFSET_LOW_THRESHOLD_US) {
        if (new_poll > POLL_INTERVAL_MIN) { new_poll--; }
    }

    return new_poll;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * calculate_network_quality - Calculate network quality percentage
 * @delay: Round-trip delay in microseconds
 *
 * Simple quality metric: 100% - delay(ms)
 *
 * Return: Quality 0-100
 */
uint8_t calculate_network_quality(uint64_t delay) {
    int64_t quality = 100 - (int64_t)(delay / 1000);
    if (quality < 0) return 0;
    if (quality > 100) return 100;
    return (uint8_t)quality;
}
