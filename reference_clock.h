#ifndef REFERENCE_CLOCK_H
#define REFERENCE_CLOCK_H

#include "ntpd.h"
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Support
 * ============================================================================
 */

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Types
 * ============================================================================
 */

/* RFC 5905 Section 4: Reference clock types */
typedef enum {
    REF_CLOCK_NONE = 0,
    REF_CLOCK_GPS,    /* GPS receiver (stratum 1) */
    REF_CLOCK_ATOMIC, /* Atomic clock (stratum 1) */
    REF_CLOCK_PPS     /* Pulse Per Second input */
} ReferenceClockType;

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock States
 * ============================================================================
 */

typedef struct {
    ReferenceClockType type; /* Clock type */
    char device[64];         /* Device path (e.g., /dev/ttyS0) */
    bool enabled;            /* Clock enabled status */
    time_t last_update;      /* Last update timestamp */
    int64_t offset_us;       /* Time offset in microseconds */
    uint64_t jitter_us;      /* Jitter in microseconds */
    uint8_t stratum;         /* Stratum level */
    NtpTimestamp ref_ts;     /* Reference timestamp */
    char ref_id[4];          /* Reference ID (RFC 5905: 4-char ASCII string) */
} ReferenceClockState;

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Constants
 * ============================================================================
 */

#define REF_CLOCK_FILE STATE_DIR "/reference_clock"
#define REF_CLOCK_OFFSET_MAX_PPM 128.0       /* Max frequency offset (PPM) */
#define REF_CLOCK_UPDATE_INTERVAL_SEC 1      /* Update interval (seconds) */
#define REF_CLOCK_JITTER_THRESHOLD_US 100000 /* 100ms - high jitter */

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Functions
 * ============================================================================
 */

/* Initialize reference clock subsystem */
int reference_clock_init(void);

/* Cleanup reference clock resources */
int reference_clock_cleanup(void);

/* Check reference clock status and update time */
int reference_clock_check(void);

/* Get reference clock status */
int reference_clock_get_status(void);

/* Get reference clock offset */
int reference_clock_get_offset(int64_t* offset_us);

/* Get reference clock jitter */
int reference_clock_get_jitter(uint64_t* jitter_us);

/* Configure reference clock device */
int reference_clock_configure(const char* device, ReferenceClockType type);

/* Enable/disable reference clock */
int reference_clock_set_enabled(bool enabled);

/* Get reference clock state */
ReferenceClockState* get_reference_clock_state(void);

/* ============================================================================
 * RFC 5905 Section 4: Utility Functions
 * ============================================================================
 */

/* Get reference clock type string */
const char* reference_clock_type_to_string(ReferenceClockType type);

/* Check if reference clock is available */
bool reference_clock_is_available(void);

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock State
 * ============================================================================
 */

extern ReferenceClockState g_reference_clock;

/* ============================================================================
 * End of reference_clock.h
 * ============================================================================
 */

#endif /* REFERENCE_CLOCK_H */
