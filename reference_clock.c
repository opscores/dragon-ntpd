#define _GNU_SOURCE
#include "reference_clock.h"
#include "time_sync.h"
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Support
 * ============================================================================
 */

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock State
 * ============================================================================
 */

/* RFC 5905 Section 4: Reference clock state */
ReferenceClockState g_reference_clock;

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Initialization
 * ============================================================================
 */

/**
 * reference_clock_init - Initialize reference clock subsystem
 *
 * RFC 5905 Section 4: Reference clocks are used to provide time
 * information to NTP servers. Supported types:
 * - GPS receivers (stratum 1)
 * - Atomic clocks (stratum 1)
 * - PPS (Pulse Per Second) input
 *
 * Called once during system initialization.
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_init(void) {
    ReferenceClockState* state = &g_reference_clock;

    /* Initialize all fields to zero (CERT C: Initialize all members) */
    memset(state, 0, sizeof(*state));

    /* Set default type */
    state->type = REF_CLOCK_NONE;

    /* Set default device */
    snprintf(state->device, sizeof(state->device), "/dev/null");

    /* Set default stratum (RFC 5905: 16 = unknown) */
    state->stratum = 16;

    /* Set default reference ID */
    state->ref_id = 0;

    /* Set default reference timestamp */
    state->ref_ts.sec = 0;
    state->ref_ts.frac = 0;

    return 0;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Cleanup
 * ============================================================================
 */

/**
 * reference_clock_cleanup - Cleanup reference clock resources
 *
 * RFC 5905 Section 4: Clean up reference clock resources.
 *
 * Called during system shutdown.
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_cleanup(void) {
    ReferenceClockState* state = &g_reference_clock;

    /* Close any open devices */
    if (state->type == REF_CLOCK_GPS) {
        /* GPS receiver cleanup */
        /* Close GPS device if open */
    } else if (state->type == REF_CLOCK_ATOMIC) {
        /* Atomic clock cleanup */
        /* Close atomic clock device if open */
    } else if (state->type == REF_CLOCK_PPS) {
        /* PPS input cleanup */
        /* Close PPS device if open */
    }

    return 0;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Configuration
 * ============================================================================
 */

/**
 * reference_clock_configure - Configure reference clock device
 *
 * RFC 5905 Section 4: Configure reference clock device.
 *
 * Parameters:
 *   device - Device path (e.g., /dev/ttyS0 for GPS, /dev/i2c-1 for atomic)
 *   type   - Clock type (GPS, atomic, PPS)
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_configure(const char* device, ReferenceClockType type) {
    ReferenceClockState* state = &g_reference_clock;

    /* Validate device path */
    if (device == NULL) { return -1; }

    /* Check device path length (CERT C: Buffer size check) */
    size_t len = strlen(device);
    if (len >= sizeof(state->device)) { len = sizeof(state->device) - 1; }

    /* Copy device path */
    memcpy(state->device, device, len);
    state->device[len] = '\0';

    /* Validate clock type */
    if (type < REF_CLOCK_NONE || type > REF_CLOCK_PPS) { return -1; }

    state->type = type;

    /* Enable clock */
    return reference_clock_set_enabled(true);
}

/**
 * reference_clock_set_enabled - Enable/disable reference clock
 *
 * Parameters:
 *   enabled - Enable (true) or disable (false)
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_set_enabled(bool enabled) {
    ReferenceClockState* state = &g_reference_clock;

    state->enabled = enabled;

    return 0;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Check
 * ============================================================================
 */

/**
 * reference_clock_check - Check reference clock status and update time
 *
 * RFC 5905 Section 4: Check reference clock status and update time.
 * This function handles:
 * - GPS receivers: Read time from GPS NMEA sentences
 * - Atomic clocks: Read time from I2C/SPI interface
 * - PPS: Read time from pulse-per-second input
 *
 * Called periodically to check reference clock status and update time.
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_check(void) {
    ReferenceClockState* state = &g_reference_clock;

    /* Check if clock is enabled */
    if (!state->enabled) { return 0; }

    /* Check if clock type is valid */
    if (state->type == REF_CLOCK_NONE) { return 0; }

    /* Get current time */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* Update reference timestamp */
    state->ref_ts.sec = (uint32_t)ts.tv_sec;
    state->ref_ts.frac = (uint32_t)ts.tv_nsec;

    /* Update last update time */
    state->last_update = time(NULL);

    /* Simulate offset and jitter (replace with actual hardware reading) */
    /* In production: Read from GPS/atomic clock device */
    state->offset_us = 0;
    state->jitter_us = 0;

    /* Update system time if offset is within acceptable range */
    int64_t offset_us = 0;
    if (reference_clock_get_offset(&offset_us) == 0) {
        /* Apply offset if within threshold */
        if (llabs(offset_us) < 1000000) { /* 1 second threshold */
            /* Apply time correction */
            int result = apply_time_correction_slew_or_step(offset_us);
            if (result != 0) { syslog(LOG_WARNING, "Failed to apply time correction"); }
        }
    }

    return 0;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Status
 * ============================================================================
 */

/**
 * reference_clock_get_status - Get reference clock status
 *
 * RFC 5905 Section 4: Get reference clock status.
 *
 * Return: 0 = OK, 1 = disabled, 2 = error, -1 = unknown
 */
int reference_clock_get_status(void) {
    ReferenceClockState* state = &g_reference_clock;

    if (!state->enabled) { return 1; }

    if (state->type == REF_CLOCK_NONE) { return 2; }

    return 0;
}

/**
 * reference_clock_get_offset - Get reference clock offset
 *
 * RFC 5905 Section 4: Get reference clock offset.
 *
 * Parameters:
 *   offset_us - Pointer to store offset in microseconds
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_get_offset(int64_t* offset_us) {
    ReferenceClockState* state = &g_reference_clock;

    if (offset_us == NULL) { return -1; }

    if (!state->enabled) { return -1; }

    if (state->type == REF_CLOCK_NONE) { return -1; }

    /* Get offset from state */
    *offset_us = state->offset_us;

    return 0;
}

/**
 * reference_clock_get_jitter - Get reference clock jitter
 *
 * RFC 5905 Section 4: Get reference clock jitter.
 *
 * Parameters:
 *   jitter_us - Pointer to store jitter in microseconds
 *
 * Return: 0 on success, -1 on error
 */
int reference_clock_get_jitter(uint64_t* jitter_us) {
    ReferenceClockState* state = &g_reference_clock;

    if (jitter_us == NULL) { return -1; }

    if (!state->enabled) { return -1; }

    if (state->type == REF_CLOCK_NONE) { return -1; }

    /* Get jitter from state */
    *jitter_us = state->jitter_us;

    return 0;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock State Access
 * ============================================================================
 */

/**
 * get_reference_clock_state - Get pointer to reference clock state
 *
 * RFC 5905 Section 4: Get pointer to reference clock state.
 *
 * Return: Pointer to reference clock state (never NULL)
 */
ReferenceClockState* get_reference_clock_state(void) {
    return &g_reference_clock;
}

/* ============================================================================
 * RFC 5905 Section 4: Reference Clock Type Utilities
 * ============================================================================
 */

/**
 * reference_clock_type_to_string - Get string representation of clock type
 *
 * RFC 5905 Section 4: Get string representation of clock type.
 *
 * Parameters:
 *   type - Clock type
 *
 * Return: String representation (never NULL)
 */
const char* reference_clock_type_to_string(ReferenceClockType type) {
    switch (type) {
    case REF_CLOCK_NONE: return "none";
    case REF_CLOCK_GPS: return "gps";
    case REF_CLOCK_ATOMIC: return "atomic";
    case REF_CLOCK_PPS: return "pps";
    default: return "unknown";
    }
}

/**
 * reference_clock_is_available - Check if reference clock is available
 *
 * RFC 5905 Section 4: Check if reference clock is available.
 *
 * Return: true if available, false otherwise
 */
bool reference_clock_is_available(void) {
    ReferenceClockState* state = &g_reference_clock;

    return state->enabled && state->type != REF_CLOCK_NONE;
}

/* ============================================================================
 * End of reference_clock.c
 * ============================================================================
 */
