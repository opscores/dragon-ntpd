#define _GNU_SOURCE
#include "ntpd.h"

/* ============================================================================
 * Leap Second Handling (RFC 5905 Section 11.4)
 * ============================================================================
 *
 * Leap second notification:
 * - Process leap second files from /etc/ntp/leap-YYYYMMDD.s
 * - Schedule leap second events 60 seconds before end of minute
 *
 * Leap second events:
 * - LI=1: Positive leap second (+1s at end of minute)
 * - LI=2: Negative leap second (-1s at end of minute)
 *
 * Implementation:
 * - leap_second_check_file(): Check leap second files for imminent events
 * - leap_second_schedule_event(): Schedule correction 60s before end of minute
 * - leap_second_apply_correction(): Apply leap second correction
 * - leap_second_cleanup(): Cleanup resources
 *
 * Security considerations (CERT C):
 * - Check for NULL pointers
 * - Check for buffer overflows
 * - Check for integer overflows
 * - Use safe string functions
 * ============================================================================
 */

/* Leap second state */
typedef struct {
    bool initialized;
    time_t last_check_time;
    time_t next_check_time;
    int64_t pending_offset_us;
    uint8_t pending_leap_dir;
    bool event_scheduled;
    time_t event_time;
    char leap_file_dir[64];
    char leap_file_prefix[32];
    char leap_file_suffix[8];
    int check_interval_sec;
    int event_interval_sec;
} LeapSecondState;

/* Global leap second state */
static LeapSecondState g_leap_second_state;
static pthread_mutex_t g_leap_second_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * leap_second_get_leap_dir - Get leap second direction from leap indicator
 * @li: Leap indicator value (0-3)
 *
 * RFC 5905 Section 7.3.1: Leap indicator values:
 * 0 = No warning
 * 1 = +1s (positive leap second)
 * 2 = -1s (negative leap second)
 * 3 = Not synchronized
 *
 * Return: Leap second direction (LEAP_SECOND_DIR_POSITIVE,
 * LEAP_SECOND_DIR_NEGATIVE, 0)
 */
/**
 * leap_second_get_end_of_minute_time - Get time when current minute ends
 *
 * Return: Time in seconds when current minute ends, 0 on error
 */
static time_t leap_second_get_end_of_minute_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) { return 0; }
    time_t now = (time_t)ts.tv_sec;
    return now + (60 - (now % 60));
}

/**
 * leap_second_get_file_name - Get leap second file name for given date
 * @year: Year (e.g., 2024)
 * @month: Month (1-12)
 * @day: Day (1-31)
 * @buf: Buffer to store file name
 * @buf_size: Buffer size
 *
 * Return: 0 on success, -1 on error
 */
static int leap_second_get_file_name(int year, int month, int day, char* buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) { return -1; }

    /* Format: leap-YYYYMMDD.s */
    int year_digits = 0;
    int temp = year;
    while (temp > 0) {
        year_digits++;
        temp /= 10;
    }

    if (year_digits > 4) { return -1; /* Year too large */ }

    snprintf(buf, buf_size, "%sleap-%04d%02d%02d%s", g_leap_second_state.leap_file_dir, year, month, day, g_leap_second_state.leap_file_suffix);

    return 0;
}

/**
 * leap_second_get_current_date - Get current date components
 * @year: Pointer to store year (output)
 * @month: Pointer to store month (output)
 * @day: Pointer to store day (output)
 *
 * Return: 0 on success, -1 on error
 */
static int leap_second_get_current_date(int* year, int* month, int* day) {
    struct tm* tm_info;
    time_t now = time(NULL);
    tm_info = localtime(&now);

    if (tm_info == NULL) { return -1; }

    *year = tm_info->tm_year + 1900;
    *month = tm_info->tm_mon + 1;
    *day = tm_info->tm_mday;

    return 0;
}

/* ============================================================================
 * Leap Second File Handling (RFC 5905 Section 11.4)
 * ============================================================================
 */

/**
 * leap_second_check_file - Check leap second files for imminent events
 *
 * RFC 5905 Section 11.4: Leap second files are located in /etc/ntp/
 * File format: leap-YYYYMMDD.s
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_check_file(void) {
    pthread_mutex_lock(&g_leap_second_mutex);

    /* Check if already initialized */
    if (!g_leap_second_state.initialized) {
        syslog(LOG_DEBUG, "Leap second check: not initialized");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Check if enough time has passed since last check */
    time_t now = time(NULL);
    if (now - g_leap_second_state.last_check_time < g_leap_second_state.check_interval_sec) {
        syslog(LOG_DEBUG, "Leap second check: not enough time passed (%ds < %ds)", (int)(now - g_leap_second_state.last_check_time),
               g_leap_second_state.check_interval_sec);
        pthread_mutex_unlock(&g_leap_second_mutex);
        return 0;
    }

    /* Get current date */
    int year, month, day;
    if (leap_second_get_current_date(&year, &month, &day) != 0) {
        syslog(LOG_ERR, "Leap second check: failed to get current date");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Get leap second file name */
    char file_name[256];
    if (leap_second_get_file_name(year, month, day, file_name, sizeof(file_name)) != 0) {
        syslog(LOG_ERR, "Leap second check: failed to get file name");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Check if leap second file exists */
    struct stat stat_buf;
    if (stat(file_name, &stat_buf) == 0) {
        syslog(LOG_INFO, "Leap second file found: %s", file_name);

        /* Read leap second direction from file */
        FILE* fp = fopen(file_name, "r");
        if (fp == NULL) {
            syslog(LOG_ERR, "Leap second check: failed to open file: %s", file_name);
            pthread_mutex_unlock(&g_leap_second_mutex);
            return -1;
        }

        uint8_t leap_dir;
        if (fscanf(fp, "%hhu", &leap_dir) != 1) {
            syslog(LOG_ERR, "Leap second check: failed to read leap direction from file: %s", file_name);
            fclose(fp);
            pthread_mutex_unlock(&g_leap_second_mutex);
            return -1;
        }

        fclose(fp);

        /* Validate leap second direction */
        if (leap_dir != LEAP_SECOND_DIR_POSITIVE && leap_dir != LEAP_SECOND_DIR_NEGATIVE) {
            syslog(LOG_ERR, "Leap second check: invalid leap direction in file: %s (value=%hhu)", file_name, leap_dir);
            pthread_mutex_unlock(&g_leap_second_mutex);
            return -1;
        }

        /* Schedule leap second event */
        if (leap_second_schedule_event(leap_dir, file_name) == 0) {
            syslog(LOG_INFO, "Leap second event scheduled: %s at %ld seconds from now", leap_dir == LEAP_SECOND_DIR_POSITIVE ? "positive" : "negative",
                   g_leap_second_state.event_time - now);
        } else {
            syslog(LOG_ERR, "Leap second check: failed to schedule event");
        }
    } else {
        syslog(LOG_DEBUG, "Leap second check: no leap second file found for %04d-%02d-%02d", year, month, day);
    }

    /* Update last check time */
    g_leap_second_state.last_check_time = now;
    pthread_mutex_unlock(&g_leap_second_mutex);

    return 0;
}

/**
 * leap_second_schedule_event - Schedule leap second event
 * @leap_dir: Leap second direction (LEAP_SECOND_DIR_POSITIVE or
 * LEAP_SECOND_DIR_NEGATIVE)
 * @file_name: Leap second file name
 *
 * RFC 5905 Section 11.4: Schedule correction 60 seconds before end of minute
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_schedule_event(uint8_t leap_dir, const char* file_name) {
    (void)file_name; /* Reserved for future use - file-based leap second
                        scheduling */

    pthread_mutex_lock(&g_leap_second_mutex);

    /* Check if event already scheduled */
    if (g_leap_second_state.event_scheduled) {
        syslog(LOG_DEBUG, "Leap second schedule: event already scheduled");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Get end of minute time */
    time_t end_of_minute = leap_second_get_end_of_minute_time();
    if (end_of_minute == 0) {
        syslog(LOG_ERR, "Leap second schedule: failed to get end of minute time");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Schedule event 60 seconds before end of minute (RFC 5905 Section 11.4) */
    time_t event_time = end_of_minute - g_leap_second_state.event_interval_sec;
    time_t now = time(NULL);

    if (event_time <= now) {
        syslog(LOG_WARNING, "Leap second schedule: event time has passed (event_time=%ld, now=%ld)", (long)event_time, (long)now);
        /* Still schedule it for next minute */
        event_time = end_of_minute + g_leap_second_state.event_interval_sec;
    }

    /* Store pending offset (60 seconds = 60,000,000 us) */
    g_leap_second_state.pending_offset_us = leap_dir == LEAP_SECOND_DIR_POSITIVE ? (int64_t)60000000 : (int64_t)(-60000000);
    g_leap_second_state.pending_leap_dir = leap_dir;
    g_leap_second_state.event_time = event_time;
    g_leap_second_state.event_scheduled = true;

    syslog(LOG_INFO, "Leap second event scheduled: %s leap second at %ld seconds from now", leap_dir == LEAP_SECOND_DIR_POSITIVE ? "positive" : "negative",
           (long)(event_time - now));

    pthread_mutex_unlock(&g_leap_second_mutex);

    return 0;
}

/* ============================================================================
 * Leap Second Event Handling
 * ============================================================================
 */

/**
 * leap_second_apply_correction - Apply leap second correction
 * @leap_dir: Leap second direction (LEAP_SECOND_DIR_POSITIVE or
 * LEAP_SECOND_DIR_NEGATIVE)
 *
 * RFC 5905 Section 11.4: Apply leap second correction at scheduled time
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_apply_correction(uint8_t leap_dir) {
    (void)leap_dir; /* Use stored pending_leap_dir instead */

    pthread_mutex_lock(&g_leap_second_mutex);

    /* Check if event is scheduled */
    if (!g_leap_second_state.event_scheduled) {
        syslog(LOG_DEBUG, "Leap second apply: no event scheduled");
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Check if enough time has passed since event time */
    time_t now = time(NULL);
    if (now < g_leap_second_state.event_time) {
        syslog(LOG_WARNING, "Leap second apply: event not yet due (now=%ld, event_time=%ld)", (long)now, (long)g_leap_second_state.event_time);
        pthread_mutex_unlock(&g_leap_second_mutex);
        return -1;
    }

    /* Get pending offset */
    int64_t offset_us = g_leap_second_state.pending_offset_us;
    uint8_t dir = g_leap_second_state.pending_leap_dir;

    /* Apply correction using apply_time_correction_slew_or_step() */
    int result = apply_time_correction_slew_or_step(offset_us);

    if (result == 0) {
        syslog(LOG_INFO, "Leap second correction applied: %s leap second (%" PRId64 " us)", dir == LEAP_SECOND_DIR_POSITIVE ? "positive" : "negative",
               offset_us);
    } else {
        syslog(LOG_ERR, "Leap second correction failed: %s", strerror(errno));
    }

    /* Clear pending event */
    g_leap_second_state.pending_offset_us = 0;
    g_leap_second_state.pending_leap_dir = 0;
    g_leap_second_state.event_scheduled = false;

    pthread_mutex_unlock(&g_leap_second_mutex);

    return result;
}

/**
 * leap_second_check_and_apply - Check and apply leap second correction if
 * needed
 *
 * Check if leap second event is due and apply correction if needed.
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_check_and_apply(void) {
    pthread_mutex_lock(&g_leap_second_mutex);

    /* Check if event is scheduled and due */
    if (g_leap_second_state.event_scheduled) {
        time_t now = time(NULL);
        if (now >= g_leap_second_state.event_time) {
            /* Apply correction */
            uint8_t leap_dir = g_leap_second_state.pending_leap_dir;
            int result = leap_second_apply_correction(leap_dir);

            if (result == 0) {
                syslog(LOG_INFO, "Leap second event completed: %s leap second", leap_dir == LEAP_SECOND_DIR_POSITIVE ? "positive" : "negative");
            } else {
                syslog(LOG_ERR, "Leap second event failed: %s", strerror(errno));
            }
        }
    }

    pthread_mutex_unlock(&g_leap_second_mutex);

    return 0;
}

/* ============================================================================
 * Leap Second Initialization and Cleanup
 * ============================================================================
 */

/**
 * leap_second_init - Initialize leap second handling
 *
 * RFC 5905 Section 11.4: Initialize leap second state
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_init(void) {
    pthread_mutex_lock(&g_leap_second_mutex);

    /* Initialize state */
    g_leap_second_state.initialized = true;
    g_leap_second_state.last_check_time = 0;
    g_leap_second_state.next_check_time = 0;
    g_leap_second_state.pending_offset_us = 0;
    g_leap_second_state.pending_leap_dir = 0;
    g_leap_second_state.event_scheduled = false;
    g_leap_second_state.event_time = 0;

    /* Initialize file paths */
    strncpy(g_leap_second_state.leap_file_dir, LEAP_SECOND_FILE_DIR, sizeof(g_leap_second_state.leap_file_dir) - 1);
    strncpy(g_leap_second_state.leap_file_prefix, LEAP_SECOND_FILE_PREFIX, sizeof(g_leap_second_state.leap_file_prefix) - 1);
    strncpy(g_leap_second_state.leap_file_suffix, LEAP_SECOND_FILE_SUFFIX, sizeof(g_leap_second_state.leap_file_suffix) - 1);

    /* Initialize intervals */
    g_leap_second_state.check_interval_sec = LEAP_SECOND_CHECK_INTERVAL_SEC;
    g_leap_second_state.event_interval_sec = LEAP_SECOND_EVENT_INTERVAL_SEC;

    syslog(LOG_INFO,
           "Leap second handling initialized: check_interval=%ds, "
           "event_interval=%ds",
           g_leap_second_state.check_interval_sec, g_leap_second_state.event_interval_sec);

    pthread_mutex_unlock(&g_leap_second_mutex);

    return 0;
}

/**
 * leap_second_cleanup - Cleanup leap second handling
 *
 * RFC 5905 Section 11.4: Cleanup leap second state
 *
 * Return: 0 on success, -1 on error
 */
int leap_second_cleanup(void) {
    pthread_mutex_lock(&g_leap_second_mutex);

    /* Clear state */
    g_leap_second_state.initialized = false;
    g_leap_second_state.last_check_time = 0;
    g_leap_second_state.next_check_time = 0;
    g_leap_second_state.pending_offset_us = 0;
    g_leap_second_state.pending_leap_dir = 0;
    g_leap_second_state.event_scheduled = false;
    g_leap_second_state.event_time = 0;

    syslog(LOG_INFO, "Leap second handling cleaned up");

    pthread_mutex_unlock(&g_leap_second_mutex);

    return 0;
}
