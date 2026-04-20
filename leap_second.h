#ifndef LEAP_SECOND_H
#define LEAP_SECOND_H

#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * Leap Second Constants (RFC 5905 Section 11.4)
 * ============================================================================
 */

#define LEAP_SECOND_DIR_NONE 0
#define LEAP_SECOND_DIR_POSITIVE 1
#define LEAP_SECOND_DIR_NEGATIVE 2

/* ============================================================================
 * Leap Second Functions (RFC 5905 Section 11.4)
 * ============================================================================
 */

int leap_second_init(void);
int leap_second_cleanup(void);
int leap_second_check_file(void);
int leap_second_schedule_event(uint8_t leap_dir, const char* file_name);
int leap_second_apply_correction(uint8_t leap_dir);
int leap_second_check_and_apply(void);

#endif /* LEAP_SECOND_H */
