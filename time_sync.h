#ifndef TIME_SYNC_H
#define TIME_SYNC_H

#include "ntpd.h"

/* ============================================================================
 * RFC 5905 Section 11.3 - Clock Discipline Constants
 * ============================================================================
 */

/* RFC 5905 Section 11.3 - Clock discipline constants */
#define CLOCK_PHI 15e-6            /* Max frequency error (s/s) = 15 PPM */
#define CLOCK_PLLGAIN 8            /* PLL loop gain (log2) */
#define CLOCK_FLLGAIN 4            /* FLL loop gain (log2) */
#define CLOCK_ALLAN_INTERCEPT 1500 /* Allan intercept (sec), RFC 5905 default */
#define FREQ_UPDATE_INTERVAL_MIN_SEC 64

/* RFC 5905 Section 11.3 - Loop filter constants */
#define FLL_ALPHA 0.1                    /* FLL filter coefficient */
#define PLL_ALPHA 0.01                   /* PLL filter coefficient */
#define FREQ_DEADBAND_PPM 0.001          /* Deadband for small errors (1 mPPM) */
#define FREQ_MAX_STEP_PPM 10.0           /* Max PPM step per update (rate limiting) */
#define PLL_STABLE_COUNT 5               /* PLL stability counter threshold */
#define FLL_HIGH_GAIN 0.5                /* High FLL gain for recovery */
#define FLL_LOW_GAIN 0.1                 /* Low FLL gain for stability */
#define PLL_HIGH_GAIN 0.1                /* High PLL gain for fast convergence */
#define PLL_NOMINAL_GAIN 0.01            /* Nominal PLL gain (standard) */
#define PLL_LOW_GAIN 0.001               /* Low PLL gain for stability */
#define FLL_RECOVERY_THRESHOLD_US 500000 /* Threshold for PLL->FLL transition (500ms) */
#define PLL_THRESHOLD_US 10000           /* Threshold for FLL->PLL transition (10ms) */
#define JITTER_HIGH_THRESHOLD_US 200000  /* 200ms - high jitter */
#define JITTER_LOW_THRESHOLD_US 50000    /* 50ms - low jitter */

/* RFC 5905 Section 11.3 - Gain scheduling constants */
#define PGATE 4    /* Poll-adjust gate */
#define LIMIT 30   /* Poll-adjust threshold */
#define MINPOLL 6  /* Minimum poll interval (64 sec) */
#define MAXPOLL 17 /* Maximum poll interval (36.4 hours) */

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

/* ============================================================================
 * RFC 5905 Section 7.4 - Clock Accuracy Estimation Functions
 * ============================================================================
 */

/* Calculate clock precision (ρ) - RFC 5905 Section 6.2 */
double calculate_clock_precision(void);

/* Calculate Allan variance for clock stability */
double calculate_allan_variance(int64_t offset_us, time_t delta_sec);

/* Update clock accuracy state */
void update_clock_accuracy(int64_t offset_us, time_t delta_sec);

/* Initialize clock accuracy state */
void init_clock_accuracy(void);

/* Get clock accuracy state */
ClockAccuracyState* get_clock_accuracy_state(void);

/* Get clock precision */
double get_clock_precision(void);

/* Get clock stability metric */
double get_clock_stability(void);

#endif /* TIME_SYNC_H */
