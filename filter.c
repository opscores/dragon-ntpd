#include "ntpd.h"

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * marx_add_sample_us - Add sample to MARX filter (RFC 5905 Section 10)
 * @ts_ns: Timestamp in nanoseconds
 * @delay_us: Round-trip delay in microseconds
 * @offset_us: Clock offset in microseconds
 *
 * Adds a new clock sample to the MARX filter.
 * Filter maintains up to MAX_SAMPLES (8) entries.
 * Thread-safe via g_mutex.
 */
void marx_add_sample_us(uint64_t ts_ns, uint64_t delay_us, int64_t offset_us) {
  pthread_mutex_lock(&g_mutex);

  if (g_sample_count >= MAX_SAMPLES) {
    pthread_mutex_unlock(&g_mutex);
    return;
  }

  g_samples[g_sample_count].ts = ts_ns;
  g_samples[g_sample_count].delay = delay_us;
  g_samples[g_sample_count].offset = offset_us;
  g_sample_count++;
  pthread_mutex_unlock(&g_mutex);
}

/**
 * marx_remove_sample - Remove sample from MARX filter by index
 * @index: Index of sample to remove
 *
 * Removes sample and shifts remaining entries.
 * Thread-safe via g_mutex.
 */
void marx_remove_sample(int index) {
  if (index >= 0 && index < g_sample_count) {
    pthread_mutex_lock(&g_mutex);
    const size_t move_count = (size_t)(g_sample_count - index - 1);
    memmove(&g_samples[index], &g_samples[index + 1],
            move_count * sizeof(NtpSample));
    g_sample_count--;
    pthread_mutex_unlock(&g_mutex);
  }
}

/**
 * marx_median - Calculate median from array
 * @arr: Pointer to array of values
 * @count: Number of elements
 *
 * Uses simple bubble sort and returns median.
 * For even count, returns average of two middle values.
 *
 * Return: Median value
 */
uint64_t marx_median(uint64_t *arr, int count) {
  if (arr == NULL || count <= 0)
    return 0;

  for (int i = 0; i < count - 1; i++) {
    for (int j = 0; j < count - i - 1; j++) {
      if (arr[j] > arr[j + 1]) {
        uint64_t tmp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = tmp;
      }
    }
  }

  return (count % 2 == 0) ? arr[count / 2 - 1] : arr[count / 2];
}

/**
 * marx_filter_outliers - Filter outliers using Modified Z-Score (MARX
 * algorithm)
 * @samples: Pointer to array of samples
 * @count: Number of samples
 * @k: Z-score threshold (typically 3)
 *
 * Uses Median Absolute Deviation (MAD) to filter outliers.
 * Returns count of valid samples after filtering.
 *
 * Return: Number of valid samples after filtering
 */
int marx_filter_outliers(NtpSample *samples, int count, int k) {
  if (samples == NULL || count < 3)
    return count;
  if (count > MAX_SAMPLES)
    count = MAX_SAMPLES;

  const int original_count = count;

  uint64_t delays[MAX_SAMPLES];
  for (int i = 0; i < count; i++) {
    delays[i] = samples[i].delay;
  }

  uint64_t median = marx_median(delays, count);

  uint64_t abs_devs[MAX_SAMPLES];
  for (int i = 0; i < count; i++) {
    abs_devs[i] = (samples[i].delay > median) ? (samples[i].delay - median)
                                              : (median - samples[i].delay);
  }
  uint64_t mad = marx_median(abs_devs, count);

  uint64_t kmad;
  if (mad == 0) {
    kmad = 0;
  } else {
    if (k == 0) {
      kmad = 0;
    } else {
      uint64_t k64 = (uint64_t)k;
      if (k64 > (UINT64_MAX / mad)) {
        kmad = UINT64_MAX;
      } else {
        kmad = k64 * mad;
        if (kmad > UINT64_MAX - median) {
          kmad = UINT64_MAX;
        }
      }
    }
  }

  uint64_t threshold;
  if (kmad == 0) {
    threshold = median;
  } else {
    if (kmad > UINT64_MAX - median) {
      threshold = UINT64_MAX;
    } else {
      threshold = median + kmad;
    }
  }

  int filtered = 0;
  for (int i = 0; i < count; i++) {
    if (samples[i].delay <= threshold) {
      if (filtered != i) {
        samples[filtered] = samples[i];
      }
      filtered++;
    }
  }

  return (filtered < original_count) ? filtered : original_count;
}

/**
 * ntp_offset_jitter_us_locked - Calculate jitter from samples (WITH mutex held)
 *
 * Calculates RMS jitter from clock offset samples.
 * Must be called with g_mutex locked.
 *
 * Return: Jitter in microseconds, or 0 if < 2 samples
 */
uint64_t ntp_offset_jitter_us_locked(void) {
  pthread_mutex_lock(&g_mutex);

  if (g_sample_count <= 1) {
    pthread_mutex_unlock(&g_mutex);
    return 0;
  }

  long double mean = 0.0L;
  for (int i = 0; i < g_sample_count; i++) {
    mean += (long double)g_samples[i].offset;
  }
  mean /= (long double)g_sample_count;

  long double var = 0.0L;
  for (int i = 0; i < g_sample_count; i++) {
    long double d = (long double)g_samples[i].offset - mean;
    var += d * d;
  }

  if (g_sample_count > 1) {
    var /= (long double)(g_sample_count - 1);
  }

  if (var < 0.0L)
    var = 0.0L;
  long double sd = sqrtl(var);
  if (sd < 0.0L)
    sd = 0.0L;
  if (sd > (long double)UINT64_MAX) {
    pthread_mutex_unlock(&g_mutex);
    return UINT64_MAX;
  }

  pthread_mutex_unlock(&g_mutex);
  return (uint64_t)sd;
}
