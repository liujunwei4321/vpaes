/* bench_common.h - shared timing core so every implementation in this
 * comparison is measured by byte-identical code: same buffer size, same
 * fixed time budget per sample, same median/best reporting, same
 * "R <mode> <best MB/s>" machine-readable output line.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define BENCH_BUF     (4u << 20)   /* 4 MiB working set */
#define BENCH_SAMPLES 7
#define BENCH_BUDGET  0.20         /* seconds per sample */

static double bench_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

typedef void (*bench_fn)(const void *arg, const uint8_t *in,
                         uint8_t *out, size_t len);

static int bench_cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double bench_run(bench_fn f, const void *arg, const uint8_t *in,
                        uint8_t *out, size_t len, double *best)
{
    double s[BENCH_SAMPLES];
    for (int k = 0; k < BENCH_SAMPLES; k++) {
        double t0 = bench_now(), t1;
        size_t total = 0;
        do {
            f(arg, in, out, len);
            total += len;
            t1 = bench_now();
        } while (t1 - t0 < BENCH_BUDGET);
        s[k] = (double)total / (t1 - t0) / 1e6;
    }
    qsort(s, BENCH_SAMPLES, sizeof(double), bench_cmp);
    if (best) *best = s[BENCH_SAMPLES - 1];
    return s[BENCH_SAMPLES / 2];
}

static void bench_row(const char *mode, bench_fn f, const void *arg,
                      const uint8_t *in, uint8_t *out, size_t len)
{
    double best;
    double med = bench_run(f, arg, in, out, len, &best);
    printf("  %-22s %8.1f MB/s   (best %8.1f)\n", mode, med, best);
    fflush(stdout);
    printf("R %s %.1f\n", mode, best);
}

#endif /* BENCH_COMMON_H */
