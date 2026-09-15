/* optbench.c - low-noise throughput harness for vpaes_pure_c experiments.
 *
 * Measures only the modes that have optimisation headroom, using a fixed
 * time budget per sample and a median over several samples so that
 * flag-level and algorithmic changes can be compared reliably.
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "vpaes.h"

#define BUFSZ   (4u << 20)
#define SAMPLES 7
#define BUDGET  0.20           /* seconds per sample */

static uint8_t *inbuf, *outbuf;
static uint8_t key[32];
static uint8_t iv[16];
static vpaes_ctx ctx128, ctx192, ctx256;
static volatile uint64_t sink;

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* ---- mode wrappers: all take (ctx, in, out, len) ---- */
static void w_ecb_enc(const vpaes_ctx *c, const uint8_t *i, uint8_t *o, size_t n)
{ vpaes_ecb_encrypt(c, i, o, n); }

static void w_ecb_dec(const vpaes_ctx *c, const uint8_t *i, uint8_t *o, size_t n)
{ vpaes_ecb_decrypt(c, i, o, n); }

static void w_cbc_enc(const vpaes_ctx *c, const uint8_t *i, uint8_t *o, size_t n)
{ vpaes_cbc_encrypt(c, iv, i, o, n); }

static void w_cbc_dec(const vpaes_ctx *c, const uint8_t *i, uint8_t *o, size_t n)
{ vpaes_cbc_decrypt(c, iv, i, o, n); }

static void w_ctr(const vpaes_ctx *c, const uint8_t *i, uint8_t *o, size_t n)
{ vpaes_ctr_xcrypt(c, iv, i, o, n); }

typedef void (*xf_t)(const vpaes_ctx *, const uint8_t *, uint8_t *, size_t);

/* Returns median MB/s over SAMPLES fixed-budget samples. */
static double bench(xf_t f, const vpaes_ctx *c, double *out_best)
{
    double s[SAMPLES];
    for (int k = 0; k < SAMPLES; k++) {
        double t0 = now_s(), t1;
        size_t total = 0;
        do {
            f(c, inbuf, outbuf, BUFSZ);
            total += BUFSZ;
            t1 = now_s();
        } while (t1 - t0 < BUDGET);
        s[k] = (double)total / (t1 - t0) / 1e6;
        sink += outbuf[k];
    }
    qsort(s, SAMPLES, sizeof(double), cmp_d);
    if (out_best) *out_best = s[SAMPLES - 1];
    return s[SAMPLES / 2];
}

static void row(const char *name, xf_t f, const vpaes_ctx *c)
{
    double best;
    double med = bench(f, c, &best);
    printf("  %-24s %8.1f MB/s   (best %8.1f)\n", name, med, best);
    /* machine-readable line consumed by the comparison driver */
    printf("R %s %.1f\n", name, best);
}

int main(void)
{
    inbuf  = malloc(BUFSZ);
    outbuf = malloc(BUFSZ);
    if (!inbuf || !outbuf) return 1;
    for (size_t i = 0; i < BUFSZ; i++) inbuf[i] = (uint8_t)(i * 7 + 11);
    memset(outbuf, 0, BUFSZ);
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 16; i++) iv[i]  = (uint8_t)(0xa0 + i);

    vpaes_set_key(&ctx128, key, 16);
    vpaes_set_key(&ctx192, key, 24);
    vpaes_set_key(&ctx256, key, 32);

    printf("vpaes_pure_c optbench   buffer=%u B  samples=%d  budget=%.2fs\n",
           BUFSZ, SAMPLES, BUDGET);
    printf("== AES-128 ==\n");
    row("a128_ECB_enc",  w_ecb_enc, &ctx128);
    row("a128_ECB_dec",  w_ecb_dec, &ctx128);
    row("a128_CBC_enc",  w_cbc_enc, &ctx128);
    row("a128_CBC_dec",  w_cbc_dec, &ctx128);
    row("a128_CTR",      w_ctr,     &ctx128);
    printf("== AES-192 ==\n");
    row("a192_ECB_enc",  w_ecb_enc, &ctx192);
    row("a192_CTR",      w_ctr,     &ctx192);
    printf("== AES-256 ==\n");
    row("a256_ECB_enc",  w_ecb_enc, &ctx256);
    row("a256_CBC_enc",  w_cbc_enc, &ctx256);
    row("a256_CTR",      w_ctr,     &ctx256);

    if (sink == 0x1234567) return 2;   /* keep the sink observable */
    return 0;
}
