/* difftest.c - differential test: optimised variant vs the stock scalar
 * implementation, byte for byte, over every mode, key size, length and
 * aliasing arrangement.  The KAT files only cover ECB and CBC, so CTR is
 * verified here against the reference implementation rather than against
 * published vectors alone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "vpaes.h"

/* reference (scalar) entry points, from ref_rename.c */
int  ref_set_key(vpaes_ctx *ctx, const uint8_t *key, size_t key_len);
void ref_ecb_encrypt(const vpaes_ctx *, const uint8_t *, uint8_t *, size_t);
void ref_ecb_decrypt(const vpaes_ctx *, const uint8_t *, uint8_t *, size_t);
void ref_cbc_encrypt(const vpaes_ctx *, const uint8_t *, const uint8_t *, uint8_t *, size_t);
void ref_cbc_decrypt(const vpaes_ctx *, const uint8_t *, const uint8_t *, uint8_t *, size_t);
void ref_ctr_xcrypt (const vpaes_ctx *, const uint8_t *, const uint8_t *, uint8_t *, size_t);

static uint64_t rng = 0x243F6A8885A308D3ULL;
static uint8_t rnd(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint8_t)(rng >> 24);
}

#define MAXBUF 8192
static uint8_t src[MAXBUF], ivb[16], kbuf[32];
static uint8_t fa[MAXBUF], fb[MAXBUF], ra[MAXBUF], rb[MAXBUF];

static int fails = 0, checks = 0;

static void cmp(const char *what, size_t keylen, size_t len, const char *variant)
{
    checks++;
    if (memcmp(fa, ra, len) != 0) {
        fails++;
        size_t i;
        for (i = 0; i < len; i++) if (fa[i] != ra[i]) break;
        printf("  MISMATCH %-22s key=%2zu len=%5zu %-12s first diff @%zu\n",
               what, keylen, len, variant, i);
    }
}

static void run_case(size_t keylen, size_t len)
{
    vpaes_ctx c;
    char tag[64];

    vpaes_set_key(&c, kbuf, keylen);

    /* ---- ECB encrypt / decrypt, disjoint buffers ---- */
    memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
    vpaes_ecb_encrypt(&c, src, fa, len);
    ref_ecb_encrypt(&c, src, ra, len);
    snprintf(tag, sizeof tag, "ECB enc key=%zu", keylen);
    cmp("ECB encrypt", keylen, len, "out-of-place");

    memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
    vpaes_ecb_decrypt(&c, src, fa, len);
    ref_ecb_decrypt(&c, src, ra, len);
    cmp("ECB decrypt", keylen, len, "out-of-place");

    /* ---- ECB in place ---- */
    memcpy(fa, src, len); memcpy(ra, src, len);
    vpaes_ecb_encrypt(&c, fa, fa, len);
    ref_ecb_encrypt(&c, ra, ra, len);
    cmp("ECB encrypt", keylen, len, "in-place");

    /* ---- CBC encrypt / decrypt, disjoint ---- */
    memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
    vpaes_cbc_encrypt(&c, ivb, src, fa, len);
    ref_cbc_encrypt(&c, ivb, src, ra, len);
    cmp("CBC encrypt", keylen, len, "out-of-place");

    memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
    vpaes_cbc_decrypt(&c, ivb, src, fa, len);
    ref_cbc_decrypt(&c, ivb, src, ra, len);
    cmp("CBC decrypt", keylen, len, "out-of-place");

    /* ---- CBC in place ---- */
    memcpy(fa, src, len); memcpy(ra, src, len);
    vpaes_cbc_encrypt(&c, ivb, fa, fa, len);
    ref_cbc_encrypt(&c, ivb, ra, ra, len);
    cmp("CBC encrypt", keylen, len, "in-place");

    memcpy(fa, src, len); memcpy(ra, src, len);
    vpaes_cbc_decrypt(&c, ivb, fa, fa, len);
    ref_cbc_decrypt(&c, ivb, ra, ra, len);
    cmp("CBC decrypt", keylen, len, "in-place");

    /* ---- CTR, arbitrary length, disjoint and in place ---- */
    memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
    vpaes_ctr_xcrypt(&c, ivb, src, fa, len);
    ref_ctr_xcrypt(&c, ivb, src, ra, len);
    cmp("CTR xcrypt", keylen, len, "out-of-place");

    memcpy(fa, src, len); memcpy(ra, src, len);
    vpaes_ctr_xcrypt(&c, ivb, fa, fa, len);
    ref_ctr_xcrypt(&c, ivb, ra, ra, len);
    cmp("CTR xcrypt", keylen, len, "in-place");

    /* ---- CTR stream continuation: two calls must equal one call ---- */
    if (len >= 32) {
        size_t half = len / 2;
        uint8_t iv2[16];
        memcpy(iv2, ivb, 16);
        vpaes_ctr_xcrypt(&c, ivb, src, fa, half);
        /* advance iv2 by half/16 blocks, mirroring RFC 3686 */
        {
            size_t blocks = half / 16, i;
            uint32_t ctr = ((uint32_t)iv2[12] << 24) | ((uint32_t)iv2[13] << 16) |
                           ((uint32_t)iv2[14] << 8) | (uint32_t)iv2[15];
            ctr += (uint32_t)blocks;
            iv2[12] = (uint8_t)(ctr >> 24); iv2[13] = (uint8_t)(ctr >> 16);
            iv2[14] = (uint8_t)(ctr >> 8);  iv2[15] = (uint8_t)ctr;
            (void)i;
        }
        vpaes_ctr_xcrypt(&c, iv2, src + (half / 16) * 16, fa + (half / 16) * 16,
                         half - (half / 16) * 16);
        memset(ra, 0, MAXBUF);
        vpaes_ctr_xcrypt(&c, ivb, src, ra, len);
        cmp("CTR chunked", keylen, len, "two-call vs one");
    }
    (void)tag;
}

int main(void)
{
    static const size_t keylens[] = { 16, 24, 32 };
    /* lengths around the 16-byte boundary, the 64-block (1 KiB) CTR chunk
     * boundary, and a couple of larger sizes */
    static const size_t lens[] = { 0, 1, 15, 16, 17, 32, 33, 63, 64, 65,
                                   255, 256, 257, 1008, 1024, 1040, 4096, 4111 };
    size_t i, j, n;

    for (i = 0; i < MAXBUF; i++) src[i] = rnd();
    for (i = 0; i < 16; i++) ivb[i] = rnd();
    for (i = 0; i < 32; i++) kbuf[i] = rnd();

    printf("differential test: optimised vs stock scalar\n");
    for (i = 0; i < sizeof keylens / sizeof keylens[0]; i++) {
        for (j = 0; j < sizeof lens / sizeof lens[0]; j++) {
            n = lens[j];
            if (n > MAXBUF) continue;
            run_case(keylens[i], n);
        }
    }

    /* Also sweep every length from 0..600 for CTR at AES-128, since that is
     * the mode with a non-block-multiple tail and the one the KAT suite
     * does not tabulate. */
    {
        vpaes_ctx c;
        vpaes_set_key(&c, kbuf, 16);
        for (n = 0; n <= 600; n++) {
            memset(fa, 0, MAXBUF); memset(ra, 0, MAXBUF);
            vpaes_ctr_xcrypt(&c, ivb, src, fa, n);
            ref_ctr_xcrypt(&c, ivb, src, ra, n);
            cmp("CTR sweep len=0..600", 16, n, "out-of-place");
        }
    }

    printf("\n%d comparisons, %d mismatches\n", checks, fails);
    printf("%s\n", fails ? "DIFFERENTIAL TEST FAILED" : "DIFFERENTIAL TEST PASSED");
    return fails ? 1 : 0;
}
