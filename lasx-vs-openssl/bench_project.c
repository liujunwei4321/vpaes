/* bench_project.c - throughput for the LoongArch LASX4 vpaes paths in the
 * project tree, measured with the same timing core as the OpenSSL harness
 * (bench_common.h) so the numbers are directly comparable.
 *
 * Correctness gates run first: the R24 decrypt must equal the base LASX4
 * decrypt byte for byte, CTR must be an involution, and CBC-decrypt must
 * invert CBC-encrypt.  A silently wrong fast path must not be reportable as
 * a speed win.
 *
 * Build (ssh19):
 *   gcc -O2 -funroll-loops -march=loongarch64 -mlsx -mlasx -mno-strict-align \
 *       -I. -o bench_project bench_project.c \
 *       la_vpaes_dec_lasx4_r24.c la_vpaes_dec_lasx4.c la_vpaes_lasx4.c \
 *       la_vpaes_schedule.c la_vpaes_dec.c la_vpaes.c \
 *       la_vpaes_modes.c la_vpaes_modes_lsx4.c
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <lsxintrin.h>
#include <lasxintrin.h>
#include "bench_common.h"

int  la_vpaes_set_encrypt_key_lasx4(const uint8_t *key, int bits,
                                    uint8_t rk[244], __m256i rk_bcast[16]);
void la_vpaes_encrypt_4blocks(const uint8_t in[4][16], uint8_t out[4][16],
                              const uint8_t rk[244], const __m256i *rk_bcast);
int  la_vpaes_set_decrypt_key_lasx4(const uint8_t *key, int bits,
                                    uint8_t rk[244], __m256i rk_bcast[16]);
void la_vpaes_decrypt_4blocks(const uint8_t in[4][16], uint8_t out[4][16],
                              const uint8_t rk[244], const __m256i *rk_bcast);
int  la_vpaes_set_decrypt_key_lasx4_r24(const uint8_t *key, int bits,
                                        uint8_t rk[244], __m256i rk_bcast[16]);
void la_vpaes_decrypt_4blocks_r24(const uint8_t in[4][16], uint8_t out[4][16],
                                  const uint8_t *rk, const __m256i *rk_bcast);

/* LASX4 mode layer (AES-128): CTR and CBC-decrypt over 4 blocks per call.
 * Signatures declared locally so this harness does not depend on la_vpaes.h
 * being present with the matching revision. */
void la_vpaes128_ctr_crypt_4blocks_lasx(const uint8_t *in, uint8_t *out,
                                        uint8_t ctr[16], const uint8_t rk[244],
                                        const __m256i *rk_bcast);
void la_vpaes128_cbc_decrypt_4blocks_lasx(const uint8_t *in, uint8_t *out,
                                          const uint8_t prev_ct[16],
                                          const uint8_t rk[244],
                                          const __m256i *rk_bcast);
void la_vpaes128_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t n_blocks,
                             const uint8_t rk[244], uint8_t iv[16]);

enum { OP_ENC4 = 0, OP_DEC4 = 1, OP_DEC4_R24 = 2, OP_CTR4 = 3, OP_CBCD4 = 4, OP_CBCE = 5 };

typedef struct {
    uint8_t rk[256]   __attribute__((aligned(32)));
    __m256i bcast[16] __attribute__((aligned(32)));
    uint8_t iv[16]    __attribute__((aligned(16)));
    int     op;
} prj_ctx;

static void prj_op(const void *arg, const uint8_t *in, uint8_t *out, size_t len)
{
    const prj_ctx *c = (const prj_ctx *)arg;
    size_t nb = len >> 4, i;

    switch (c->op) {
    case OP_CTR4: {
        uint8_t ctr[16];
        memcpy(ctr, c->iv, 16);
        for (i = 0; i + 4 <= nb; i += 4)
            la_vpaes128_ctr_crypt_4blocks_lasx(in + (i << 4), out + (i << 4),
                                               ctr, c->rk, c->bcast);
        break;
    }
    case OP_CBCD4: {
        uint8_t prev[16];
        memcpy(prev, c->iv, 16);
        for (i = 0; i + 4 <= nb; i += 4) {
            la_vpaes128_cbc_decrypt_4blocks_lasx(in + (i << 4), out + (i << 4),
                                                 prev, c->rk, c->bcast);
            memcpy(prev, in + ((i + 3) << 4), 16);
        }
        break;
    }
    case OP_CBCE: {
        uint8_t iv[16];
        memcpy(iv, c->iv, 16);
        la_vpaes128_cbc_encrypt(in, out, nb, c->rk, iv);
        break;
    }
    default:
        for (i = 0; i + 4 <= nb; i += 4) {
            const uint8_t (*bi)[16] = (const uint8_t (*)[16])(in  + (i << 4));
            uint8_t       (*bo)[16] = (uint8_t       (*)[16])(out + (i << 4));
            if (c->op == OP_ENC4)         la_vpaes_encrypt_4blocks(bi, bo, c->rk, c->bcast);
            else if (c->op == OP_DEC4)    la_vpaes_decrypt_4blocks(bi, bo, c->rk, c->bcast);
            else                          la_vpaes_decrypt_4blocks_r24(bi, bo, c->rk, c->bcast);
        }
        break;
    }
}

static int setup(prj_ctx *c, int op, const uint8_t *key, int bits)
{
    int rc;
    c->op = op;
    switch (op) {
    case OP_ENC4:
    case OP_CBCE:  rc = la_vpaes_set_encrypt_key_lasx4(key, bits, c->rk, c->bcast); break;
    case OP_DEC4:  rc = la_vpaes_set_decrypt_key_lasx4(key, bits, c->rk, c->bcast); break;
    default:       rc = la_vpaes_set_decrypt_key_lasx4_r24(key, bits, c->rk, c->bcast); break;
    }
    return rc;
}

static uint8_t g_key[32] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
};
static uint8_t g_iv[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

/* ---- correctness gates ---- */
static int correctness(const uint8_t *data, size_t nb)
{
    static const int bitsv[3] = { 128, 192, 256 };
    prj_ctx enc, dec, r24, ctr, cdec, cenc;
    size_t sz = nb * 16;
    uint8_t *ct = malloc(sz), *p1 = malloc(sz), *p2 = malloc(sz), *p3 = malloc(sz);
    int bad = 0;

    if (!ct || !p1 || !p2 || !p3) return 1;

    for (int k = 0; k < 3; k++) {
        int bits = bitsv[k];
        if (setup(&enc, OP_ENC4, g_key, bits) || setup(&dec, OP_DEC4, g_key, bits) ||
            setup(&r24, OP_DEC4_R24, g_key, bits)) {
            printf("  setup failed AES-%d\n", bits); bad++; continue;
        }
        prj_op(&enc, data, ct, sz);
        prj_op(&dec, ct,   p1, sz);
        prj_op(&r24, ct,   p2, sz);
        if (memcmp(p1, data, sz) != 0) { printf("  ROUNDTRIP FAIL AES-%d\n", bits); bad++; }
        if (memcmp(p1, p2, sz) != 0)   { printf("  R24 != BASE DECRYPT AES-%d\n", bits); bad++; }
    }

    /* AES-128 mode layer */
    if (setup(&ctr, OP_CTR4, g_key, 128) || setup(&cdec, OP_CBCD4, g_key, 128) ||
        setup(&cenc, OP_CBCE, g_key, 128)) {
        printf("  setup failed for AES-128 mode layer\n"); bad++;
    } else {
        memcpy(ctr.iv, g_iv, 16);
        prj_op(&ctr, data, ct, sz);          /* encrypt  */
        prj_op(&ctr, ct,   p1, sz);          /* CTR is an involution */
        if (memcmp(p1, data, sz) != 0) { printf("  CTR NOT INVOLUTIVE\n"); bad++; }

        memcpy(cenc.iv, g_iv, 16);
        memcpy(cdec.iv, g_iv, 16);
        prj_op(&cenc, data, ct, sz);
        prj_op(&cdec, ct,   p3, sz);
        if (memcmp(p3, data, sz) != 0) { printf("  CBC DEC DOES NOT INVERT CBC ENC\n"); bad++; }
    }
    free(ct); free(p1); free(p2); free(p3);
    return bad;
}

int main(void)
{
    static const int bitsv[3] = { 128, 192, 256 };
    const size_t bytes = BENCH_BUF;
    const size_t nb    = bytes / 16;
    uint8_t *in  = malloc(bytes);
    uint8_t *out = malloc(bytes);

    if (!in || !out) return 1;
    for (size_t i = 0; i < bytes; i++) in[i] = (uint8_t)(i * 7 + 11);
    memset(out, 0, bytes);

    printf("== correctness gates ==\n");
    printf("   %s\n", correctness(in, nb)
                         ? "FAIL" : "PASS (r24==base dec, ECB round-trip, CTR involution, CBCdec inverts CBCenc)");

    printf("\n=== LASX4 vpaes (project), %u B buffer ===\n", BENCH_BUF);
    for (int k = 0; k < 3; k++) {
        int bits = bitsv[k];
        prj_ctx c;
        char mode[64];

        if (setup(&c, OP_ENC4, g_key, bits) == 0) {
            snprintf(mode, sizeof mode, "a%d_LASX4_ECB_enc", bits);
            bench_row(mode, prj_op, &c, in, out, bytes);
        }
        if (setup(&c, OP_DEC4_R24, g_key, bits) == 0) {
            snprintf(mode, sizeof mode, "a%d_LASX4r24_ECB_dec", bits);
            bench_row(mode, prj_op, &c, in, out, bytes);
        }
        if (setup(&c, OP_DEC4, g_key, bits) == 0) {
            snprintf(mode, sizeof mode, "a%d_LASX4_ECB_dec_base", bits);
            bench_row(mode, prj_op, &c, in, out, bytes);
        }
    }
    /* mode layer is AES-128 only */
    {
        prj_ctx c;
        memcpy(c.iv, g_iv, 16);
        if (setup(&c, OP_CTR4, g_key, 128) == 0) {
            bench_row("a128_LASX4_CTR", prj_op, &c, in, out, bytes);
        }
        memcpy(c.iv, g_iv, 16);
        if (setup(&c, OP_CBCD4, g_key, 128) == 0) {
            bench_row("a128_LASX4_CBC_dec", prj_op, &c, in, out, bytes);
        }
        memcpy(c.iv, g_iv, 16);
        if (setup(&c, OP_CBCE, g_key, 128) == 0) {
            bench_row("a128_CBC_enc_1block", prj_op, &c, in, out, bytes);
        }
    }
    free(in); free(out);
    return 0;
}
