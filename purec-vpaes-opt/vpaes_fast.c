/*
 * vpaes_fast.c  -  experimental multi-block interleaved variant.
 *
 * Reuses the scalar core (tables, round helpers, key schedule, dispatch)
 * from vpaes.c verbatim by renaming that file's batch-mode entry points
 * out of the way, then providing interleaved replacements that keep
 * VPAES_IL independent blocks in flight.  The scalar routines are still
 * used for tails, so semantics are inherited rather than reimplemented.
 *
 * Rationale: in the stock batch loops every mode calls
 * vpaes_encrypt_block() once per 16-byte block.  Within a block the ten
 * rounds form a strict dependency chain, and each round's T-table loads
 * cannot issue until the previous round's XOR tree retires.  With only
 * one block in flight the core stalls on L1 load latency for most of
 * the round.  Independent blocks have no such coupling, so issuing them
 * together fills the load pipeline.
 *
 * Build: gcc -O3 -Isrc -DVPAES_IL=4 ...
 */

#include <string.h>

#define vpaes_ecb_encrypt vpaes_ecb_encrypt_scalar
#define vpaes_ecb_decrypt vpaes_ecb_decrypt_scalar
#define vpaes_cbc_encrypt vpaes_cbc_encrypt_scalar
#define vpaes_cbc_decrypt vpaes_cbc_decrypt_scalar
#define vpaes_ctr_xcrypt  vpaes_ctr_xcrypt_scalar
#include "vpaes.c"
#undef vpaes_ecb_encrypt
#undef vpaes_ecb_decrypt
#undef vpaes_cbc_encrypt
#undef vpaes_cbc_decrypt
#undef vpaes_ctr_xcrypt

#ifndef VPAES_IL
#define VPAES_IL 4
#endif

void vpaes_ecb_encrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len);
void vpaes_ecb_decrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len);
void vpaes_cbc_encrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len);
void vpaes_cbc_decrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len);
void vpaes_ctr_xcrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                      const uint8_t *in, uint8_t *out, size_t len);

/* ---- interleaved round drivers ------------------------------------ */

static void enc_iblocks(uint32_t s[VPAES_IL][4], const vpaes_ctx *ctx)
{
    const uint32_t *rk = ctx->rk;
    int nr = ctx->nrounds;
    for (int r = 1; r < nr; r++) {
        const uint32_t *rkr = rk + 4 * r;
        for (int b = 0; b < VPAES_IL; b++) enc_round(s[b], rkr);
    }
    for (int b = 0; b < VPAES_IL; b++) enc_last(s[b], rk + 4 * nr);
}

static void dec_iblocks(uint32_t s[VPAES_IL][4], const vpaes_ctx *ctx)
{
    const uint32_t *rk  = ctx->rk;
    const uint32_t *rki = ctx->rk_inv;
    int nr = ctx->nrounds;
    for (int r = nr - 1; r >= 1; r--) {
        const uint32_t *rkir = rki + 4 * r;
        for (int b = 0; b < VPAES_IL; b++) dec_round(s[b], rkir);
    }
    for (int b = 0; b < VPAES_IL; b++) {
        dec_last_core(s[b]);
        s[b][0] ^= rk[0]; s[b][1] ^= rk[1];
        s[b][2] ^= rk[2]; s[b][3] ^= rk[3];
    }
}

static void load_iblocks(const uint8_t *in, uint32_t s[VPAES_IL][4],
                         const vpaes_ctx *ctx, size_t stride)
{
    for (int b = 0; b < VPAES_IL; b++) {
        bytes_to_state(in + (size_t)b * stride, s[b]);
        s[b][0] ^= ctx->rk[0]; s[b][1] ^= ctx->rk[1];
        s[b][2] ^= ctx->rk[2]; s[b][3] ^= ctx->rk[3];
    }
}

static void store_iblocks(uint8_t *out, uint32_t s[VPAES_IL][4], size_t stride)
{
    for (int b = 0; b < VPAES_IL; b++)
        state_to_bytes(s[b], out + (size_t)b * stride);
}

/* ---- ECB ---------------------------------------------------------- */

void vpaes_ecb_encrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len)
{
    const size_t chunk = (size_t)VPAES_IL * VPAES_BLOCKLEN;
    while (len >= chunk) {
        uint32_t s[VPAES_IL][4];
        load_iblocks(in, s, ctx, VPAES_BLOCKLEN);
        enc_iblocks(s, ctx);
        store_iblocks(out, s, VPAES_BLOCKLEN);
        in += chunk; out += chunk; len -= chunk;
    }
    if (len) vpaes_ecb_encrypt_scalar(ctx, in, out, len);
}

void vpaes_ecb_decrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len)
{
    const size_t chunk = (size_t)VPAES_IL * VPAES_BLOCKLEN;
    while (len >= chunk) {
        uint32_t s[VPAES_IL][4];
        for (int b = 0; b < VPAES_IL; b++) {
            bytes_to_state(in + (size_t)b * VPAES_BLOCKLEN, s[b]);
            const uint32_t *last = ctx->rk + 4 * ctx->nrounds;
            s[b][0] ^= last[0]; s[b][1] ^= last[1];
            s[b][2] ^= last[2]; s[b][3] ^= last[3];
        }
        dec_iblocks(s, ctx);
        store_iblocks(out, s, VPAES_BLOCKLEN);
        in += chunk; out += chunk; len -= chunk;
    }
    if (len) vpaes_ecb_decrypt_scalar(ctx, in, out, len);
}

/* ---- CBC encrypt: inherently serial (each block needs the previous
 * ciphertext), so no interleaving is possible; delegate.  ----------- */

void vpaes_cbc_encrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    vpaes_cbc_encrypt_scalar(ctx, iv, in, out, len);
}

/* ---- CBC decrypt: block decryptions are independent; only the final
 * chaining XOR is serial.  Save the ciphertext chain first so the
 * routine stays correct for in == out.  ---------------------------- */

void vpaes_cbc_decrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    const size_t chunk = (size_t)VPAES_IL * VPAES_BLOCKLEN;
    uint8_t prev[VPAES_BLOCKLEN];
    memcpy(prev, iv, VPAES_BLOCKLEN);
    while (len >= chunk) {
        uint8_t ct[VPAES_IL][VPAES_BLOCKLEN];
        uint8_t pt[VPAES_IL][VPAES_BLOCKLEN];
        uint32_t s[VPAES_IL][4];
        const uint32_t *last = ctx->rk + 4 * ctx->nrounds;
        for (int b = 0; b < VPAES_IL; b++) {
            memcpy(ct[b], in + (size_t)b * VPAES_BLOCKLEN, VPAES_BLOCKLEN);
            bytes_to_state(ct[b], s[b]);
            s[b][0] ^= last[0]; s[b][1] ^= last[1];
            s[b][2] ^= last[2]; s[b][3] ^= last[3];
        }
        dec_iblocks(s, ctx);
        store_iblocks(&pt[0][0], s, VPAES_BLOCKLEN);
        for (int b = 0; b < VPAES_IL; b++) {
            const uint8_t *chain = (b == 0) ? prev : ct[b - 1];
            uint8_t ob[VPAES_BLOCKLEN];
            for (int i = 0; i < VPAES_BLOCKLEN; i++)
                ob[i] = (uint8_t)(pt[b][i] ^ chain[i]);
            memcpy(out + (size_t)b * VPAES_BLOCKLEN, ob, VPAES_BLOCKLEN);
        }
        memcpy(prev, ct[VPAES_IL - 1], VPAES_BLOCKLEN);
        in += chunk; out += chunk; len -= chunk;
    }
    if (len) vpaes_cbc_decrypt_scalar(ctx, prev, in, out, len);
}

/* ---- CTR: fully parallel (counter blocks are known up front) ------ */

static void ctr_bump(uint8_t ctr[VPAES_BLOCKLEN])
{
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
                 ((uint32_t)ctr[14] <<  8) | ((uint32_t)ctr[15]);
    c++;
    ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
    ctr[14] = (uint8_t)(c >>  8); ctr[15] = (uint8_t)(c);
}

void vpaes_ctr_xcrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                      const uint8_t *in, uint8_t *out, size_t len)
{
    if (len > (size_t)0xFFFFFFFFULL * VPAES_BLOCKLEN) return;

    const size_t chunk = (size_t)VPAES_IL * VPAES_BLOCKLEN;
    uint8_t ctr[VPAES_BLOCKLEN];
    memcpy(ctr, iv, VPAES_BLOCKLEN);

    while (len >= chunk) {
        uint8_t blk[VPAES_IL][VPAES_BLOCKLEN];
        uint32_t s[VPAES_IL][4];
        for (int b = 0; b < VPAES_IL; b++) {
            memcpy(blk[b], ctr, VPAES_BLOCKLEN);
            ctr_bump(ctr);
            bytes_to_state(blk[b], s[b]);
            s[b][0] ^= ctx->rk[0]; s[b][1] ^= ctx->rk[1];
            s[b][2] ^= ctx->rk[2]; s[b][3] ^= ctx->rk[3];
        }
        enc_iblocks(s, ctx);
        for (int b = 0; b < VPAES_IL; b++) {
            uint8_t ks[VPAES_BLOCKLEN], ob[VPAES_BLOCKLEN];
            state_to_bytes(s[b], ks);
            const uint8_t *src = in + (size_t)b * VPAES_BLOCKLEN;
            for (int i = 0; i < VPAES_BLOCKLEN; i++)
                ob[i] = (uint8_t)(src[i] ^ ks[i]);
            memcpy(out + (size_t)b * VPAES_BLOCKLEN, ob, VPAES_BLOCKLEN);
        }
        in += chunk; out += chunk; len -= chunk;
    }
    if (len) vpaes_ctr_xcrypt_scalar(ctx, ctr, in, out, len);
}
