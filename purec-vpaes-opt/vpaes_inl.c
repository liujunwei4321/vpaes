/*
 * vpaes_inl.c  -  experimental fully-inlined batch variant.
 *
 * The stock code binds ctx->enc_dispatch/dec_dispatch to enc_128/192/256 and
 * calls them through the function pointer once per block.  That has two
 * costs the disassembly makes visible:
 *
 *   1. an indirect call per 16-byte block (no inlining);
 *   2. worse, the state array's address escapes into that call, so the
 *      callee cannot prove the T-table loads (const uint32_t[]) do not
 *      alias the state stores (uint32_t).  GCC therefore re-materialises
 *      the state in memory on every round; enc_128's compiled body shows
 *      st.w=40 / ld.w=204 for what should be a register-resident loop.
 *
 * Here the state lives in four local scalars that are never address-taken,
 * all round work is macro-inlined, and the key size is dispatched once
 * outside the block loop.  No state touches memory between the initial load
 * and the final store.
 *
 * Build: gcc -O3 -Isrc -c vpaes_inl.c
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

/* ---- byte <-> scalar state, matching vpaes.c conventions exactly ---- */

#define LDS(S0,S1,S2,S3, P) do {                        \
    uint64_t lo_, hi_;                                  \
    memcpy(&lo_, (P), 8); memcpy(&hi_, (P) + 8, 8);      \
    lo_ = bswap64(lo_); hi_ = bswap64(hi_);             \
    S0 = (uint32_t)(lo_ >> 32); S1 = (uint32_t)lo_;     \
    S2 = (uint32_t)(hi_ >> 32); S3 = (uint32_t)hi_;     \
} while (0)

#define STS(P, S0,S1,S2,S3) do {                                            \
    uint64_t lo_ = bswap64(((uint64_t)(uint32_t)(S0) << 32) | (uint32_t)(S1)); \
    uint64_t hi_ = bswap64(((uint64_t)(uint32_t)(S2) << 32) | (uint32_t)(S3)); \
    memcpy((P), &lo_, 8); memcpy((P) + 8, &hi_, 8);                         \
} while (0)

/* ---- round macros operating on the enclosing s0..s3 scalars ---- */

#define ENC_ROUND(RKP) do {                                             \
    uint32_t t0_ = s0, t1_ = s1, t2_ = s2, t3_ = s3;                    \
    s0 = Te0[(t0_ >> 24) & 0xff] ^ Te1[(t1_ >> 16) & 0xff] ^            \
         Te2[(t2_ >>  8) & 0xff] ^ Te3[(t3_      ) & 0xff] ^ (RKP)[0];  \
    s1 = Te0[(t1_ >> 24) & 0xff] ^ Te1[(t2_ >> 16) & 0xff] ^            \
         Te2[(t3_ >>  8) & 0xff] ^ Te3[(t0_      ) & 0xff] ^ (RKP)[1];  \
    s2 = Te0[(t2_ >> 24) & 0xff] ^ Te1[(t3_ >> 16) & 0xff] ^            \
         Te2[(t0_ >>  8) & 0xff] ^ Te3[(t1_      ) & 0xff] ^ (RKP)[2];  \
    s3 = Te0[(t3_ >> 24) & 0xff] ^ Te1[(t0_ >> 16) & 0xff] ^            \
         Te2[(t1_ >>  8) & 0xff] ^ Te3[(t2_      ) & 0xff] ^ (RKP)[3];  \
} while (0)

#define ENC_LAST(RKP) do {                                              \
    uint32_t t0_ = s0, t1_ = s1, t2_ = s2, t3_ = s3;                    \
    s0 = (T0d[(t0_ >> 24) & 0xff] | T1d[(t1_ >> 16) & 0xff] |           \
          T2d[(t2_ >>  8) & 0xff] | T3d[(t3_      ) & 0xff]) ^ (RKP)[0];\
    s1 = (T0d[(t1_ >> 24) & 0xff] | T1d[(t2_ >> 16) & 0xff] |           \
          T2d[(t3_ >>  8) & 0xff] | T3d[(t0_      ) & 0xff]) ^ (RKP)[1];\
    s2 = (T0d[(t2_ >> 24) & 0xff] | T1d[(t3_ >> 16) & 0xff] |           \
          T2d[(t0_ >>  8) & 0xff] | T3d[(t1_      ) & 0xff]) ^ (RKP)[2];\
    s3 = (T0d[(t3_ >> 24) & 0xff] | T1d[(t0_ >> 16) & 0xff] |           \
          T2d[(t1_ >>  8) & 0xff] | T3d[(t2_      ) & 0xff]) ^ (RKP)[3];\
} while (0)

#define DEC_ROUND(RKIP) do {                                            \
    uint32_t t0_ = s0, t1_ = s1, t2_ = s2, t3_ = s3;                    \
    s0 = Td0[(t0_ >> 24) & 0xff] ^ Td1[(t3_ >> 16) & 0xff] ^            \
         Td2[(t2_ >>  8) & 0xff] ^ Td3[(t1_      ) & 0xff] ^ (RKIP)[0]; \
    s1 = Td0[(t1_ >> 24) & 0xff] ^ Td1[(t0_ >> 16) & 0xff] ^            \
         Td2[(t3_ >>  8) & 0xff] ^ Td3[(t2_      ) & 0xff] ^ (RKIP)[1]; \
    s2 = Td0[(t2_ >> 24) & 0xff] ^ Td1[(t1_ >> 16) & 0xff] ^            \
         Td2[(t0_ >>  8) & 0xff] ^ Td3[(t3_      ) & 0xff] ^ (RKIP)[2]; \
    s3 = Td0[(t3_ >> 24) & 0xff] ^ Td1[(t2_ >> 16) & 0xff] ^            \
         Td2[(t1_ >>  8) & 0xff] ^ Td3[(t0_      ) & 0xff] ^ (RKIP)[3]; \
} while (0)

#define DEC_LAST() do {                                                 \
    uint32_t t0_ = s0, t1_ = s1, t2_ = s2, t3_ = s3;                    \
    s0 = TD0d[(t0_ >> 24) & 0xff] | TD1d[(t3_ >> 16) & 0xff] |          \
         TD2d[(t2_ >>  8) & 0xff] | TD3d[(t1_      ) & 0xff];           \
    s1 = TD0d[(t1_ >> 24) & 0xff] | TD1d[(t0_ >> 16) & 0xff] |          \
         TD2d[(t3_ >>  8) & 0xff] | TD3d[(t2_      ) & 0xff];           \
    s2 = TD0d[(t2_ >> 24) & 0xff] | TD1d[(t1_ >> 16) & 0xff] |          \
         TD2d[(t0_ >>  8) & 0xff] | TD3d[(t3_      ) & 0xff];           \
    s3 = TD0d[(t3_ >> 24) & 0xff] | TD1d[(t2_ >> 16) & 0xff] |          \
         TD2d[(t1_ >>  8) & 0xff] | TD3d[(t0_      ) & 0xff];           \
} while (0)

/* ---- per-key-size batch generators ---- */

#define GEN_ECB_ENC(NAME, NR)                                            \
static void NAME(const vpaes_ctx *ctx, const uint8_t *in,                \
                 uint8_t *out, size_t len)                               \
{                                                                        \
    const uint32_t *rk = ctx->rk;                                        \
    while (len >= 16) {                                                  \
        uint32_t s0, s1, s2, s3;                                         \
        LDS(s0, s1, s2, s3, in);                                         \
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];              \
        for (int r = 1; r < (NR); r++) { ENC_ROUND(rk + 4 * r); }        \
        ENC_LAST(rk + 4 * (NR));                                         \
        STS(out, s0, s1, s2, s3);                                        \
        in += 16; out += 16; len -= 16;                                  \
    }                                                                    \
}

#define GEN_ECB_DEC(NAME, NR)                                            \
static void NAME(const vpaes_ctx *ctx, const uint8_t *in,                \
                 uint8_t *out, size_t len)                               \
{                                                                        \
    const uint32_t *rk  = ctx->rk;                                       \
    const uint32_t *rki = ctx->rk_inv;                                   \
    const uint32_t *last = rk + 4 * (NR);                                \
    while (len >= 16) {                                                  \
        uint32_t s0, s1, s2, s3;                                         \
        LDS(s0, s1, s2, s3, in);                                         \
        s0 ^= last[0]; s1 ^= last[1]; s2 ^= last[2]; s3 ^= last[3];      \
        for (int r = (NR) - 1; r >= 1; r--) { DEC_ROUND(rki + 4 * r); }  \
        DEC_LAST();                                                      \
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];              \
        STS(out, s0, s1, s2, s3);                                        \
        in += 16; out += 16; len -= 16;                                  \
    }                                                                    \
}

#define GEN_CBC_ENC(NAME, NR)                                            \
static void NAME(const vpaes_ctx *ctx, const uint8_t iv[16],             \
                 const uint8_t *in, uint8_t *out, size_t len)            \
{                                                                        \
    const uint32_t *rk = ctx->rk;                                        \
    uint64_t plo_, phi_;                                                 \
    memcpy(&plo_, iv, 8); memcpy(&phi_, iv + 8, 8);                      \
    while (len >= 16) {                                                  \
        uint32_t s0, s1, s2, s3;                                         \
        uint64_t lo_, hi_;                                               \
        memcpy(&lo_, in, 8); memcpy(&hi_, in + 8, 8);                    \
        lo_ ^= plo_; hi_ ^= phi_;                                        \
        lo_ = bswap64(lo_); hi_ = bswap64(hi_);                          \
        s0 = (uint32_t)(lo_ >> 32); s1 = (uint32_t)lo_;                  \
        s2 = (uint32_t)(hi_ >> 32); s3 = (uint32_t)hi_;                  \
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];              \
        for (int r = 1; r < (NR); r++) { ENC_ROUND(rk + 4 * r); }        \
        ENC_LAST(rk + 4 * (NR));                                         \
        plo_ = bswap64(((uint64_t)s0 << 32) | s1);                       \
        phi_ = bswap64(((uint64_t)s2 << 32) | s3);                       \
        memcpy(out, &plo_, 8); memcpy(out + 8, &phi_, 8);                \
        in += 16; out += 16; len -= 16;                                  \
    }                                                                    \
}

#define GEN_CBC_DEC(NAME, NR)                                            \
static void NAME(const vpaes_ctx *ctx, const uint8_t iv[16],             \
                 const uint8_t *in, uint8_t *out, size_t len)            \
{                                                                        \
    const uint32_t *rk  = ctx->rk;                                       \
    const uint32_t *rki = ctx->rk_inv;                                   \
    const uint32_t *last = rk + 4 * (NR);                                \
    uint64_t plo_, phi_;                                                 \
    memcpy(&plo_, iv, 8); memcpy(&phi_, iv + 8, 8);                      \
    while (len >= 16) {                                                  \
        uint32_t s0, s1, s2, s3;                                         \
        uint64_t clo_, chi_, lo_, hi_;                                   \
        memcpy(&clo_, in, 8); memcpy(&chi_, in + 8, 8);                  \
        lo_ = bswap64(clo_); hi_ = bswap64(chi_);                        \
        s0 = (uint32_t)(lo_ >> 32); s1 = (uint32_t)lo_;                  \
        s2 = (uint32_t)(hi_ >> 32); s3 = (uint32_t)hi_;                  \
        s0 ^= last[0]; s1 ^= last[1]; s2 ^= last[2]; s3 ^= last[3];      \
        for (int r = (NR) - 1; r >= 1; r--) { DEC_ROUND(rki + 4 * r); }  \
        DEC_LAST();                                                      \
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];              \
        lo_ = bswap64(((uint64_t)s0 << 32) | s1) ^ plo_;                 \
        hi_ = bswap64(((uint64_t)s2 << 32) | s3) ^ phi_;                 \
        memcpy(out, &lo_, 8); memcpy(out + 8, &hi_, 8);                  \
        plo_ = clo_; phi_ = chi_;                                        \
        in += 16; out += 16; len -= 16;                                  \
    }                                                                    \
}

GEN_ECB_ENC(ecb_enc_128, VPAES_Nr_128)
GEN_ECB_ENC(ecb_enc_192, VPAES_Nr_192)
GEN_ECB_ENC(ecb_enc_256, VPAES_Nr_256)
GEN_ECB_DEC(ecb_dec_128, VPAES_Nr_128)
GEN_ECB_DEC(ecb_dec_192, VPAES_Nr_192)
GEN_ECB_DEC(ecb_dec_256, VPAES_Nr_256)
GEN_CBC_ENC(cbc_enc_128, VPAES_Nr_128)
GEN_CBC_ENC(cbc_enc_192, VPAES_Nr_192)
GEN_CBC_ENC(cbc_enc_256, VPAES_Nr_256)
GEN_CBC_DEC(cbc_dec_128, VPAES_Nr_128)
GEN_CBC_DEC(cbc_dec_192, VPAES_Nr_192)
GEN_CBC_DEC(cbc_dec_256, VPAES_Nr_256)

/* ECB-style batch functions take (ctx, in, out, len). */
#define DISPATCH3(ctx, in, out, len, f128, f192, f256, scalar_call)      \
    do {                                                                 \
        switch ((ctx)->nrounds) {                                        \
        case 10: f128((ctx), (in), (out), (len)); break;                 \
        case 12: f192((ctx), (in), (out), (len)); break;                 \
        case 14: f256((ctx), (in), (out), (len)); break;                 \
        default: scalar_call; break;                                     \
        }                                                                \
    } while (0)

/* CBC-style batch functions take (ctx, iv, in, out, len). */
#define DISPATCH_IV(ctx, iv, in, out, len, f128, f192, f256, scalar_call) \
    do {                                                                 \
        switch ((ctx)->nrounds) {                                        \
        case 10: f128((ctx), (iv), (in), (out), (len)); break;           \
        case 12: f192((ctx), (iv), (in), (out), (len)); break;           \
        case 14: f256((ctx), (iv), (in), (out), (len)); break;           \
        default: scalar_call; break;                                     \
        }                                                                \
    } while (0)

void vpaes_ecb_encrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len)
{
    DISPATCH3(ctx, in, out, len, ecb_enc_128, ecb_enc_192, ecb_enc_256,
              vpaes_ecb_encrypt_scalar(ctx, in, out, len));
}

void vpaes_ecb_decrypt(const vpaes_ctx *ctx,
                       const uint8_t *in, uint8_t *out, size_t len)
{
    DISPATCH3(ctx, in, out, len, ecb_dec_128, ecb_dec_192, ecb_dec_256,
              vpaes_ecb_decrypt_scalar(ctx, in, out, len));
}

void vpaes_cbc_encrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    DISPATCH_IV(ctx, iv, in, out, len, cbc_enc_128, cbc_enc_192, cbc_enc_256,
                vpaes_cbc_encrypt_scalar(ctx, iv, in, out, len));
}

void vpaes_cbc_decrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                       const uint8_t *in, uint8_t *out, size_t len)
{
    DISPATCH_IV(ctx, iv, in, out, len, cbc_dec_128, cbc_dec_192, cbc_dec_256,
                vpaes_cbc_decrypt_scalar(ctx, iv, in, out, len));
}

/* CTR driven through the ECB path: fill a chunk of counter blocks, encrypt
 * the chunk in place to obtain keystream, then XOR.  Filling every counter
 * before any encryption keeps the AES loads clear of store-to-load
 * forwarding windows, and the AES work then runs on exactly the code path
 * the ECB numbers already show to be fastest here.  A per-block CTR loop
 * that seeded the state straight from counter scalars measured at less than
 * half this rate on this core, so the bulk-fill shape is deliberate. */
#define VPAES_KS 64   /* counter blocks per chunk: 64*16 = 1 KiB, L1 resident */

void vpaes_ctr_xcrypt(const vpaes_ctx *ctx, const uint8_t iv[VPAES_BLOCKLEN],
                      const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ctr[VPAES_BLOCKLEN];
    uint8_t ks[VPAES_KS * VPAES_BLOCKLEN];
    uint32_t c0, c1, c2, c_;
    const size_t chunk = (size_t)VPAES_KS * VPAES_BLOCKLEN;

    if (len > (size_t)0xFFFFFFFFULL * VPAES_BLOCKLEN) return;
    memcpy(ctr, iv, VPAES_BLOCKLEN);
    {
        uint64_t lo_, hi_;
        memcpy(&lo_, ctr, 8); memcpy(&hi_, ctr + 8, 8);
        lo_ = bswap64(lo_); hi_ = bswap64(hi_);
        c0 = (uint32_t)(lo_ >> 32); c1 = (uint32_t)lo_;
        c2 = (uint32_t)(hi_ >> 32);
    }
    c_ = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
         ((uint32_t)ctr[14] <<  8) | ((uint32_t)ctr[15]);

    while (len >= chunk) {
        const uint32_t w0 = bswap32(c0), w1 = bswap32(c1), w2 = bswap32(c2);
        for (int k = 0; k < VPAES_KS; k++) {
            const uint32_t w3 = bswap32(c_);
            uint8_t *p = ks + (size_t)k * 16;
            memcpy(p,      &w0, 4); memcpy(p +  4, &w1, 4);
            memcpy(p +  8, &w2, 4); memcpy(p + 12, &w3, 4);
            c_++;
        }
        vpaes_ecb_encrypt(ctx, ks, ks, chunk);   /* counters -> keystream */
        for (size_t i = 0; i < chunk; i += 8) {
            uint64_t a_, b_;
            memcpy(&a_, in + i, 8); memcpy(&b_, ks + i, 8);
            a_ ^= b_;
            memcpy(out + i, &a_, 8);
        }
        in += chunk; out += chunk; len -= chunk;
    }
    if (len) {
        ctr[12] = (uint8_t)(c_ >> 24); ctr[13] = (uint8_t)(c_ >> 16);
        ctr[14] = (uint8_t)(c_ >>  8); ctr[15] = (uint8_t)c_;
        ctr[0] = (uint8_t)(c0 >> 24);  ctr[1] = (uint8_t)(c0 >> 16);
        ctr[2] = (uint8_t)(c0 >>  8);  ctr[3] = (uint8_t)c0;
        ctr[4] = (uint8_t)(c1 >> 24);  ctr[5] = (uint8_t)(c1 >> 16);
        ctr[6] = (uint8_t)(c1 >>  8);  ctr[7] = (uint8_t)c1;
        ctr[8] = (uint8_t)(c2 >> 24);  ctr[9] = (uint8_t)(c2 >> 16);
        ctr[10] = (uint8_t)(c2 >>  8); ctr[11] = (uint8_t)c2;
        vpaes_ctr_xcrypt_scalar(ctx, ctr, in, out, len);
    }
}
