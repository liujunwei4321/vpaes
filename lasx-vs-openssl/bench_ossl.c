/* bench_ossl.c - throughput for OpenSSL's own AES through EVP, measured with
 * the same timing core (bench_common.h) and buffer size as the project-side
 * harness, so OpenSSL and the LASX4 vpaes paths are compared under identical
 * methodology rather than across two different timing tools.
 *
 * A round-trip check runs first: if the OpenSSL build were silently broken
 * (e.g. the asm did not link), a bogus throughput number must not be reported.
 *
 * Build (ssh19), against the no-shared build in /home/test/osslN:
 *   gcc -O2 -I/home/test/ossl3/include -o bench_ossl_3 bench_ossl.c \
 *       /home/test/ossl3/libcrypto.a -lpthread -ldl
 */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "bench_common.h"

typedef struct {
    const EVP_CIPHER *cipher;
    uint8_t key[32];
    uint8_t iv[16];
    int enc;
} ossl_ctx;

static void ossl_op(const void *arg, const uint8_t *in, uint8_t *out, size_t len)
{
    const ossl_ctx *c = (const ossl_ctx *)arg;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_CipherInit_ex(ctx, c->cipher, NULL, c->key, c->iv, c->enc);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CipherUpdate(ctx, out, &outl, in, (int)len);
    EVP_CipherFinal_ex(ctx, out + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);
}

/* one-shot helper used only by the correctness check */
static int roundtrip(const EVP_CIPHER *enc_c, const EVP_CIPHER *dec_c,
                     const uint8_t *key, int keylen,
                     const uint8_t *iv, const uint8_t *in, uint8_t *mid,
                     uint8_t *back, size_t len)
{
    ossl_ctx a, b;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    a.cipher = enc_c; a.enc = 1;
    b.cipher = dec_c; b.enc = 0;
    memcpy(a.key, key, keylen); memcpy(b.key, key, keylen);
    if (iv) { memcpy(a.iv, iv, 16); memcpy(b.iv, iv, 16); }
    ossl_op(&a, in, mid, len);
    ossl_op(&b, mid, back, len);
    return memcmp(in, back, len);
}

int main(void)
{
    static uint8_t key[32] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    uint8_t iv[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    const size_t bytes = BENCH_BUF;
    uint8_t *in   = malloc(bytes);
    uint8_t *out  = malloc(bytes);
    uint8_t *mid  = malloc(bytes);
    uint8_t *back = malloc(bytes);
    int bad = 0;

    if (!in || !out || !mid || !back) return 1;
    for (size_t i = 0; i < bytes; i++) in[i] = (uint8_t)(i * 7 + 11);

    printf("OpenSSL runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("== correctness (EVP round-trip) ==\n");
    bad += roundtrip(EVP_aes_128_ecb(), EVP_aes_128_ecb(), key, 16, NULL, in, mid, back, bytes);
    bad += roundtrip(EVP_aes_128_cbc(), EVP_aes_128_cbc(), key, 16, iv,   in, mid, back, bytes);
    bad += roundtrip(EVP_aes_128_ctr(), EVP_aes_128_ctr(), key, 16, iv,   in, mid, back, bytes);
    bad += roundtrip(EVP_aes_192_cbc(), EVP_aes_192_cbc(), key, 24, iv,   in, mid, back, bytes);
    bad += roundtrip(EVP_aes_256_ecb(), EVP_aes_256_ecb(), key, 32, NULL, in, mid, back, bytes);
    bad += roundtrip(EVP_aes_256_cbc(), EVP_aes_256_cbc(), key, 32, iv,   in, mid, back, bytes);
    bad += roundtrip(EVP_aes_256_ctr(), EVP_aes_256_ctr(), key, 32, iv,   in, mid, back, bytes);
    printf("   EVP round-trip: %s\n", bad ? "FAIL" : "PASS (128/192/256, ECB/CBC/CTR)");

    printf("\n=== OpenSSL EVP AES, %u B buffer ===\n", BENCH_BUF);
    {
        struct { const char *name; const EVP_CIPHER *(*get)(void); int keylen; int enc; int is_ctr; } tbl[] = {
            { "a128_ECB_enc", EVP_aes_128_ecb, 16, 1, 0 },
            { "a128_ECB_dec", EVP_aes_128_ecb, 16, 0, 0 },
            { "a128_CBC_enc", EVP_aes_128_cbc, 16, 1, 0 },
            { "a128_CBC_dec", EVP_aes_128_cbc, 16, 0, 0 },
            { "a128_CTR",     EVP_aes_128_ctr, 16, 1, 1 },
            { "a192_ECB_enc", EVP_aes_192_ecb, 24, 1, 0 },
            { "a192_CBC_enc", EVP_aes_192_cbc, 24, 1, 0 },
            { "a192_CTR",     EVP_aes_192_ctr, 24, 1, 1 },
            { "a256_ECB_enc", EVP_aes_256_ecb, 32, 1, 0 },
            { "a256_ECB_dec", EVP_aes_256_ecb, 32, 0, 0 },
            { "a256_CBC_enc", EVP_aes_256_cbc, 32, 1, 0 },
            { "a256_CBC_dec", EVP_aes_256_cbc, 32, 0, 0 },
            { "a256_CTR",     EVP_aes_256_ctr, 32, 1, 1 },
        };
        for (size_t i = 0; i < sizeof tbl / sizeof tbl[0]; i++) {
            ossl_ctx c;
            memset(&c, 0, sizeof c);
            c.cipher = tbl[i].get();
            c.enc    = tbl[i].enc;
            memcpy(c.key, key, (size_t)tbl[i].keylen);
            memcpy(c.iv,  iv, 16);
            bench_row(tbl[i].name, ossl_op, &c, in, out, bytes);
        }
    }
    free(in); free(out); free(mid); free(back);
    return bad ? 1 : 0;
}
