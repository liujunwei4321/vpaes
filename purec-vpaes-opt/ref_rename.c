/* Reference copy of vpaes.c exported under ref_* names, so a differential
 * test can link it alongside the optimised variant in one binary. */
#define vpaes_ecb_encrypt   ref_ecb_encrypt
#define vpaes_ecb_decrypt   ref_ecb_decrypt
#define vpaes_cbc_encrypt   ref_cbc_encrypt
#define vpaes_cbc_decrypt   ref_cbc_decrypt
#define vpaes_ctr_xcrypt    ref_ctr_xcrypt
#define vpaes_set_key       ref_set_key
#define vpaes_encrypt_block ref_encrypt_block
#define vpaes_decrypt_block ref_decrypt_block
#define enc_dispatch        ref_enc_dispatch
#define dec_dispatch        ref_dec_dispatch
#include "vpaes.c"
