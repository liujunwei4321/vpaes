# LASX4 vpaes vs OpenSSL 3.6.3 / 4.0.1 — bench on ssh19

Host: **ssh19** — Loongson-3A5000LL rev 0x11 @2.3 GHz, 4 cores, Kylin V10
(LoongArch64), gcc 8.3.0. All numbers best-of-3 interleaved passes, 4 MiB
buffer, `taskset -c 0`.

## Headline

**OpenSSL 3.6.3 and 4.0.1 are performance-identical for AES on LoongArch.**
Every row agrees to within 0.5%. The reason is that
`crypto/aes/asm/vpaes-loongarch64.pl` is **byte-identical** between the two
releases (md5 `8d6101a8136cd177c1c4bcd32355aaa2`) and so is the generated
`.S` (md5 `fd33410462a4529b6b8c0d01b44ce8e1`). There is no AES speed argument
for moving 3.6.3 -> 4.0.1.

Against OpenSSL 1.1.1w's copy of that file — the one this project has been
using as its reference — the generated assembly is also **instruction-for-
instruction identical**. The only difference is symbol visibility:

```diff
18d17   < .globl _vpaes_encrypt_core
114d112 < .globl _vpaes_decrypt_core
806d803 < .globl _vpaes_preheat
```

1.1.1w exported those three internal helpers; 3.6.3/4.0.1 keep them local.
Nothing in the project references them (the project's own `la_*_core`
functions are a separate C port), so swapping `vpaes-loongarch64.s` for the
3.6.3/4.0.1 output is safe and performance-neutral.

## Results

| mode | proj `-O2` | proj PGO+LTO | ossl 3.6.3 | ossl 4.0.1 | proj/ossl |
|------|-----------:|-------------:|-----------:|-----------:|----------:|
| AES-128 ECB enc | 401 | 404 | 198 | 198 | **2.04x** |
| AES-128 ECB dec | 387 | 394 | 175 | 175 | **2.25x** |
| AES-128 CBC enc | 197 | 192 | 200 | 199 | **0.96x** |
| AES-128 CBC dec | 352 | 364 | 176 | 176 | **2.06x** |
| AES-128 CTR     | 381 | 435 | 162 | 162 | **2.68x** |
| AES-192 ECB enc | 345 | 348 | 165 | 165 | 2.11x |
| AES-192 ECB dec | 334 | 339 | -   | -   | - |
| AES-256 ECB enc | 303 | 305 | 142 | 142 | 2.15x |
| AES-256 ECB dec | 290 | 294 | 125 | 125 | 2.35x |

MB/s. `proj` is `la_vpaes_lasx4.c` / `la_vpaes_dec_lasx4_r24.c`; `ossl` is the
built OpenSSL binary's own EVP path. The project's CTR/CBC mode layer is
AES-128 only, hence `-` for 192/256.

### What the ratios actually mean

The project's advantage is **structural, not a tuning win**, and it comes from
two specific places:

1. **Block parallelism.** OpenSSL binds `dat->block` to `vpaes_encrypt` and
   runs the generic `cbc128.c` / `ctr128.c` loops, which call that block
   function **once per 16 bytes**. Its LoongArch vpaes is a 1-block LSX
   routine. The project processes **4 blocks per call** on LASX. That is the
   whole ~2x.
2. **No `AES_CTR_ASM` for loongarch64.** OpenSSL's `build.info` defines only
   `VPAES_ASM` for this target, so CTR has no dedicated multi-block path —
   explaining why CTR shows the largest gap (2.68x) while ECB/CBC sit near 2.0x.

This was verified rather than inferred: `VPAES_CAPABLE` is
`(OPENSSL_loongarch_hwcap_P & LOONGARCH_HWCAP_LSX)`, i.e. bit 4 of
`getauxval(AT_HWCAP)`. That value is `0x1ffe` on this machine, so bit 4 is
set and OpenSSL **does** take the assembly path — the numbers are the asm, not
a C fallback.

### The one mode with no advantage

**CBC encryption is 0.96x — marginally slower than OpenSSL.** CBC encrypt is
sequential by definition (block *i* needs ciphertext *i-1*), so there is no
4-block path to exploit: the project falls back to its 1-block LSX routine at
~197 MB/s against OpenSSL's ~199 MB/s. Any claim of a uniform ~2x over OpenSSL
should exclude this mode.

### R24 vs the base LASX4 decrypt

Correctness-gated (byte-for-byte equal output, round-trip, CTR involution,
CBC-dec inverts CBC-enc — all PASS), R24 is consistently faster:

| key | base LASX4 dec | R24 dec | delta |
|-----|---------------:|--------:|------:|
| AES-128 | 361 | 387 | +7.2% |
| AES-192 | 307 | 334 | +8.8% |
| AES-256 | 267 | 290 | +8.6% |

## Toolchain gotcha: OpenSSL 3.6.3 / 4.0.1 will not build as shipped

Both releases fail on Kylin's gcc 8.3:

```
crypto/sha/sha256-loongarch64.S:2935: Fatal error: no match insn: ret
crypto/sha/sha512-loongarch64.S:3707: Fatal error: no match insn: ret
```

The vendor binutils has no LoongArch `ret` pseudo-instruction — it is rejected
under every `-march`. `ret` is architecturally `jirl $r0,$r1,0`, which the
assembler does accept, so the generated asm is patched in place:

```sh
sed -i 's/^[[:space:]]*ret[[:space:]]*$/jirl $r0,$r1,0/' \
    crypto/sha/sha256-loongarch64.S crypto/sha/sha512-loongarch64.S
```

patch after the `.S` files are generated, then re-run `make`. `build_ossl2.sh`
does this in a retry loop (5 files matched a bare `ret`; only the two LoongArch
SHA files matter for this target — three SPARC files also matched and are
never assembled here). After patching, both build cleanly and the AES and SHA
paths work; all EVP round-trips pass.

## Method

All four implementations were measured by **the same timing code**
(`bench_common.h`: 4 MiB buffer, 0.2 s fixed budget per sample, 7 samples,
best-of reported) rather than by mixing `openssl speed` with a home-grown
loop. `openssl speed -evp aes-128-ecb` was run as an independent cross-check
and agrees with the harness: 199.3 MB/s vs 198 MB/s at 1024-byte blocks.

Correctness gates run before every measurement: the harness refuses to report
a number it cannot back up. Gates that passed: R24 decrypt == base LASX4
decrypt (128/192/256), ECB round-trip, CTR involution, CBC-decrypt inverting
CBC-encrypt, and OpenSSL EVP round-trip on 128/192/256 x ECB/CBC/CTR.

Caveat on variance: a background process (`xorcrypt`, ~2% CPU) is
intermittently active on this host, so single-run medians drift. All figures
are best-of-3-pass and were reproducible across passes; individual runs can
read up to ~6% lower. The project's published ship-build figures (460 enc /
394 R24-dec for AES-128) are a little above what is reproducible here
(404-432 enc / 394 R24-dec) — consistent with their 64 MiB buffer and
different pass counting, but worth knowing that ~400, not ~460, is what the
`-O2 -funroll-loops`-class builds measure at 4 MiB.

## Files

| file | role |
|------|------|
| `bench_common.h` | shared timing core (used by both sides) |
| `bench_project.c` | LASX4 ECB/CTR/CBC + correctness gates |
| `bench_ossl.c` | OpenSSL EVP AES + round-trip gate |
| `final2.sh` | builds all harnesses, measures, renders the table |
| `build_ossl2.sh` | OpenSSL build incl. the `ret` patch loop |

Raw run data and the asm diff are on ssh19 at `/home/test/final2.txt` and
`/home/test/vpaes_asm_111w_vs_363.diff`.
