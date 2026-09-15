# LoongArch AES benchmark & optimisation — release 2026-09-15

Two independent pieces of work, both measured on the same machine with the
same discipline: every reported speed is gated behind a correctness check that
runs first, and no number appears in a report that the harness could not back
up.

**Target host** — `ssh19`: Loongson-3A5000LL rev 0x11 @2.3 GHz, 4 cores,
L1d 64 KiB/core, L2 1 MiB, L3 16 MiB, Kylin V10 (LoongArch64), vendor gcc 8.3.0.
CPU features: `lsx lasx crypto`. All measurements pinned to one core
(`taskset -c 0`), 4 MiB buffer.

---

## Deliverable 1 — `purec-vpaes-opt/`

Optimisation of the pure-C, no-SIMD `vpaes_pure_c` scalar implementation.

**Headline: 1.13x–1.26x on every mode and key size**, by removing an indirect
call per block. The stock code binds `ctx->enc_dispatch` to `enc_128/192/256`
and calls it through the function pointer once per 16-byte block. Because the
state array's address escapes into that call, the callee cannot prove the
T-table loads (`const uint32_t[]`) do not alias the state stores (`uint32_t`),
so GCC re-materialises the state in memory **on every round** — the compiled
`enc_128` shows `st.w=40 / ld.w=204` for what should be a register-resident
loop. `vpaes_inl.c` keeps the state in four local scalars that are never
address-taken and dispatches on key size once outside the block loop.

| mode | stock `-O2` | recommended | speedup |
|------|------------:|------------:|--------:|
| AES-128 ECB enc | 160 | 190 | 1.19x |
| AES-128 ECB dec | 166 | 189 | 1.13x |
| AES-128 CBC enc | 153 | 185 | 1.21x |
| AES-128 CBC dec | 165 | 188 | 1.14x |
| AES-128 CTR     | 145 | 181 | 1.25x |
| AES-256 ECB enc | 120 | 135 | 1.13x |
| AES-256 CTR     | 111 | 132 | 1.19x |

(MB/s; full table including AES-192 in `report/purec-vpaes-optimisation.md`.)

**Verified:** sanity 8/8 PASS; NIST CAVP KAT 48/48 files, **4156/4156 vectors**;
differential test vs the stock scalar code **1126 comparisons, 0 mismatches**
(3 key sizes x 18 lengths incl. 0/1/15/16/17 and the 1 KiB chunk boundary, all
modes, in-place and disjoint, plus CTR two-calls-vs-one and a sweep of every
length 0..600). Transcript: `purec-vpaes-opt/data/purec_verify.txt`.

Two findings worth keeping, because both contradict the obvious guess:

* **Compiler flags are a dead end** — max +6% (`-O3 -funroll-loops`).
  `-march=native`, `-march=la464 -mlsx -mlasx` and `-Ofast` all measured
  *slower* than plain `-O3`, because nothing in a T-table AES auto-vectorises.
* **Multi-block interleaving is not the win it looks like.** Explicitly keeping
  2/4/8 blocks in flight peaked at +16% (IL=8) and lost ground at IL=4, because
  the stock `while (len >= 16)` loop already hands the out-of-order core
  independent blocks to overlap. The real problem was the per-round state
  spill, not the dependency chain.

---

## Deliverable 2 — `lasx-vs-openssl/`

Benchmark of the project's LoongArch LASX4 vpaes paths against **OpenSSL 3.6.3
and 4.0.1** built natively on the target.

| mode | proj `-O2` | proj PGO+LTO | ossl 3.6.3 | ossl 4.0.1 | proj/ossl |
|------|-----------:|-------------:|-----------:|-----------:|----------:|
| AES-128 ECB enc | 401 | 404 | 198 | 198 | **2.04x** |
| AES-128 ECB dec | 387 | 394 | 175 | 175 | **2.25x** |
| AES-128 CBC enc | 197 | 192 | 200 | 199 | **0.96x** |
| AES-128 CBC dec | 352 | 364 | 176 | 176 | **2.06x** |
| AES-128 CTR     | 381 | 435 | 162 | 162 | **2.68x** |
| AES-192 ECB enc | 345 | 348 | 165 | 165 | 2.11x |
| AES-256 ECB enc | 303 | 305 | 142 | 142 | 2.15x |
| AES-256 ECB dec | 290 | 294 | 125 | 125 | 2.35x |

MB/s. Project column is `la_vpaes_lasx4.c` / `la_vpaes_dec_lasx4_r24.c`; ossl
column is the built OpenSSL binary's own EVP path. The project's CTR/CBC mode
layer is AES-128 only, so 192/256 have no counterpart.

Four results, all verified rather than inferred:

1. **OpenSSL 3.6.3 and 4.0.1 are performance-identical for AES on LoongArch.**
   Every row agrees to within 0.5%. `crypto/aes/asm/vpaes-loongarch64.pl` is
   **byte-identical** between the two releases (md5 `8d6101a8136cd177c1c4bcd32355aaa2`),
   as is the generated `.S` (md5 `fd33410462a4529b6b8c0d01b44ce8e1`). There is
   no AES speed argument for moving 3.6.3 -> 4.0.1.
2. **The LoongArch AES assembly is instruction-for-instruction unchanged since
   1.1.1w.** Only three `.globl` lines differ (internal helpers went from
   exported to local), so swapping in the newer file is safe and
   performance-neutral. Diff in `lasx-vs-openssl/data/`.
3. **The ~2x is structural, not tuning.** OpenSSL binds `dat->block` to the
   single-block `vpaes_encrypt` and runs the generic `cbc128.c`/`ctr128.c`
   loops, which call it **once per 16 bytes**; this project does **4 blocks per
   call** on LASX. CTR shows the largest gap because OpenSSL defines no
   `AES_CTR_ASM` for loongarch64, so it has no dedicated multi-block CTR path
   at all. Verified that OpenSSL really takes the asm route:
   `VPAES_CAPABLE = (hwcap & (1<<4))` and `AT_HWCAP = 0x1ffe`, so bit 4 is set.
4. **CBC encryption is the one mode with no advantage — 0.96x.** CBC encrypt is
   sequential by definition, so there is no 4-block path; the project falls back
   to its 1-block routine (~197 MB/s vs OpenSSL ~199 MB/s). Any claim of a
   uniform ~2x should exclude this mode.

**R24 vs the base LASX4 decrypt** (correctness-gated: byte-equal output,
round-trip, CTR involution, CBC-dec inverts CBC-enc — all PASS):

| key | base dec | R24 dec | delta |
|-----|---------:|--------:|------:|
| AES-128 | 361 | 387 | +7.2% |
| AES-192 | 307 | 334 | +8.8% |
| AES-256 | 267 | 290 | +8.6% |

### Toolchain gotcha — OpenSSL 3.6.3 / 4.0.1 do not build as shipped

Both releases fail on Kylin's gcc 8.3 with
`Fatal error: no match insn: ret` in `crypto/sha/sha{256,512}-loongarch64.S`.
The vendor binutils has no LoongArch `ret` pseudo (rejected under every
`-march`). `ret` is architecturally `jirl $r0,$r1,0`, which assembles, so:

```sh
sed -i 's/^[[:space:]]*ret[[:space:]]*$/jirl $r0,$r1,0/' \
    crypto/sha/sha256-loongarch64.S crypto/sha/sha512-loongarch64.S
```

Patch after the `.S` files are generated, then re-run `make`.
`build_ossl2.sh` does this in a retry loop. Both versions then build cleanly.

---

## Reproducing

Everything runs on a LoongArch64 Linux host with gcc supporting
`-mlsx -mlasx`.

**Deliverable 1** needs a copy of `vpaes_pure_c-A-grade` (the upstream project)
with `vpaes_inl.c` / `vpaes_fast.c` dropped into `src/`, then:

```sh
bash purec-vpaes-opt/verify.sh     # build + sanity + KAT + differential test
bash purec-vpaes-opt/final.sh      # multi-pass throughput comparison
python3 purec-vpaes-opt/report.py  # render the table from the collected data
```

**Deliverable 2** needs the project tree (`la_vpaes*.c`, `la_vpaes_schedule.c`,
`la_vpaes_tables.h`, ...) and the two OpenSSL source trees:

```sh
bash lasx-vs-openssl/build_ossl2.sh   # builds OpenSSL 3.6.3 and 4.0.1 incl. the ret patch
bash lasx-vs-openssl/final2.sh        # builds all harnesses, measures, renders the table
```

Both sides of deliverable 2 use the same timing core (`bench_common.h`: 4 MiB
buffer, 0.2 s fixed budget per sample, 7 samples, best-of reported) rather than
mixing `openssl speed` with a home-grown loop. `openssl speed -evp aes-128-ecb`
was run as an independent cross-check and agrees: 199.3 MB/s vs 198 MB/s.

---

## Caveats

* A background process (`xorcrypt`, ~2% CPU) is intermittently active on this
  host, so single-run medians drift. All figures are best-of-N over interleaved
  passes; individual runs can read up to ~6% lower.
* The project's previously published ship-build figures (460 enc / 394 R24-dec,
  AES-128) are above what is reproducible here (404–432 enc / 394 R24-dec at
  4 MiB) — consistent with their 64 MiB buffer and different pass counting, but
  ~400 is what an `-O2 -funroll-loops`-class build measures at 4 MiB.
* `make test-sanitize` cannot run on this host: `libubsan` is not installed for
  the vendor gcc 8.3, though `libasan` is. ASan-only builds were used instead.
* Deliverable 1's `vpaes_fast.c` is the experimental interleaving variant that
  variant C of the comparison builds; it is kept for the record, not recommended.
* The OpenSSL source tarballs are **not** included (55 MB each, and they are
  upstream artifacts). Only the build script and the generated LoongArch AES
  assembly used for the comparison are shipped.

## Layout

```
report/
  lasx4-vs-openssl-3.6.3-4.0.1.md   full write-up, deliverable 2
  purec-vpaes-optimisation.md       full write-up, deliverable 1
lasx-vs-openssl/
  bench_common.h  bench_project.c  bench_ossl.c    harnesses
  final2.sh       build_ossl2.sh                   drivers
  data/final2.txt                                  raw run data
  data/vpaes_asm_111w_vs_363.diff                  1.1.1w vs 3.6.3 asm diff
  data/vpaes-loongarch64-3.6.3.s                   generated AES asm (ref)
purec-vpaes-opt/
  vpaes_inl.c                  recommended variant (drop into src/, replaces vpaes.c)
  vpaes_fast.c                 experimental interleaving variant (variant C)
  optbench.c  difftest.c  ref_rename.c             harnesses
  final.sh  report.py  verify.sh  asman.sh  asm3.sh  drivers
  data/purec_data.txt                              raw run data
  data/purec_verify.txt                            correctness transcript
```

`MANIFEST.txt` lists every file with its size and SHA-256.
