# vpaes_pure_c — optimisation work on ssh19

Target host: **ssh19** — Loongson-3A5000LL, 4 cores @2.3 GHz, L1d 64 KiB/core,
L2 1 MiB, L3 16 MiB, Kylin V10 (LoongArch64), gcc 8.3.0.

## Headline result

The stock code calls `enc_128/192/256` **through the `ctx->*_dispatch` function
pointer**, once per 16-byte block. That has two costs, both visible in the
disassembly:

1. an indirect call per block, so nothing inlines;
2. worse — the state array's address escapes into that call, so the callee
   cannot prove the T-table loads (`const uint32_t[]`) don't alias the state
   stores (`uint32_t`). GCC therefore re-materialises the state in memory on
   **every round**. The compiled `enc_128` shows `st.w=40 / ld.w=204` for what
   should be a register-resident loop.

`vpaes_inl.c` keeps the state in four local scalars that are never
address-taken, macro-inlines all round work, and dispatches on key size once
outside the block loop. Measured on the target, best-of-N over interleaved
passes, 4 MiB buffer, pinned to one core:

| mode        | A stock `-O2` | B `-O3 -unroll` | C interleave IL8 | **I inlined `-O3`** |
|-------------|--------------:|----------------:|-----------------:|--------------------:|
| a128 ECB enc|        159.8  |          170.1  |           184.7  |          **190.0**  |
| a128 ECB dec|        166.4  |          175.0  |           170.3  |          **188.8**  |
| a128 CBC enc|        152.9  |          167.6  |           168.6  |          **184.5**  |
| a128 CBC dec|        164.5  |          173.4  |           154.6  |          **187.7**  |
| a128 CTR    |        145.0  |          164.6  |           160.5  |          **181.3**  |
| a192 ECB enc|        137.2  |          142.6  |           155.9  |          **159.5**  |
| a192 CTR    |        122.3  |          136.7  |           137.9  |          **153.5**  |
| a256 ECB enc|        120.0  |          124.7  |           134.8  |          **135.2**  |
| a256 CBC enc|        116.6  |          123.4  |           123.6  |          **132.1**  |
| a256 CTR    |        111.1  |          121.8  |           120.9  |          **132.3**  |

Speedup of the recommended variant: **1.13x–1.26x**, uniform across all modes
and key sizes. MB/s -> cycles/byte at 2.3 GHz: a128 ECB enc 14.4 -> 12.1 c/B.

Two findings worth recording because they contradict the obvious guess:

* **Compiler flags are a dead end** (max +6%, from `-O3 -funroll-loops`).
  `-march=native`, `-march=la464 -mlsx -mlasx` and `-Ofast` all measured
  *slower* than plain `-O3` here, because nothing in a T-table AES is
  auto-vectorisable.
* **Multi-block interleaving is not the win it looks like.** Explicitly
  keeping 2/4/8 blocks in flight peaked at +16% (IL=8) and *lost* ground at
  IL=4 and on some modes, because the stock `while (len >= 16)` loop already
  hands the out-of-order core independent blocks to overlap. The real problem
  was the per-round state spill, not the dependency chain.

## Verification

`vpaes_inl.c` was validated against the stock implementation, not just
against the shipped vectors (the KAT files only tabulate ECB and CBC, so CTR
would otherwise rest on a single RFC 3686 vector):

* `san` — all 8 sanity checks PASS (FIPS-197 x3, SP 800-38A CBC, RFC 3686 CTR,
  in-place CBC decrypt, partial-block CTR, aliasing stress)
* `kat` — 48/48 files PASS, **4156/4156 vectors**
* `difftest` — **1126 comparisons, 0 mismatches** vs the stock scalar code:
  3 key sizes x 18 lengths (incl. 0/1/15/16/17 and the 1 KiB chunk boundary),
  ECB/CBC/CTR, in-place and disjoint, plus a two-call-vs-one-call CTR
  chunking check and a sweep of every length 0..600
* builds clean under `-Wall -Wextra -Wpedantic`

## Files

| file | role |
|------|------|
| `vpaes_inl.c` | the optimised variant (reuses `src/vpaes.c` via symbol renaming) |
| `optbench.c`   | low-noise harness: fixed time budget, median + best, `R <mode> <mb/s>` lines |
| `difftest.c`, `ref_rename.c` | differential test vs the stock scalar code |
| `final.sh`, `report.py` | interleaved multi-pass comparison driver + table renderer |
| `verify.sh`    | end-to-end correctness run (build + sanity + KAT + difftest) |

### Build / run

On the target, from a copy of `vpaes_pure_c-A-grade` with `vpaes_inl.c` in `src/`:

```sh
gcc -O3 -Wall -Wextra -Wpedantic -std=c99 -Isrc -o bin/sanity_test src/sanity.c  src/vpaes_inl.c
gcc -O3 -Wall -Wextra -Wpedantic -std=c99 -Isrc -o bin/kat_test    src/kat_test.c src/vpaes_inl.c
./bin/sanity_test && for f in kat/ECB*.txt kat/CBC*.txt; do ./bin/kat_test "$f"; done

gcc -O2 -std=c99 -Isrc -o bin/difftest src/difftest.c src/ref_rename.c src/vpaes_inl.c
./bin/difftest
```

`vpaes_inl.c` is a drop-in replacement for `src/vpaes.c` at link time — it
re-exports the same five public symbols, so `Makefile` targets work by
substituting the source file.

## Known limitation

`make test-sanitize` cannot run on this host: `libubsan` is not installed for
the vendor gcc 8.3 (`-lubsan` not found), though `libasan` is present. ASan-only
builds were run instead — all 8 sanity checks and all 48 KAT files pass with
`-fsanitize=address -Werror`.

## Where the remaining headroom is

Measured throughput is 12.1 cycles/byte for AES-128 ECB; the pure L1
load-port bound for this table layout (160 loads/block at ~2 loads/cycle) is
about 5 c/B. Closing that gap needs fewer operations per byte, not better
scheduling:

* **LSX / LASX (recommended).** Verified available on this host: `vshuf.b`
  (4-operand form), `xvshuf.b`, `vand.v`, `vor.v`, `vxor.v`, `vbitsel.v`,
  `vreplgr2vr.b`, `vld`/`vst` all assemble, `<lsxintrin.h>` compiles under
  `-mlsx`, and `-march=la464`, `-march=native`, `-mlsx`, `-mlasx` are all
  accepted. `vshuf.b` is exactly the instruction Hamburg's vpaes is built
  around — one shuffle replaces 16 table lookups — so the project's own
  `docs/LSX_LASX_MIGRATION.md` Phase 3 plan is implementable with this
  toolchain. This is the largest realistic win.
* **Bitslicing** if the pure-C constraint is absolute: no table lookups at all,
  processes many blocks in parallel in 64-bit words. Also makes the code
  constant-time, which the header currently disclaims.
* **Not available:** hardware AES. No `aesenc`/`aesdec`/`aeskeygenassist`, and
  no `sm4`/`sm3`/`crc32`/`rndrng` mnemonics assemble under this gcc, so the
  LA664 `xcrypt-e`/`xcrypt-d` path in the docs cannot be used from this
  toolchain. Whether the 3A5000 silicon has them is untested; they are
  unusable here either way.

Note also that any SIMD or bitsliced path breaks the module's stated premise
of "pure C, no SIMD intrinsics, no inline assembly", so it belongs behind a
compile-time toggle and a runtime `getauxval` check, as the migration doc
already proposes.
