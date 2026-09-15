#!/bin/bash
# Final consolidated measurement: project LASX4 (plain and PGO+LTO ship build)
# and OpenSSL 3.6.3 / 4.0.1, all through the same bench_common.h timing core,
# all pinned to one core, several interleaved passes with best-of reported to
# suppress the intermittent background load on this host.
set -u
cd /home/test/loongarch_simp_kat || exit 1

SRCS="bench_project.c la_vpaes_dec_lasx4_r24.c la_vpaes_dec_lasx4.c \
      la_vpaes_lasx4.c la_vpaes_schedule.c la_vpaes_dec.c la_vpaes.c \
      la_vpaes_modes.c la_vpaes_modes_lsx4.c la_vpaes_lsx4.c la_vpaes_dec_lsx4.c"
ARCH="-march=loongarch64 -mlsx -mlasx -mno-strict-align"
OPTS="-O2 -funroll-loops -falign-functions=64 -fno-tree-loop-distribute-patterns"

echo "### building project harnesses ###"
gcc -O2 -funroll-loops $ARCH -I. -o bench_project $SRCS || exit 1
gcc $OPTS $ARCH -fprofile-generate -flto -I. -o bp_gen $SRCS || exit 1
taskset -c 0 ./bp_gen > /dev/null 2>&1
gcc $OPTS $ARCH -fprofile-use -flto -I. -o bp_pgo $SRCS || exit 1
echo "built: bench_project (plain -O2), bp_pgo (PGO+LTO)"

PASSES=3
rm -f /tmp/final2.txt
for p in $(seq $PASSES); do
    taskset -c 0 ./bench_project 2>/dev/null | grep '^R ' | awk '{print "projO2", $2, $3}'  >> /tmp/final2.txt
    taskset -c 0 ./bp_pgo        2>/dev/null | grep '^R ' | awk '{print "projPGO", $2, $3}' >> /tmp/final2.txt
    taskset -c 0 ./bench_ossl_3  2>/dev/null | grep '^R ' | awk '{print "ossl363", $2, $3}' >> /tmp/final2.txt
    taskset -c 0 ./bench_ossl_4  2>/dev/null | grep '^R ' | awk '{print "ossl401", $2, $3}' >> /tmp/final2.txt
done

python3 - <<'PY'
import collections
best = collections.defaultdict(float)
for line in open('/tmp/final2.txt'):
    p = line.split()
    if len(p) != 3:
        continue
    try:
        r = float(p[2])
    except ValueError:
        continue
    best[(p[0], p[1])] = max(best[(p[0], p[1])], r)

# (label, project mode name or None, openssl mode name or None)
ROWS = [
    ("AES-128 ECB enc", "a128_LASX4_ECB_enc",     "a128_ECB_enc"),
    ("AES-128 ECB dec", "a128_LASX4r24_ECB_dec",  "a128_ECB_dec"),
    ("AES-128 CBC enc", "a128_CBC_enc_1block",    "a128_CBC_enc"),
    ("AES-128 CBC dec", "a128_LASX4_CBC_dec",     "a128_CBC_dec"),
    ("AES-128 CTR",     "a128_LASX4_CTR",         "a128_CTR"),
    ("AES-192 ECB enc", "a192_LASX4_ECB_enc",     "a192_ECB_enc"),
    ("AES-192 ECB dec", "a192_LASX4r24_ECB_dec",  None),
    ("AES-192 CBC enc", None,                     "a192_CBC_enc"),
    ("AES-192 CTR",     None,                     "a192_CTR"),
    ("AES-256 ECB enc", "a256_LASX4_ECB_enc",     "a256_ECB_enc"),
    ("AES-256 ECB dec", "a256_LASX4r24_ECB_dec",  "a256_ECB_dec"),
    ("AES-256 CBC enc", None,                     "a256_CBC_enc"),
    ("AES-256 CBC dec", None,                     "a256_CBC_dec"),
    ("AES-256 CTR",     None,                     "a256_CTR"),
]

def g(v, m):
    return best.get((v, m), 0.0) if m else 0.0

print()
print("Throughput MB/s, best of %d interleaved passes, 4 MiB buffer, pinned to one core" % 3)
print("ssh19 = Loongson-3A5000LL @2.3GHz, Kylin V10, gcc 8.3.0")
print()
hdr = f"{'mode':<16}{'proj -O2':>10}{'proj PGO':>10}{'ossl 3.6.3':>12}{'ossl 4.0.1':>12}{'proj/ossl':>11}"
print(hdr)
print("-" * len(hdr))
for label, pm, om in ROWS:
    a, b = g("projO2", pm), g("projPGO", pm)
    c, d = g("ossl363", om), g("ossl401", om)
    ratio = (b / d) if (b and d) else 0.0
    fa = f"{a:.0f}" if a else "-"
    fb = f"{b:.0f}" if b else "-"
    fc = f"{c:.0f}" if c else "-"
    fd = f"{d:.0f}" if d else "-"
    fr = f"{ratio:.2f}x" if ratio else "-"
    print(f"{label:<16}{fa:>10}{fb:>10}{fc:>12}{fd:>12}{fr:>11}")

print()
print("proj/ossl = PGO+LTO project build vs OpenSSL 4.0.1 (its own EVP path)")
print("Note: the project's CTR/CBC mode layer is implemented for AES-128 only,")
print("so 192/256 rows have no project counterpart (-).")
PY
