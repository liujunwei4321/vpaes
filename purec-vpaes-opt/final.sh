#!/bin/bash
# Final head-to-head comparison across key sizes and modes.
# A competing process (xorcrypt) is active on this host, so medians drift;
# every variant is measured in several interleaved passes and the best
# observed rate is reported -- the robust estimator for throughput under
# external interference.
set -u
cd /home/test/vpaes_build/vpaes_pure_c-A-grade || exit 1
mkdir -p bin

gcc -O2 -Wall -Wextra -std=c99 -Isrc -o bin/v_A optbench.c src/vpaes.c 2>/dev/null
gcc -O3 -funroll-loops -std=c99 -Isrc -o bin/v_B optbench.c src/vpaes.c 2>/dev/null
gcc -O3 -funroll-loops -std=c99 -DVPAES_IL=8 -Isrc -o bin/v_C optbench.c src/vpaes_fast.c 2>/dev/null
gcc -O2 -std=c99 -Isrc -o bin/v_D optbench.c src/vpaes_inl.c 2>/dev/null
gcc -O3 -std=c99 -Isrc -o bin/v_I optbench.c src/vpaes_inl.c 2>/dev/null

VARIANTS="A B C D I"
PASSES=4
rm -f /tmp/best.txt
for p in $(seq $PASSES); do
    for v in $VARIANTS; do
        taskset -c 1 ./bin/v_$v 2>/dev/null | grep '^R ' | awk -v v="$v" '{print v, $2, $3}' >> /tmp/best.txt
    done
done

python3 - <<'PY'
import collections
best = collections.defaultdict(float)
order = []
for line in open('/tmp/best.txt'):
    p = line.split()
    if len(p) != 3:
        continue
    v, m, r = p[0], p[1], float(p[2])
    k = (v, m)
    if k not in best:
        order.append(m)
    best[k] = max(best[k], r)

variants = ['A', 'B', 'C', 'D', 'I']
hdr = {'A': 'A stock -O2', 'B': 'B -O3-unroll', 'C': 'C ilace-IL8',
       'D': 'D inlined -O2', 'I': 'I inlined -O3'}
metrics = []
for m in order:
    if m not in metrics:
        metrics.append(m)

print("Throughput, MB/s, best-of-%d (ssh19, Loongson-3A5000LL @2.3GHz, 4MiB buffer)" % PASSES)
print(f"{'mode':<14}" + "".join(f"{hdr[v]:>15}" for v in variants))
print("-" * (14 + 15 * len(variants)))
for m in metrics:
    print(f"{m:<14}" + "".join(f"{best.get((v,m),0):>15.1f}" for v in variants))

print()
print("Speedup relative to A (stock scalar, project default flags)")
print(f"{'mode':<14}" + "".join(f"{hdr[v]:>15}" for v in variants[1:]))
print("-" * (14 + 15 * (len(variants) - 1)))
for m in metrics:
    base = best.get(('A', m), 0) or 1.0
    print(f"{m:<14}" + "".join(f"{best.get((v,m),0)/base:>14.2f}x" for v in variants[1:]))
PY
