#!/usr/bin/env python3
"""Render the comparison tables from /tmp/best.txt (written by final.sh)."""
import collections

best = collections.defaultdict(float)
order = []
for line in open('/tmp/best.txt'):
    p = line.split()
    if len(p) != 3:
        continue
    v, m, r = p[0], p[1], float(p[2])
    if (v, m) not in best:
        order.append(m)
    best[(v, m)] = max(best[(v, m)], r)

variants = ['A', 'B', 'C', 'D', 'I']
hdr = {'A': 'A stock-O2', 'B': 'B O3-unroll', 'C': 'C ilace-IL8',
       'D': 'D inl-O2', 'I': 'I inl-O3'}
metrics = []
for m in order:
    if m not in metrics:
        metrics.append(m)

print("Throughput MB/s, best-of-N across interleaved passes")
print("ssh19: Loongson-3A5000LL @2.3GHz, 4 MiB buffer, pinned to one core")
print()
print(f"{'mode':<14}" + "".join(f"{hdr[v]:>14}" for v in variants))
print("-" * (14 + 14 * len(variants)))
for m in metrics:
    print(f"{m:<14}" + "".join(f"{best.get((v, m), 0):>14.1f}" for v in variants))

print()
print("Speedup vs A (stock scalar, project default flags)")
print(f"{'mode':<14}" + "".join(f"{hdr[v]:>14}" for v in variants[1:]))
print("-" * (14 + 14 * (len(variants) - 1)))
for m in metrics:
    base = best.get(('A', m), 0) or 1.0
    print(f"{m:<14}" + "".join(f"{best.get((v, m), 0) / base:>13.2f}x"
                               for v in variants[1:]))

print()
print("Variant key:")
print("  A  stock scalar, -O2 (what the shipped Makefile uses)")
print("  B  stock scalar, -O3 -funroll-loops (best pure flag change)")
print("  C  stock scalar + 8-way block interleaving, -O3")
print("  D  inlined scalars (no dispatch, state in registers), -O2")
print("  I  inlined scalars, -O3   <-- recommended")
