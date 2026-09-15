#!/bin/bash
# Dump per-function instruction stats for the inlined variant.
set -u
cd /home/test/vpaes_build/vpaes_pure_c-A-grade || exit 1
gcc -O3 -std=c99 -Isrc -c -o /tmp/vi.o src/vpaes_inl.c || exit 1
objdump -d /tmp/vi.o --no-show-raw-insn > /tmp/vi.asm

# Split disassembly into per-function files keyed by symbol name.
python3 - <<'PY'
import re, subprocess, collections, os
txt = open('/tmp/vi.asm').read()
blocks = re.split(r'\n(?=[0-9a-f]{16} <)', txt)
funcs = {}
for b in blocks:
    m = re.match(r'[0-9a-f]{16} <([^>]+)>:', b)
    if not m:
        continue
    name = m.group(1)
    insns = re.findall(r'^\s+[0-9a-f]+:\s+(\S+)', b, re.M)
    if insns:
        funcs.setdefault(name, []).extend(insns)

def stats(name, insns):
    c = collections.Counter(insns)
    interesting = ['st.w','st.d','ld.w','ld.bu','ld.hu','ld.d','jirl','xor','bstrpick.d',
                   'bstrpick.w','srli.d','srli.w','slli.w','andi','revb.4h','revb.2h',
                   'rotri.w','alsl.d','addi.d','memcpy']
    print(f"  {name:24s} total={len(insns):5d}  " +
          " ".join(f"{k}={c[k]}" for k in interesting if c[k]))
    return c

print("### functions with >=200 instructions (hot AES loops) ###")
for name in sorted(funcs, key=lambda n: -len(funcs[n])):
    if len(funcs[name]) >= 200:
        stats(name, funcs[name])
PY
