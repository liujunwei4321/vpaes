#!/bin/bash
set -u
cd /home/test/vpaes_build/vpaes_pure_c-A-grade || exit 1
gcc -O3 -std=c99 -Isrc -c -o /tmp/vi.o src/vpaes_inl.c || exit 1
objdump -d /tmp/vi.o --no-show-raw-insn > /tmp/vi.asm
python3 - "$@" <<'PY'
import re, collections, sys
txt = open('/tmp/vi.asm').read()
lines = txt.splitlines()
# Build an index of local labels -> line number, and find the containing
# global function for reporting.
label_re = re.compile(r'^([0-9a-f]{16}) <([^>]+)>:')
insn_re  = re.compile(r'^\s+[0-9a-f]+:\s+(\S+)')

# collect contiguous blocks per label
blocks = {}
cur = None
for ln in lines:
    m = label_re.match(ln)
    if m:
        cur = m.group(2)
        blocks[cur] = []
        continue
    if cur is not None:
        mi = insn_re.match(ln)
        if mi:
            blocks[cur].append(mi.group(1))

for name in sys.argv[1:]:
    b = blocks.get(name)
    if b is None:
        print(f"{name}: not found")
        continue
    c = collections.Counter(b)
    keys = ['st.w','st.d','ld.w','ld.bu','ld.d','jirl','xor','bstrpick.d','bstrpick.w',
            'srli.d','srli.w','slli.w','andi','revb.4h','revb.2h','rotri.w','alsl.d',
            'addi.d','slli.d','or','beq','bne','bgeu']
    print(f"=== {name}: {len(b)} instructions ===")
    print("   " + "  ".join(f"{k}={c[k]}" for k in keys if c[k]))
PY
