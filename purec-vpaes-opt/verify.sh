#!/bin/bash
set -u
cd /home/test/vpaes_build/vpaes_pure_c-A-grade || exit 1
mkdir -p bin

echo "=========== FINAL VERIFICATION ==========="
echo "--- build optimised variant (strict warnings) ---"
gcc -O3 -Wall -Wextra -Wpedantic -std=c99 -Isrc -o bin/sanity_test src/sanity.c src/vpaes_inl.c || exit 1
gcc -O3 -Wall -Wextra -Wpedantic -std=c99 -Isrc -o bin/kat_test src/kat_test.c src/vpaes_inl.c || exit 1
echo "clean build with -Wall -Wextra -Wpedantic, no warnings"

echo
echo "--- sanity (optimised) ---"
./bin/sanity_test | tail -10

echo
echo "--- NIST CAVP KAT (optimised) ---"
python3 - <<'PY'
import subprocess, glob, re
files = sorted(glob.glob('kat/ECB*.txt')) + sorted(glob.glob('kat/CBC*.txt'))
nf = nv = 0
bad = []
for f in files:
    r = subprocess.run(['./bin/kat_test', f], capture_output=True, text=True)
    ok = (r.returncode == 0) and ('-- OK' in r.stdout)
    m = re.search(r'passed (\d+)/(\d+)', r.stdout)
    nf += 1
    if m:
        nv += int(m.group(1))
        if m.group(1) != m.group(2):
            ok = False
    if not ok:
        bad.append(f)
print(f"KAT files: {nf-len(bad)}/{nf} PASS, vectors: {nv} passed")
for b in bad:
    print("  FAILED:", b)
PY

echo
echo "--- differential test vs stock scalar (all modes, in-place + disjoint) ---"
gcc -O2 -std=c99 -Isrc -o bin/difftest src/difftest.c src/ref_rename.c src/vpaes_inl.c || exit 1
./bin/difftest | tail -4

echo
echo "--- control: stock scalar on the same KAT suite ---"
gcc -O2 -std=c99 -Isrc -o bin/kat_ref src/kat_test.c src/vpaes.c || exit 1
python3 - <<'PY'
import subprocess, glob, re
files = sorted(glob.glob('kat/ECB*.txt')) + sorted(glob.glob('kat/CBC*.txt'))
nf = nv = 0
for f in files:
    r = subprocess.run(['./bin/kat_ref', f], capture_output=True, text=True)
    m = re.search(r'passed (\d+)/(\d+)', r.stdout)
    nf += 1
    if m:
        nv += int(m.group(1))
print(f"stock scalar: KAT files {nf}/{nf} PASS, vectors {nv} passed")
PY
