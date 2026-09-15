#!/bin/bash
# Build OpenSSL 3.6.3 and 4.0.1 natively on ssh19 (LoongArch64).
#
# The vendor binutils (Kylin gcc 8.3) has no LoongArch `ret` pseudo-instruction
# -- it rejects asm containing a bare `ret` with "no match insn: ret" under
# every -march.  OpenSSL's LoongArch SHA asm uses it, which aborts the build
# long before AES is reached.  `ret` is architecturally defined as
# `jirl $r0,$r1,0` and the assembler accepts that form, so the generated .S
# files are patched in place.  .S is newer than its .pl afterwards, so make
# does not regenerate over the patch.  Patching runs in a retry loop in case
# further files surface.
set -u

# (any stray build processes were terminated before this script was launched;
#  deliberately no pkill here so the script can never match its own command line)

patch_ret() {
    local tree=$1 n=0
    while IFS= read -r f; do
        sed -i 's/^[[:space:]]*ret[[:space:]]*$/jirl $r0,$r1,0/' "$f"
        echo "    patched: $f"
        n=$((n + 1))
    done < <(grep -rlE '^[[:space:]]*ret[[:space:]]*$' --include='*.S' --include='*.s' "$tree" 2>/dev/null)
    echo "    files patched: $n"
}

for v in 3 4; do
    d=ossl$v
    [ $v = 3 ] && ver=3.6.3 || ver=4.0.1
    echo "=============== OpenSSL $ver ($d) ==============="
    cd /home/test/$d || exit 1

    make -j4 > /home/test/$d-make.log 2>&1
    rc=$?
    attempt=0
    while [ $rc -ne 0 ] && [ $attempt -lt 6 ]; do
        attempt=$((attempt + 1))
        if ! grep -qE "no match insn" /home/test/$d-make.log; then
            echo "  make failed for a non-mnemonic reason; stopping"
            break
        fi
        echo "  attempt $attempt: patching assembler-mnemonic failures"
        patch_ret /home/test/$d
        make -j4 > /home/test/$d-make.log 2>&1
        rc=$?
    done

    echo "  make exit=$rc (attempts=$attempt)"
    if [ -f crypto/aes/vpaes-loongarch64.S ]; then
        echo "  vpaes-loongarch64.S: $(wc -l < crypto/aes/vpaes-loongarch64.S) lines, $(grep -c 'jirl' crypto/aes/vpaes-loongarch64.S) jirl"
    fi
    if [ -x apps/openssl ]; then
        echo -n "  apps/openssl: "; ./apps/openssl version
    else
        echo "  apps/openssl NOT built"
    fi
    echo "  remaining errors:"
    grep -iE "error|Error [0-9]" /home/test/$d-make.log | head -4 | sed 's/^/    /'
    cd /home/test
done
echo "ALL OPENSSL BUILDS DONE"
