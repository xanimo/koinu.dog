#!/usr/bin/env bash
# Build koinu.wasm for the learn pages.
#
# The same crypto/ and net/ sources kw links, taken from the koinu submodule,
# plus kw_web.c, compiled for wasm32-wasi as a reactor (no main; the page calls
# exported functions). rng.c and mem.c are left out because kw_web.c supplies
# kw_random_bytes over getentropy and the parts of mem.c a browser can do
# (zeroing, constant-time compare; there is nothing to mlock and no core file to
# suppress).
#
# ECMULT_WINDOW_SIZE=2 keeps the verification table small: the page signs and
# derives but never verifies, and the default window costs a megabyte.
#
# needs zig (pip install ziglang, or a release from ziglang.org) and both
# submodules checked out, koinu and secp256k1 inside it:
#
#     git submodule update --init --recursive
set -eu
cd "$(dirname "$0")"
ZIG=${ZIG:-"python3 -m ziglang"}
KW=koinu
SECP=$KW/depends/secp256k1

# Checked rather than left to the compiler: an unchecked-out submodule is an
# empty directory, and the error for that is forty missing files.
[ -f $KW/crypto/ec.c ]       || { echo "build.sh: the koinu submodule is not checked out" >&2; exit 1; }
[ -f $SECP/src/secp256k1.c ] || { echo "build.sh: secp256k1 inside koinu is not checked out" >&2; exit 1; }

SRC="$KW/crypto/hex.c $KW/crypto/sha2.c $KW/crypto/sha2_hw.c $KW/crypto/cpu.c
     $KW/crypto/ripemd160.c $KW/crypto/hmac.c $KW/crypto/pbkdf2.c $KW/crypto/siphash.c
     $KW/crypto/base58.c $KW/crypto/ec.c $KW/crypto/bip32.c $KW/crypto/bip39.c
     $KW/crypto/bip44.c $KW/crypto/address.c $KW/crypto/chainparams.c
     $KW/crypto/slip39.c $KW/crypto/codex32.c $KW/crypto/scrypt.c $KW/crypto/scrypt_avx2.c
     $KW/crypto/chacha20.c $KW/crypto/aead.c $KW/crypto/kdf.c $KW/crypto/keystore.c
     $KW/crypto/tx.c $KW/crypto/log.c
     $KW/crypto/vendor/argon2/argon2.c $KW/crypto/vendor/argon2/core.c
     $KW/crypto/vendor/argon2/encoding.c $KW/crypto/vendor/argon2/ref.c
     $KW/crypto/vendor/argon2/thread.c $KW/crypto/vendor/argon2/blake2/blake2b.c
     $KW/crypto/vendor/poly1305-donna/poly1305-donna.c
     $KW/net/pow.c $KW/net/auxpow.c $KW/net/gcs.c
     $SECP/src/secp256k1.c $SECP/src/precomputed_ecmult.c $SECP/src/precomputed_ecmult_gen.c
     kw_web.c"

# -I$KW so kw_web.c can reach test/bip158_vectors.h, which is the filter
# chapter's vectors rather than a copy of them.
$ZIG cc -target wasm32-wasi -mexec-model=reactor -O2 -std=gnu11 \
    -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_MMAN \
    -lwasi-emulated-process-clocks -lwasi-emulated-signal -lwasi-emulated-mman \
    -I$KW -I$KW/crypto -I$KW/net -I$KW/wallet -I$KW/include -I$SECP/include -I$SECP \
    -I$KW/crypto/vendor/poly1305-donna -I$KW/crypto/vendor/argon2 \
    -DARGON2_NO_THREADS -DECMULT_WINDOW_SIZE=2 \
    -include $KW/crypto/vendor/kw_symbols.h \
    -Wl,--export=malloc -Wl,--export=free -Wl,-z,stack-size=1048576 -Wl,--strip-all \
    -o koinu.wasm $SRC
ls -l koinu.wasm
