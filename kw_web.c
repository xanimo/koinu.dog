/* koinu.dog - browser shim for the learn pages
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Thin wrappers over the library for the runnable panels on koinu.dog. Every
 * function takes strings and returns a JSON string in one static buffer, so the
 * page needs nothing but a pointer and a length. The work is done by the same
 * crypto/ and net/ code kw links; nothing here reimplements a primitive.
 *
 * Two pieces of the native build have no meaning in a browser and are replaced
 * at the bottom of this file rather than patched in their own sources:
 * kw_random_bytes reads getentropy(), which the loader backs with
 * crypto.getRandomValues, and the mlock half of crypto/mem.c becomes zeroing
 * only, since wasm linear memory has no pages to pin and no swap to keep them
 * out of. This is a teaching build. It is not a wallet, and it says so. */

#include "hex.h"
#include "base58.h"
#include "sha2.h"
#include "ripemd160.h"
#include "bip39.h"
#include "bip32.h"
#include "bip44.h"
#include "address.h"
#include "chainparams.h"
#include "ec.h"
#include "keystore.h"
#include "tx.h"
#include "slip39.h"
#include "codex32.h"
#include "scrypt.h"
#include "pow.h"
#include "auxpow.h"
#include "gcs.h"
#include "mem.h"
#include "test/bip158_vectors.h"   /* -I the koinu submodule root */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXPORT(name) __attribute__((export_name(#name)))

/* ── io ────────────────────────────────────────────────────────────────── */

static char out[65536];
static size_t olen;

static void o_reset(void) { olen = 0; out[0] = 0; }
static void o_add(const char *fmt, ...)
{
    if (olen >= sizeof out - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + olen, sizeof out - olen, fmt, ap);
    va_end(ap);
    if (n > 0) olen += (size_t)n < sizeof out - olen ? (size_t)n : sizeof out - olen - 1;
}
static void o_hex(const char *key, const uint8_t *b, size_t n, int comma)
{
    o_add("\"%s\":\"", key);
    for (size_t i = 0; i < n; i++) o_add("%02x", b[i]);
    o_add("\"%s", comma ? "," : "");
}
static void o_rhex(const char *key, const uint8_t *b, size_t n, int comma)
{
    o_add("\"%s\":\"", key);
    for (size_t i = n; i-- > 0; ) o_add("%02x", b[i]);
    o_add("\"%s", comma ? "," : "");
}
/* a JSON string, escaping what JSON requires */
static void o_str(const char *key, const char *s, int comma)
{
    o_add("\"%s\":\"", key);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') o_add("\\%c", *s);
        else if ((unsigned char)*s < 0x20) o_add("\\u%04x", (unsigned char)*s);
        else o_add("%c", *s);
    }
    o_add("\"%s", comma ? "," : "");
}
static const char *fail(const char *why)
{
    o_reset();
    o_add("{");
    o_str("error", why, 0);
    o_add("}");
    return out;
}

/* the page writes inputs here */
EXPORT(kwj_alloc) void *kwj_alloc(size_t n) { return malloc(n); }
EXPORT(kwj_free)  void kwj_free(void *p)    { free(p); }
EXPORT(kwj_len)   size_t kwj_len(void)       { return olen; }

static int unhex(const char *h, uint8_t *b, size_t cap, size_t *n)
{
    size_t l = strlen(h);
    if (l % 2 || l / 2 > cap) return 0;
    if (!kw_hex_decode(h, l, b, l / 2)) return 0;
    *n = l / 2;
    return 1;
}

/* ── 1. keys ───────────────────────────────────────────────────────────── */

EXPORT(kwj_generate) const char *kwj_generate(int words)
{
    char m[KW_BIP39_MNEMONIC_MAX];
    size_t ent = words == 24 ? 32 : 16;
    o_reset();
    if (!kw_bip39_generate(ent, m, sizeof m)) return fail("no randomness");
    o_add("{");
    o_str("mnemonic", m, 0);
    o_add("}");
    kw_secure_zero(m, sizeof m);
    return out;
}

EXPORT(kwj_keys) const char *kwj_keys(const char *mnemonic, const char *pass,
                                      uint32_t change, uint32_t index)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    uint8_t ent[32], seed[KW_BIP39_SEED_LEN];
    size_t entlen = 0;
    if (!kw_bip39_check(mnemonic)) return fail("not a valid bip39 mnemonic: a word is not on the list, or the checksum does not match");
    if (!kw_bip39_to_entropy(mnemonic, ent, sizeof ent, &entlen)) return fail("entropy");
    if (!kw_bip39_to_seed(mnemonic, pass, seed)) return fail("seed");

    kw_bip32_key master, leaf;
    if (!kw_bip32_from_seed(seed, sizeof seed, cp->bip32, &master)) return fail("master");
    if (!kw_bip44_derive(&master, cp->bip44_coin, 0, change, index, &leaf)) return fail("derive");

    uint8_t pub[33], h160[20], sh[32];
    char addr[64], wif[64];
    kw_bip32_pubkey(&leaf, pub);
    kw_sha256(pub, 33, sh);
    kw_ripemd160(sh, 32, h160);
    kw_address_p2pkh(pub, cp->p2pkh, addr, sizeof addr);
    kw_wif_encode(leaf.key + 1, 1, cp->wif, wif, sizeof wif);

    o_reset();
    o_add("{");
    o_hex("entropy", ent, entlen, 1);
    o_hex("seed", seed, sizeof seed, 1);
    o_hex("master_key", master.key + 1, 32, 1);
    o_hex("master_chain", master.chain_code, 32, 1);
    o_add("\"path\":\"m/44'/%u'/0'/%u/%u\",", cp->bip44_coin, change, index);
    o_hex("child_key", leaf.key + 1, 32, 1);
    o_hex("pubkey", pub, 33, 1);
    o_hex("sha256", sh, 32, 1);
    o_hex("hash160", h160, 20, 1);
    o_add("\"version\":\"%02x\",", cp->p2pkh);
    o_str("wif", wif, 1);
    o_str("address", addr, 0);
    o_add("}");

    kw_secure_zero(seed, sizeof seed); kw_secure_zero(ent, sizeof ent);
    kw_secure_zero(&master, sizeof master); kw_secure_zero(&leaf, sizeof leaf);
    kw_secure_zero(wif, sizeof wif);
    return out;
}

/* ── 2. keystore ───────────────────────────────────────────────────────── */

EXPORT(kwj_seal) const char *kwj_seal(const char *secret, const char *pass,
                                      uint32_t t, uint32_t m_kib)
{
    size_t n = strlen(secret);
    if (!n) return fail("nothing to seal");
    kw_keystore_params p = { t, m_kib, 1 };
    size_t cap = kw_keystore_sealed_size(n);
    uint8_t *blob = malloc(cap);
    if (!blob) return fail("memory");
    size_t got = kw_keystore_seal((const uint8_t *)secret, n, pass, &p, blob, cap);
    if (!got) { free(blob); return fail("seal refused (parameters out of range?)"); }
    o_reset();
    o_add("{");
    o_hex("blob", blob, got, 0);
    o_add("}");
    free(blob);
    return out;
}

EXPORT(kwj_open) const char *kwj_open(const char *hexblob, const char *pass)
{
    size_t l = strlen(hexblob), n = 0;
    uint8_t *blob = malloc(l / 2 + 1), *sec = malloc(KW_KEYSTORE_MAX_SECRET + 1);
    if (!blob || !sec) { free(blob); free(sec); return fail("memory"); }
    size_t slen = 0;
    int ok = unhex(hexblob, blob, l / 2 + 1, &n) &&
             kw_keystore_open(blob, n, pass, sec, KW_KEYSTORE_MAX_SECRET, &slen);
    o_reset();
    o_add("{\"ok\":%d", ok);
    if (ok) { sec[slen] = 0; o_add(","); o_str("secret", (const char *)sec, 0); }
    o_add("}");
    kw_secure_zero(sec, KW_KEYSTORE_MAX_SECRET + 1);
    free(blob); free(sec);
    return out;
}

/* ── 4. transactions ───────────────────────────────────────────────────── */

EXPORT(kwj_tx) const char *kwj_tx(const char *rawhex, int sig_index, const char *prevspk_hex)
{
    static uint8_t raw[16384];
    size_t n = 0;
    if (!unhex(rawhex, raw, sizeof raw, &n)) return fail("not hex, or longer than 16 KiB");
    kw_tx *tx = kw_tx_new();
    if (!tx) return fail("memory");
    size_t used = kw_tx_parse(raw, n, tx);
    if (!used) { kw_tx_free(tx); return fail("does not parse as a legacy transaction"); }

    uint8_t txid[32];
    kw_tx_txid(tx, txid);
    o_reset();
    o_add("{");
    o_rhex("txid", txid, 32, 1);
    o_add("\"bytes\":%zu,\"trailing\":%zu,\"version\":%u,\"locktime\":%u,\"inputs\":[",
          used, n - used, kw_tx_version(tx), kw_tx_locktime(tx));
    for (size_t i = 0; i < kw_tx_nin(tx); i++) {
        uint8_t prev[32]; uint32_t vout = 0;
        const uint8_t *ss = NULL; size_t sl = 0;
        kw_tx_input_prevout(tx, i, prev, &vout);
        kw_tx_input_script(tx, i, &ss, &sl);
        o_add("%s{", i ? "," : "");
        o_rhex("txid", prev, 32, 1);
        o_add("\"vout\":%u,", vout);
        o_hex("scriptsig", ss ? ss : (const uint8_t *)"", sl, 0);
        o_add("}");
    }
    o_add("],\"outputs\":[");
    for (size_t i = 0; i < kw_tx_nout(tx); i++) {
        uint64_t v = 0; const uint8_t *spk = NULL; size_t sl = 0;
        kw_tx_output(tx, i, &v, &spk, &sl);
        o_add("%s{\"value\":%llu,", i ? "," : "", (unsigned long long)v);
        o_hex("script", spk, sl, 1);
        char a[64] = "";
        if (sl == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) {
            uint8_t pl[21]; pl[0] = KW_DOGE_MAINNET.p2pkh; memcpy(pl + 1, spk + 3, 20);
            kw_base58check_encode(pl, 21, a, sizeof a);
        }
        o_str("address", a, 0);
        o_add("}");
    }
    o_add("]");

    if (sig_index >= 0 && prevspk_hex && *prevspk_hex) {
        uint8_t spk[1024], h[32]; size_t sl = 0;
        if (!unhex(prevspk_hex, spk, sizeof spk, &sl)) { kw_tx_free(tx); return fail("previous script is not hex"); }
        if ((size_t)sig_index >= kw_tx_nin(tx)) { kw_tx_free(tx); return fail("no such input"); }
        if (!kw_tx_sighash(tx, (size_t)sig_index, spk, sl, KW_SIGHASH_ALL, h)) {
            kw_tx_free(tx);
            return fail("sighash refused: a codeseparator under a branch, or between two checksigs");
        }
        o_add(",");
        o_hex("sighash", h, 32, 0);
    }
    o_add("}");
    kw_tx_free(tx);
    return out;
}

/* ── 5. shares ─────────────────────────────────────────────────────────── */

/* (spec) is "2of3" or "1of1,2of3" */
EXPORT(kwj_slip39_split) const char *kwj_slip39_split(const char *secret_hex, const char *pass,
                                                      const char *spec, int gthr)
{
    uint8_t ms[KW_SLIP39_MAX_SECRET]; size_t n = 0;
    if (!unhex(secret_hex, ms, sizeof ms, &n)) return fail("secret is not hex, or longer than 64 bytes");
    kw_slip39_group g[KW_SLIP39_MAX_GROUPS]; size_t ng = 0;
    const char *s = spec;
    while (*s && ng < KW_SLIP39_MAX_GROUPS) {
        unsigned t, c; int used = 0;
        if (sscanf(s, "%uof%u%n", &t, &c, &used) != 2) return fail("groups look like 2of3 or 1of1,2of3");
        g[ng].threshold = (uint8_t)t; g[ng].count = (uint8_t)c; ng++;
        s += used;
        if (*s == ',') s++; else if (*s) return fail("groups look like 2of3 or 1of1,2of3");
    }
    static char shares[KW_SLIP39_MAX_SHARES * KW_SLIP39_MAX_GROUPS][KW_SLIP39_MNEMONIC_MAX];
    size_t nout = 0;
    kw_slip39_err e = kw_slip39_split(ms, n, pass, 1, (uint8_t)gthr, g, ng,
                                      &shares[0][0], KW_SLIP39_MNEMONIC_MAX, &nout);
    kw_secure_zero(ms, sizeof ms);
    if (e != KW_SLIP39_OK) return fail(kw_slip39_strerror(e));
    o_reset();
    o_add("{\"shares\":[");
    for (size_t i = 0; i < nout; i++) {
        kw_slip39_share sh;
        kw_slip39_decode(shares[i], &sh);
        o_add("%s{", i ? "," : "");
        o_str("words", shares[i], 1);
        o_add("\"group\":%u,\"member\":%u}", sh.group_index, sh.member_index);
    }
    o_add("]}");
    return out;
}

static size_t split_lines(char *buf, const char **v, size_t cap)
{
    size_t n = 0;
    for (char *p = strtok(buf, "\n"); p && n < cap; p = strtok(NULL, "\n")) {
        while (*p == ' ' || *p == '\r' || *p == '\t') p++;
        char *e = p + strlen(p);
        while (e > p && (e[-1] == ' ' || e[-1] == '\r' || e[-1] == '\t')) *--e = 0;
        if (*p) v[n++] = p;
    }
    return n;
}

EXPORT(kwj_slip39_combine) const char *kwj_slip39_combine(char *lines, const char *pass)
{
    const char *v[64];
    size_t n = split_lines(lines, v, 64);
    uint8_t ms[KW_SLIP39_MAX_SECRET]; size_t len = 0;
    kw_slip39_err e = kw_slip39_combine(v, n, pass, ms, sizeof ms, &len);
    if (e != KW_SLIP39_OK) return fail(kw_slip39_strerror(e));
    o_reset();
    o_add("{");
    o_hex("secret", ms, len, 0);
    o_add("}");
    kw_secure_zero(ms, sizeof ms);
    return out;
}

EXPORT(kwj_codex32_split) const char *kwj_codex32_split(const char *secret_hex, const char *id,
                                                        int thr, int count)
{
    uint8_t s[KW_CODEX32_MAX_SECRET]; size_t n = 0;
    if (!unhex(secret_hex, s, sizeof s, &n)) return fail("secret is not hex");
    static char shares[KW_CODEX32_MAX_SHARES][KW_CODEX32_MAX_LEN + 1];
    size_t nout = 0;
    kw_codex32_err e = kw_codex32_split(s, n, id, (uint8_t)thr, (uint8_t)count,
                                        &shares[0][0], KW_CODEX32_MAX_LEN + 1, &nout);
    kw_secure_zero(s, sizeof s);
    if (e != KW_CODEX32_OK) return fail(kw_codex32_strerror(e));
    o_reset();
    o_add("{\"shares\":[");
    for (size_t i = 0; i < nout; i++) { o_add("%s\"%s\"", i ? "," : "", shares[i]); }
    o_add("]}");
    return out;
}

EXPORT(kwj_codex32_combine) const char *kwj_codex32_combine(char *lines)
{
    const char *v[KW_CODEX32_MAX_SHARES + 1];
    size_t n = split_lines(lines, v, KW_CODEX32_MAX_SHARES + 1);
    uint8_t s[KW_CODEX32_MAX_SECRET]; size_t len = 0;
    kw_codex32_err e = kw_codex32_combine(v, n, s, sizeof s, &len);
    if (e != KW_CODEX32_OK) return fail(kw_codex32_strerror(e));
    o_reset();
    o_add("{");
    o_hex("secret", s, len, 0);
    o_add("}");
    kw_secure_zero(s, sizeof s);
    return out;
}

/* ── 6. headers ────────────────────────────────────────────────────────── */

static void o_u256(const char *key, const kw_u256 *v, int comma)
{
    uint8_t b[32];
    kw_u256_to_bytes(v, b);
    o_rhex(key, b, 32, comma);
}

EXPORT(kwj_bits) const char *kwj_bits(uint32_t bits)
{
    kw_u256 t, w;
    if (!kw_bits_target(bits, &t)) return fail("not a valid target: negative, zero, or past 2^256");
    kw_bits_work(bits, &w);
    o_reset();
    o_add("{\"exponent\":%u,\"mantissa\":\"%06x\",", bits >> 24, bits & 0x7fffff);
    o_u256("target", &t, 1);
    o_u256("work", &w, 1);
    o_add("\"roundtrip\":\"%08x\"}", kw_target_bits(&t));
    return out;
}

EXPORT(kwj_retarget) const char *kwj_retarget(uint32_t height, uint32_t last_bits,
                                              uint32_t last_time, uint32_t first_time)
{
    uint32_t first = 0;
    int r = kw_pow_retargets(&KW_POW_MAIN, height, &first);
    uint32_t next = kw_pow_next_bits(&KW_POW_MAIN, height, last_bits, last_time, first_time);
    o_reset();
    o_add("{\"retargets\":%d,\"first_height\":%u,\"digishield\":%d,\"bits\":\"%08x\"}",
          r, r ? first : 0, height >= KW_POW_MAIN.digishield_height, next);
    return out;
}

EXPORT(kwj_header) const char *kwj_header(const char *hex)
{
    uint8_t h[80], id[32], pow[32]; size_t n = 0;
    if (!unhex(hex, h, sizeof h, &n) || n != 80) return fail("a header is exactly 80 bytes, 160 hex characters");
    static uint8_t scratch[KW_SCRYPT_SCRATCH];
    kw_hash256(h, 80, id);
    if (!kw_scrypt_pow(h, pow, scratch)) return fail("scrypt");
    uint32_t bits = kw_header_bits(h);
    kw_u256 t;
    int tv = kw_bits_target(bits, &t);
    o_reset();
    o_add("{\"version\":\"%08x\",\"auxpow\":%d,", kw_header_version(h), !!(kw_header_version(h) & 0x100));
    o_rhex("prev", h + 4, 32, 1);
    o_rhex("merkle", h + 36, 32, 1);
    o_add("\"time\":%u,\"bits\":\"%08x\",\"nonce\":%u,",
          kw_header_time(h), bits, (unsigned)(h[76] | h[77] << 8 | h[78] << 16 | (uint32_t)h[79] << 24));
    o_rhex("hash", id, 32, 1);
    o_rhex("pow", pow, 32, 1);
    if (tv) o_u256("target", &t, 1);
    o_add("\"meets\":%d}", tv ? kw_pow_check(pow, bits) : 0);
    return out;
}

/* ── 7. auxpow ─────────────────────────────────────────────────────────── */

EXPORT(kwj_auxpow_slot) const char *kwj_auxpow_slot(uint32_t nonce, int32_t chain_id, unsigned h)
{
    o_reset();
    o_add("{\"slot\":%u,\"size\":%u}", kw_auxpow_expected_index(nonce, chain_id, h),
          h < 32 ? 1u << h : 0);
    return out;
}

/* ── 8. filters ────────────────────────────────────────────────────────── */

static const kw_bip158_vec *vec(void) { return &KW_BIP158_VECS[2]; }  /* h49291, ten elements */

EXPORT(kwj_filter) const char *kwj_filter(void)
{
    const kw_bip158_vec *v = vec();
    static uint8_t f[4096]; static uint64_t vals[256];
    size_t fl = 0;
    unhex(v->filter, f, sizeof f, &fl);
    long N = kw_gcs_decode(f, fl, vals, 256);
    if (N < 0) return fail("decode");
    uint8_t bh[32]; size_t bl;
    unhex(v->hash_internal, bh, 32, &bl);
    o_reset();
    o_add("{");
    o_str("name", v->name, 1);
    o_rhex("block", bh, 32, 1);
    o_str("filter", v->filter, 1);
    o_add("\"bytes\":%zu,\"n\":%ld,\"range\":%llu,\"values\":[", fl, N,
          (unsigned long long)N * KW_GCS_M);
    for (long i = 0; i < N; i++) o_add("%s%llu", i ? "," : "", (unsigned long long)vals[i]);
    o_add("],\"elements\":[");
    for (int i = 0; i < v->nelem; i++) o_add("%s\"%s\"", i ? "," : "", v->elems[i]);
    o_add("]}");
    return out;
}

EXPORT(kwj_filter_match) const char *kwj_filter_match(const char *script_hex)
{
    const kw_bip158_vec *v = vec();
    uint8_t f[4096], bh[32], s[1024]; size_t fl = 0, bl = 0, sl = 0;
    if (!unhex(script_hex, s, sizeof s, &sl) || !sl) return fail("script is not hex");
    unhex(v->filter, f, sizeof f, &fl);
    unhex(v->hash_internal, bh, 32, &bl);
    static uint64_t tmp[256];
    long n = kw_gcs_decode(f, fl, tmp, 256);
    if (n < 0) return fail("decode");
    kw_gcs_item it = { s, sl };
    int m = kw_gcs_match_any(f, fl, bh, &it, 1);
    o_reset();
    o_add("{\"value\":%llu,\"match\":%d}",
          (unsigned long long)kw_gcs_hash(bh, (uint64_t)n, s, sl), m);
    return out;
}

/* ── platform ──────────────────────────────────────────────────────────── */

EXPORT(kwj_start) int kwj_start(void) { return kw_ec_start(); }

/* crypto/mem.c, less what a browser cannot do. The zeroing and the
   constant-time compare are the same loops; mlock, the core-dump limits and
   ptrace have no wasm equivalent, so keep and forget only zero. */
void kw_secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}
int kw_memcmp_ct(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return d;
}
int  kw_mlock(void *p, size_t n)          { (void)p; (void)n; return 0; }
int  kw_munlock(void *p, size_t n)        { (void)p; (void)n; return 0; }
void kw_secure_keep(void *p, size_t n)    { (void)p; (void)n; }
void kw_secure_forget(void *p, size_t n)  { kw_secure_zero(p, n); }
void kw_no_core_dumps(void)               { }
int  kw_write_secret(int fd, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    while (n) { ssize_t w = write(fd, b, n); if (w <= 0) return 0; b += w; n -= (size_t)w; }
    return 1;
}

/* getentropy is backed by crypto.getRandomValues in the loader, and fills at
   most 256 bytes a call, hence the loop. */
int kw_random_bytes(void *p, size_t len)
{
    uint8_t *b = (uint8_t *)p;
    while (len) {
        size_t k = len > 256 ? 256 : len;
        if (getentropy(b, k) != 0) { kw_secure_zero(p, len); return 0; }
        b += k; len -= k;
    }
    return 1;
}
