/*
 * mdindex_bridge.c -- the hash primitives hx's own registry does not carry.
 *
 * hx_func.c, built standalone the way mdxfind builds it, implements md5,
 * md4, sha1, sha256 and sha512 directly against OpenSSL and leaves every
 * other primitive to the caller.  hashpipe supplies them by registering its
 * compute_* functions, but those read a thread-local workspace that only
 * hashpipe has, so mdindex cannot borrow them; it registers its own against
 * the same libraries mdxfind itself calls.  Without this, 220 of the 571
 * indexable catalog expressions do not compile.
 *
 * A bridge has hashpipe's compute_* signature -- (pass, passlen, salt,
 * saltlen, dest) -- and hx_bridge_hash wraps it, handling the _bin, _hex,
 * _b64 and _uc output roles.  The salt arguments are unused here by
 * construction: a type that needs a salt is not indexable.
 *
 * Every primitive is the one mdxfind calls for the same type.  That is the
 * whole point of the file -- a second implementation that disagreed would
 * build an index of digests mdxfind never produces, and the disagreement
 * would look exactly like a wordlist that does not contain the word.
 *
 * $Revision: 1.2 $
 * $Log: mdindex_bridge.c,v $
 * Revision 1.2  2026/10/20 12:56:48  dlr
 * Add lm, mysql3 and murmur64a. lm comes from lm.a, the library mdxfind links, with the upper-case and 14-byte truncation mdxfind applies before the call. mysql3 and murmur64a have no library and are transcribed from mdxfind.c, the only two primitives here that are not a call into someone elses code; both are frozen legacy algorithms so there is no moving target to drift from. Both are eight bytes, shorter than the index key, and are bridged for the types that nest them inside a full-width digest; mdindex refuses the bare forms on width.
 *
 * Revision 1.1  2026/10/20 02:29:21  dlr
 * Initial revision. The hash primitives hx's own registry does not carry, bridged to the libraries mdxfind itself calls.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <mhash.h>
#include <rhash.h>
#include <openssl/evp.h>

#include <sph_blake.h>
#include <sph_bmw.h>
#include <sph_cubehash.h>
#include <sph_echo.h>
#include <sph_fugue.h>
#include <sph_groestl.h>
#include <sph_hamsi.h>
#include <sph_haval.h>
#include <sph_jh.h>
#include <sph_keccak.h>
#include <sph_luffa.h>
#include <sph_md2.h>
#include <sph_panama.h>
#include <sph_radiogatun.h>
#include <sph_ripemd.h>
#include <sph_sha0.h>
#include <sph_sha2.h>
#include <sph_shabal.h>
#include <sph_shavite.h>
#include <sph_simd.h>
#include <sph_skein.h>
#include <sph_tiger.h>
#include <sph_whirlpool.h>

#include "md6.h"
#include "hx_vm.h"

/* lm.a, the library mdxfind links for the LAN Manager hash.  It does NOT
 * upper-case or truncate; mdxfind does both before calling, so br_lm does
 * the same and for the same reason -- a bridge that prepared its input
 * differently would be the second implementation this file exists to
 * avoid. */
extern unsigned char *auth_LMhash(unsigned char *dst, const char *pwd,
                                  int pwdlen);

/* ---- the three mdxfind keeps to itself ----
 *
 * lm comes from lm.a.  mysql3 and murmur64a are static inside mdxfind.c
 * with no library behind them, so they are transcribed here -- the only
 * two in this file that are not a call into someone else's code.  Both
 * are frozen legacy algorithms, MySQL's pre-4.1 OLD_PASSWORD and
 * MurmurHash64A, so there is no moving target to drift from; each was
 * checked against mdxfind's own output before being used.
 *
 * mysql3 and murmur64a are EIGHT BYTES, which is shorter than the index
 * key.  They are bridged anyway, because the types that matter nest them
 * inside a full-width digest -- md5(mysql3(pass)) is an ordinary MD5 --
 * and sel_add_hx refuses the bare forms on digest width. */

/* LM: upper-case, truncate at 14, then the library.  16 bytes. */
static void br_lm(const unsigned char *p, int n,
                  const unsigned char *s, int sl, unsigned char *d)
{
    char up[16];
    int  i, len = n > 14 ? 14 : n;

    (void)s; (void)sl;
    for (i = 0; i < len; i++)
        up[i] = (p[i] >= 'a' && p[i] <= 'z') ? (char)(p[i] - 32) : (char)p[i];
    up[len] = 0;
    auth_LMhash(d, up, len);
}

/* MySQL pre-4.1 OLD_PASSWORD.  Skips spaces and tabs, and yields two
 * 31-bit halves printed as 16 hex characters -- 8 bytes decoded. */
static void br_mysql3(const unsigned char *p, int n,
                      const unsigned char *s, int sl, unsigned char *d)
{
    unsigned int nr = 1345345333u, nr2 = 0x12345671u, add = 7, tmp;
    unsigned char ch;
    char buf[20];
    int  i;

    (void)s; (void)sl;
    for (i = 0; i < n; i++) {
        ch = p[i];
        if (ch == ' ' || ch == '\t') continue;
        tmp = ch;
        nr  ^= (((nr & 63) + add) * tmp) + ((nr << 8) & 0xffffffffu);
        nr2 += ((nr2 << 8) & 0xffffffffu) ^ nr;
        add += tmp;
    }
    snprintf(buf, sizeof(buf), "%08x%08x", nr & 0x7fffffffu, nr2 & 0x7fffffffu);
    for (i = 0; i < 8; i++) {
        unsigned v;
        sscanf(buf + i * 2, "%2x", &v);
        d[i] = (unsigned char)v;
    }
}

/* MurmurHash64A with a zero seed, big-endian in the digest, which is how
 * mdxfind lays it out for hex display.  8 bytes. */
static void br_murmur64a(const unsigned char *p, int n,
                         const unsigned char *s, int sl, unsigned char *d)
{
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int      r = 47;
    uint64_t       h = (uint64_t)0 ^ ((uint64_t)n * m);
    const unsigned char *data = p, *end = p + (n - (n & 7));
    int i;

    (void)s; (void)sl;
    while (data != end) {
        uint64_t k;
        memcpy(&k, data, sizeof(k));
        data += 8;
        k *= m; k ^= k >> r; k *= m;
        h ^= k; h *= m;
    }
    switch (n & 7) {
    case 7: h ^= (uint64_t)data[6] << 48; /* FALLTHROUGH */
    case 6: h ^= (uint64_t)data[5] << 40; /* FALLTHROUGH */
    case 5: h ^= (uint64_t)data[4] << 32; /* FALLTHROUGH */
    case 4: h ^= (uint64_t)data[3] << 24; /* FALLTHROUGH */
    case 3: h ^= (uint64_t)data[2] << 16; /* FALLTHROUGH */
    case 2: h ^= (uint64_t)data[1] << 8;  /* FALLTHROUGH */
    case 1: h ^= (uint64_t)data[0];       h *= m;
    }
    h ^= h >> r; h *= m; h ^= h >> r;
    for (i = 0; i < 8; i++) d[i] = (unsigned char)((h >> (56 - i * 8)) & 0xff);
}

/* ---- libsph: one uniform init/update/close triple per primitive ---- */

#define SPH(HX, SPHN)                                                        \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    sph_##SPHN##_context c;                                                  \
    (void)s; (void)sl;                                                       \
    sph_##SPHN##_init(&c);                                                   \
    sph_##SPHN(&c, p, (size_t)n);                                            \
    sph_##SPHN##_close(&c, d);                                               \
}

SPH(blake224, blake224)   SPH(blake256, blake256)
SPH(blake384, blake384)   SPH(blake512, blake512)
SPH(bmw224, bmw224)       SPH(bmw256, bmw256)
SPH(bmw384, bmw384)       SPH(bmw512, bmw512)
SPH(cube224, cubehash224) SPH(cube256, cubehash256)
SPH(cube384, cubehash384) SPH(cube512, cubehash512)
SPH(echo224, echo224)     SPH(echo256, echo256)
SPH(echo384, echo384)     SPH(echo512, echo512)
SPH(fugue224, fugue224)   SPH(fugue256, fugue256)
SPH(fugue384, fugue384)   SPH(fugue512, fugue512)
SPH(groestl224, groestl224) SPH(groestl256, groestl256)
SPH(groestl384, groestl384) SPH(groestl512, groestl512)
SPH(hamsi224, hamsi224)   SPH(hamsi256, hamsi256)
SPH(hamsi384, hamsi384)   SPH(hamsi512, hamsi512)
SPH(jh224, jh224)         SPH(jh256, jh256)
SPH(jh384, jh384)         SPH(jh512, jh512)
SPH(keccak224, keccak224) SPH(keccak256, keccak256)
SPH(keccak384, keccak384) SPH(keccak512, keccak512)
SPH(luffa224, luffa224)   SPH(luffa256, luffa256)
SPH(luffa384, luffa384)   SPH(luffa512, luffa512)
SPH(shabal224, shabal224) SPH(shabal256, shabal256)
SPH(shabal384, shabal384) SPH(shabal512, shabal512)
SPH(shavite224, shavite224) SPH(shavite256, shavite256)
SPH(shavite384, shavite384) SPH(shavite512, shavite512)
SPH(simd224, simd224)     SPH(simd256, simd256)
SPH(simd384, simd384)     SPH(simd512, simd512)
SPH(skein224, skein224)   SPH(skein256, skein256)
SPH(skein384, skein384)   SPH(skein512, skein512)
SPH(md2, md2)             SPH(panama, panama)
SPH(radiogatun32, radiogatun32) SPH(radiogatun64, radiogatun64)
SPH(ripemd, ripemd)       SPH(rmd128, ripemd128)
SPH(rmd160, ripemd160)
SPH(sha0, sha0)           SPH(sha224, sha224)
SPH(sha384, sha384)
SPH(tiger, tiger)         SPH(tiger2, tiger2)
SPH(wrl, whirlpool)       SPH(wrl0, whirlpool0)
SPH(wrl1, whirlpool1)

/* The bare HAVAL names are the 3-pass variants, as mdxfind's own
 * JOB_HAV128HEXSALT arm shows: sph_haval128_3. */
SPH(hav128, haval128_3)   SPH(hav128_4, haval128_4)
SPH(hav128_5, haval128_5)
SPH(hav160_3, haval160_3) SPH(hav160_4, haval160_4)
SPH(hav160_5, haval160_5)
SPH(hav192_3, haval192_3) SPH(hav192_4, haval192_4)
SPH(hav192_5, haval192_5)
SPH(hav224_3, haval224_3) SPH(hav224_4, haval224_4)
SPH(hav224_5, haval224_5)
SPH(hav256, haval256_3)   SPH(hav256_4, haval256_4)
SPH(hav256_5, haval256_5)

/* ---- librhash: one call, selected by algorithm id ---- */

#define RH(HX, ID)                                                           \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    (void)s; (void)sl;                                                       \
    rhash_msg(ID, p, (size_t)n, d);                                          \
}

RH(has160, RHASH_HAS160)     RH(tth, RHASH_TTH)
RH(ed2k, RHASH_ED2K)         RH(aich, RHASH_AICH)
RH(gost, RHASH_GOST)         RH(gost_crypto, RHASH_GOST_CRYPTOPRO)
RH(sne128, RHASH_SNEFRU128)  RH(sne256, RHASH_SNEFRU256)
RH(edon256, RHASH_EDONR256)  RH(edon512, RHASH_EDONR512)
RH(sha3_224, RHASH_SHA3_224) RH(sha3_256, RHASH_SHA3_256)
RH(sha3_384, RHASH_SHA3_384) RH(sha3_512, RHASH_SHA3_512)

/* ---- libmhash: the two RIPEMD widths libsph does not carry ---- */

#define MH(HX, ID)                                                           \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    MHASH td;                                                                \
    (void)s; (void)sl;                                                       \
    td = mhash_init(ID);                                                     \
    if (td == MHASH_FAILED) {                                                \
        fprintf(stderr, "mdindex_bridge.c: mhash_init(%s) failed\n", #ID);   \
        exit(1);                                                             \
    }                                                                        \
    mhash(td, p, (mutils_word32)n);                                          \
    mhash_deinit(td, d);                                                     \
}

MH(rmd256, MHASH_RIPEMD256)  MH(rmd320, MHASH_RIPEMD320)

/* ---- OpenSSL EVP, for the two it has and libsph does not ---- */

#define EVPB(HX, MDFN)                                                       \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    EVP_MD_CTX *c = EVP_MD_CTX_new();                                        \
    unsigned int outl = 0;                                                   \
    (void)s; (void)sl;                                                       \
    if (c == NULL || EVP_DigestInit_ex(c, MDFN(), NULL) != 1 ||              \
        EVP_DigestUpdate(c, p, (size_t)n) != 1 ||                            \
        EVP_DigestFinal_ex(c, d, &outl) != 1) {                              \
        fprintf(stderr, "mdindex_bridge.c: EVP %s failed\n", #MDFN);         \
        exit(1);                                                             \
    }                                                                        \
    EVP_MD_CTX_free(c);                                                      \
}

EVPB(sm3, EVP_sm3)
EVPB(blake2s256, EVP_blake2s256)
EVPB(mdc2, EVP_mdc2)

/* ---- md6: one function, the digest width is an argument ---- */

#define MD6B(HX, BITS)                                                       \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    (void)s; (void)sl;                                                       \
    md6_hash(BITS, (unsigned char *)p, (uint64_t)n * 8, d);                  \
}

/* JOB_MD6 enters with i = 128, so the bare name is the 128-bit width. */
MD6B(md6, 128)      MD6B(md6128, 128)
MD6B(md6256, 256)   MD6B(md6512, 512)

/* ---- GOST R 34.11-2012 (Streebog) ----
 *
 * gost2012_32 and gost2012_64 are what mdxfind itself calls, and they are
 * already exported from gosthash/gost2012.a.  Calling them rather than
 * driving streebog_init/update/final here settles the byte order by
 * construction: the bundled Saarinen implementation reverses its output,
 * and a reimplementation that got that wrong would produce digests nothing
 * else in the suite emits.  No header declares them, hence the externs. */

extern void gost2012_32(void *data, size_t len, void *hash);
extern void gost2012_64(void *data, size_t len, void *hash);

#define STB(HX, FN)                                                          \
static void br_##HX(const unsigned char *p, int n,                           \
                    const unsigned char *s, int sl, unsigned char *d)        \
{                                                                            \
    (void)s; (void)sl;                                                       \
    FN((void *)p, (size_t)n, d);                                             \
}

STB(gost2012_32, gost2012_32)  STB(gost2012_64, gost2012_64)
STB(streebog_32, gost2012_32)  STB(streebog_64, gost2012_64)

/* ---- the registry ---- */

struct bridgerow { const char *name; hx_bridge_fn fn; int dlen; };

#define R(HX, LEN) { #HX, br_##HX, LEN }

static const struct bridgerow Bridges[] = {
    R(blake224,28), R(blake256,32), R(blake384,48), R(blake512,64),
    R(bmw224,28),   R(bmw256,32),   R(bmw384,48),   R(bmw512,64),
    R(cube224,28),  R(cube256,32),  R(cube384,48),  R(cube512,64),
    R(echo224,28),  R(echo256,32),  R(echo384,48),  R(echo512,64),
    R(fugue224,28), R(fugue256,32), R(fugue384,48), R(fugue512,64),
    R(groestl224,28), R(groestl256,32), R(groestl384,48), R(groestl512,64),
    R(hamsi224,28), R(hamsi256,32), R(hamsi384,48), R(hamsi512,64),
    R(jh224,28),    R(jh256,32),    R(jh384,48),    R(jh512,64),
    R(keccak224,28),R(keccak256,32),R(keccak384,48),R(keccak512,64),
    R(luffa224,28), R(luffa256,32), R(luffa384,48), R(luffa512,64),
    R(shabal224,28),R(shabal256,32),R(shabal384,48),R(shabal512,64),
    R(shavite224,28),R(shavite256,32),R(shavite384,48),R(shavite512,64),
    R(simd224,28),  R(simd256,32),  R(simd384,48),  R(simd512,64),
    R(skein224,28), R(skein256,32), R(skein384,48), R(skein512,64),
    R(md2,16),      R(panama,32),
    R(radiogatun32,16), R(radiogatun64,32),
    R(ripemd,16),   R(rmd128,16),   R(rmd160,20),
    R(rmd256,32),   R(rmd320,40),
    R(sha0,20),     R(sha224,28),   R(sha384,48),
    R(tiger,24),    R(tiger2,24),
    R(wrl,64),      R(wrl0,64),     R(wrl1,64),
    R(hav128,16),   R(hav128_4,16), R(hav128_5,16),
    R(hav160_3,20), R(hav160_4,20), R(hav160_5,20),
    R(hav192_3,24), R(hav192_4,24), R(hav192_5,24),
    R(hav224_3,28), R(hav224_4,28), R(hav224_5,28),
    R(hav256,32),   R(hav256_4,32), R(hav256_5,32),
    R(has160,20),   R(tth,24),      R(ed2k,16),     R(aich,20),
    R(gost,32),     R(gost_crypto,32),
    R(sne128,16),   R(sne256,32),
    R(edon256,32),  R(edon512,64),
    R(sha3_224,28), R(sha3_256,32), R(sha3_384,48), R(sha3_512,64),
    R(sm3,32),      R(blake2s256,32), R(mdc2,16),
    R(md6,16),      R(md6128,16),   R(md6256,32),   R(md6512,64),
    R(gost2012_32,32), R(gost2012_64,64),
    R(streebog_32,32), R(streebog_64,64),
    R(lm,16),       R(mysql3,8),    R(murmur64a,8),
};
#define NBRIDGE ((int)(sizeof(Bridges) / sizeof(Bridges[0])))

/*
 * Register every bridge hx does not already provide.  Called once, before
 * any expression is compiled: hx_compile resolves a function name to a
 * table ENTRY at compile time, so a primitive registered afterwards would
 * be invisible to programs already compiled.
 *
 * An existing name is never replaced.  hx_func.c's own md5/sha1/sha256 are
 * the implementations mdxfind uses too, and quietly shadowing one here
 * would be the second implementation this file exists to avoid.
 */
int mdindex_bridges_register(void)
{
    int i, added = 0;

    rhash_library_init();
    for (i = 0; i < NBRIDGE; i++) {
        if (hx_func_lookup(Bridges[i].name)) continue;
        hx_func_register(Bridges[i].name, hx_bridge_hash, Bridges[i].dlen,
                         Bridges[i].fn, Bridges[i].dlen,
                         ROLE_CAP_BIN | ROLE_CAP_HEX | ROLE_CAP_B64 |
                         ROLE_CAP_UC,
                         ROLE_HEX);
        added++;
    }
    return added;
}
