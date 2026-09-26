/* BLAKE2b (512-bit) and BLAKE2s (256-bit) hash functions, RFC 7693.
 * Header-only pure C implementation (no key, no salt/personalization).
 */
#ifndef __BLAKE2_H__
#define __BLAKE2_H__

#include <stdint.h>
#include <string.h>

static const uint8_t blake2_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/* ---------------- BLAKE2b (512-bit) ---------------- */

#define BLAKE2B_OUTBYTES   64
#define BLAKE2B_BLOCKBYTES 128

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

typedef struct {
    uint64_t h[8];
    uint64_t t[2];         /* byte counter, t[0]=low t[1]=high */
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    uint32_t buflen;
    uint8_t  outlen;
    uint8_t  last;
    uint8_t  result[BLAKE2B_OUTBYTES];
} blake2b_ctx;

static uint64_t blake2b_load64(const uint8_t* p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static void blake2b_store64(uint8_t* p, uint64_t v) {
    int i;
    for (i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t blake2b_rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static void blake2b_compress(blake2b_ctx* S, const uint8_t* block) {
    uint64_t m[16], v[16];
    int i;

    for (i = 0; i < 16; ++i) m[i] = blake2b_load64(block + i * 8);
    for (i = 0; i < 8; ++i) v[i] = S->h[i];
    for (i = 0; i < 8; ++i) v[i + 8] = blake2b_IV[i];
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    if (S->last) v[14] = ~v[14];

#define G_B2B(r, i, a, b, c, d)                                     \
    do {                                                            \
        a = a + b + m[blake2_sigma[r][2 * i + 0]];                  \
        d = blake2b_rotr64(d ^ a, 32);                              \
        c = c + d;                                                  \
        b = blake2b_rotr64(b ^ c, 24);                              \
        a = a + b + m[blake2_sigma[r][2 * i + 1]];                  \
        d = blake2b_rotr64(d ^ a, 16);                              \
        c = c + d;                                                  \
        b = blake2b_rotr64(b ^ c, 63);                              \
    } while (0)

#define ROUND_B2B(r)                                    \
    G_B2B(r, 0, v[0], v[4], v[8],  v[12]);              \
    G_B2B(r, 1, v[1], v[5], v[9],  v[13]);              \
    G_B2B(r, 2, v[2], v[6], v[10], v[14]);              \
    G_B2B(r, 3, v[3], v[7], v[11], v[15]);              \
    G_B2B(r, 4, v[0], v[5], v[10], v[15]);              \
    G_B2B(r, 5, v[1], v[6], v[11], v[12]);              \
    G_B2B(r, 6, v[2], v[7], v[8],  v[13]);              \
    G_B2B(r, 7, v[3], v[4], v[9],  v[14])

    ROUND_B2B(0); ROUND_B2B(1); ROUND_B2B(2); ROUND_B2B(3);
    ROUND_B2B(4); ROUND_B2B(5); ROUND_B2B(6); ROUND_B2B(7);
    ROUND_B2B(8); ROUND_B2B(9); ROUND_B2B(0); ROUND_B2B(1);

#undef G_B2B
#undef ROUND_B2B

    for (i = 0; i < 8; ++i)
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

static void blake2b_init(blake2b_ctx* S) {
    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; ++i) S->h[i] = blake2b_IV[i];
    /* parameter block: fanout=1, depth=1, keylen=0, digest length=64 */
    S->h[0] ^= 0x01010040ULL;
    S->outlen = BLAKE2B_OUTBYTES;
    S->last = 0;
}

static void blake2b_update(blake2b_ctx* S, const uint8_t* data, uint32_t len) {
    while (len > 0) {
        uint32_t n = BLAKE2B_BLOCKBYTES - S->buflen;
        if (n > len) n = len;
        memcpy(S->buf + S->buflen, data, n);
        S->buflen += n;
        S->t[0] += n;
        if (S->t[0] < n) S->t[1]++;
        data += n;
        len -= n;
        if (S->buflen == BLAKE2B_BLOCKBYTES) {
            blake2b_compress(S, S->buf);
            S->buflen = 0;
        }
    }
}

static void blake2b_final(blake2b_ctx* S) {
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    S->last = 1;
    blake2b_compress(S, S->buf);
    for (int i = 0; i < 8; ++i)
        blake2b_store64(S->result + i * 8, S->h[i]);
}

/* ---------------- BLAKE2s (256-bit) ---------------- */

#define BLAKE2S_OUTBYTES   32
#define BLAKE2S_BLOCKBYTES 64

static const uint32_t blake2s_IV[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    uint32_t buflen;
    uint8_t  outlen;
    uint8_t  last;
    uint8_t  result[BLAKE2S_OUTBYTES];
} blake2s_ctx;

static uint32_t blake2s_load32(const uint8_t* p) {
    uint32_t v = 0;
    int i;
    for (i = 0; i < 4; ++i) v |= ((uint32_t)p[i]) << (8 * i);
    return v;
}

static void blake2s_store32(uint8_t* p, uint32_t v) {
    int i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t blake2s_rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void blake2s_compress(blake2s_ctx* S, const uint8_t* block) {
    uint32_t m[16], v[16];
    int i;

    for (i = 0; i < 16; ++i) m[i] = blake2s_load32(block + i * 4);
    for (i = 0; i < 8; ++i) v[i] = S->h[i];
    for (i = 0; i < 8; ++i) v[i + 8] = blake2s_IV[i];
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    if (S->last) v[14] = ~v[14];

#define G_B2S(r, i, a, b, c, d)                                     \
    do {                                                            \
        a = a + b + m[blake2_sigma[r][2 * i + 0]];                  \
        d = blake2s_rotr32(d ^ a, 16);                              \
        c = c + d;                                                  \
        b = blake2s_rotr32(b ^ c, 12);                              \
        a = a + b + m[blake2_sigma[r][2 * i + 1]];                  \
        d = blake2s_rotr32(d ^ a, 8);                               \
        c = c + d;                                                  \
        b = blake2s_rotr32(b ^ c, 7);                               \
    } while (0)

#define ROUND_B2S(r)                                    \
    G_B2S(r, 0, v[0], v[4], v[8],  v[12]);              \
    G_B2S(r, 1, v[1], v[5], v[9],  v[13]);              \
    G_B2S(r, 2, v[2], v[6], v[10], v[14]);              \
    G_B2S(r, 3, v[3], v[7], v[11], v[15]);              \
    G_B2S(r, 4, v[0], v[5], v[10], v[15]);              \
    G_B2S(r, 5, v[1], v[6], v[11], v[12]);              \
    G_B2S(r, 6, v[2], v[7], v[8],  v[13]);              \
    G_B2S(r, 7, v[3], v[4], v[9],  v[14])

    ROUND_B2S(0); ROUND_B2S(1); ROUND_B2S(2); ROUND_B2S(3);
    ROUND_B2S(4); ROUND_B2S(5); ROUND_B2S(6); ROUND_B2S(7);
    ROUND_B2S(8); ROUND_B2S(9);

#undef G_B2S
#undef ROUND_B2S

    for (i = 0; i < 8; ++i)
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

static void blake2s_init(blake2s_ctx* S) {
    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; ++i) S->h[i] = blake2s_IV[i];
    /* parameter block: fanout=1, depth=1, keylen=0, digest length=32 */
    S->h[0] ^= 0x01010020UL;
    S->outlen = BLAKE2S_OUTBYTES;
    S->last = 0;
}

static void blake2s_update(blake2s_ctx* S, const uint8_t* data, uint32_t len) {
    while (len > 0) {
        uint32_t n = BLAKE2S_BLOCKBYTES - S->buflen;
        if (n > len) n = len;
        memcpy(S->buf + S->buflen, data, n);
        S->buflen += n;
        S->t[0] += n;
        if (S->t[0] < n) S->t[1]++;
        data += n;
        len -= n;
        if (S->buflen == BLAKE2S_BLOCKBYTES) {
            blake2s_compress(S, S->buf);
            S->buflen = 0;
        }
    }
}

static void blake2s_final(blake2s_ctx* S) {
    memset(S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen);
    S->last = 1;
    blake2s_compress(S, S->buf);
    for (int i = 0; i < 8; ++i)
        blake2s_store32(S->result + i * 4, S->h[i]);
}

#endif /* __BLAKE2_H__ */