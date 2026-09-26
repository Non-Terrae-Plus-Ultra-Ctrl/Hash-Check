/* xxHash64 extremely fast non-cryptographic hash (64-bit output), pure C.
 * Header-only implementation (seed 0).
 */
#ifndef __XXHASH64_H__
#define __XXHASH64_H__

#include <stdint.h>
#include <string.h>

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

typedef struct {
    uint64_t total_len;
    uint64_t v1, v2, v3, v4;
    uint8_t  buf[32];
    uint32_t buf_len;
    uint8_t  result[8];
} xxhash64_ctx;

static uint64_t xxh64_rotl(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static uint64_t xxh64_read64(const uint8_t* p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static uint32_t xxh64_read32(const uint8_t* p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t xxh64_round(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc = xxh64_rotl(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static uint64_t xxh64_merge_round(uint64_t acc, uint64_t val) {
    val = xxh64_round(0, val);
    acc ^= val;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static void xxh64_init(xxhash64_ctx* ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->v1 = XXH_PRIME64_1 + XXH_PRIME64_2;
    ctx->v2 = XXH_PRIME64_2;
    ctx->v3 = 0;
    ctx->v4 = 0 - XXH_PRIME64_1;
}

static void xxh64_update(xxhash64_ctx* ctx, const uint8_t* data, uint32_t len) {
    const uint8_t* p = data;
    ctx->total_len += len;

    if (ctx->buf_len + len < 32) {
        memcpy(ctx->buf + ctx->buf_len, p, len);
        ctx->buf_len += len;
        return;
    }

    if (ctx->buf_len) {
        uint32_t fill = 32 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, p, fill);
        ctx->v1 = xxh64_round(ctx->v1, xxh64_read64(ctx->buf));
        ctx->v2 = xxh64_round(ctx->v2, xxh64_read64(ctx->buf + 8));
        ctx->v3 = xxh64_round(ctx->v3, xxh64_read64(ctx->buf + 16));
        ctx->v4 = xxh64_round(ctx->v4, xxh64_read64(ctx->buf + 24));
        p += fill;
        len -= fill;
        ctx->buf_len = 0;
    }

    while (len >= 32) {
        ctx->v1 = xxh64_round(ctx->v1, xxh64_read64(p));
        ctx->v2 = xxh64_round(ctx->v2, xxh64_read64(p + 8));
        ctx->v3 = xxh64_round(ctx->v3, xxh64_read64(p + 16));
        ctx->v4 = xxh64_round(ctx->v4, xxh64_read64(p + 24));
        p += 32;
        len -= 32;
    }

    if (len) {
        memcpy(ctx->buf, p, len);
        ctx->buf_len = len;
    }
}

static void xxh64_final(xxhash64_ctx* ctx) {
    uint64_t h;
    const uint8_t* p = ctx->buf;
    uint32_t len = ctx->buf_len;

    if (ctx->total_len >= 32) {
        h = xxh64_rotl(ctx->v1, 1) + xxh64_rotl(ctx->v2, 7) +
            xxh64_rotl(ctx->v3, 12) + xxh64_rotl(ctx->v4, 18);
        h = xxh64_merge_round(h, ctx->v1);
        h = xxh64_merge_round(h, ctx->v2);
        h = xxh64_merge_round(h, ctx->v3);
        h = xxh64_merge_round(h, ctx->v4);
    } else {
        h = XXH_PRIME64_5;
    }

    h += ctx->total_len;

    while (len >= 8) {
        uint64_t k1 = xxh64_round(0, xxh64_read64(p));
        h ^= k1;
        h = xxh64_rotl(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
        len -= 8;
    }
    if (len >= 4) {
        h ^= (uint64_t)xxh64_read32(p) * XXH_PRIME64_1;
        h = xxh64_rotl(h, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
        len -= 4;
    }
    while (len > 0) {
        h ^= (uint64_t)(*p) * XXH_PRIME64_5;
        h = xxh64_rotl(h, 11) * XXH_PRIME64_1;
        p++;
        len--;
    }

    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    h ^= h >> 32;

    {
        int i;
        /* big-endian serialization so the hex matches the canonical uint64 value */
        for (i = 0; i < 8; ++i)
            ctx->result[i] = (uint8_t)(h >> (8 * (7 - i)));
    }
}

#endif /* __XXHASH64_H__ */