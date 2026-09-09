/* RIPEMD-160 hash function (160-bit digest), pure C implementation.
 * Header-only. Ported from the public-domain pycrypto implementation,
 * which follows the RIPEMD-160 specification (Dobbertin, Bosselaers, Preneel).
 */
#ifndef __RIPEMD160_H__
#define __RIPEMD160_H__

#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t h[5];
    uint64_t len;          /* total bits processed */
    uint8_t  buf[64];
    uint32_t buf_len;
    uint8_t  result[20];
} ripemd160_ctx;

#define RMD_ROL(s, n) (((n) << (s)) | ((n) >> (32 - (s))))

#define RMD_F1(x, y, z) ((x) ^ (y) ^ (z))
#define RMD_F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD_F3(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD_F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RMD_F5(x, y, z) ((x) ^ ((y) | ~(z)))

/* message-word ordering, left/right lines */
static const uint8_t rmd_RL[5][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 },
    { 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12 },
    { 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2 },
    { 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 }
};
static const uint8_t rmd_RR[5][16] = {
    { 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12 },
    { 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2 },
    { 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13 },
    { 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14 },
    { 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 }
};
static const uint8_t rmd_SL[5][16] = {
    { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 },
    { 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 },
    { 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 },
    { 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 },
    { 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 }
};
static const uint8_t rmd_SR[5][16] = {
    { 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 },
    { 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 },
    { 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 },
    { 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 },
    { 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 }
};
static const uint32_t rmd_KL[5] = {
    0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu
};
static const uint32_t rmd_KR[5] = {
    0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u
};

static void ripemd160_compress(uint32_t h[5], const uint8_t block[64]) {
    uint32_t X[16];
    uint32_t AL, BL, CL, DL, EL;
    uint32_t AR, BR, CR, DR, ER;
    uint32_t T;
    int r, w;

    for (w = 0; w < 16; ++w)
        X[w] = (uint32_t)block[w*4] | ((uint32_t)block[w*4+1] << 8) |
               ((uint32_t)block[w*4+2] << 16) | ((uint32_t)block[w*4+3] << 24);

    AL = AR = h[0];
    BL = BR = h[1];
    CL = CR = h[2];
    DL = DR = h[3];
    EL = ER = h[4];

    /* Round 0..4; left line uses F1..F5, right line uses F5,F4,F3,F2,F1 */
    for (r = 0; r < 5; ++r) {
        for (w = 0; w < 16; ++w) {
            switch (r) {
                case 0:
                    T = RMD_ROL(rmd_SL[r][w], AL + RMD_F1(BL, CL, DL) + X[rmd_RL[r][w]] + rmd_KL[r]) + EL;
                    AL = EL; EL = DL; DL = RMD_ROL(10, CL); CL = BL; BL = T;
                    T = RMD_ROL(rmd_SR[r][w], AR + RMD_F5(BR, CR, DR) + X[rmd_RR[r][w]] + rmd_KR[r]) + ER;
                    AR = ER; ER = DR; DR = RMD_ROL(10, CR); CR = BR; BR = T;
                    break;
                case 1:
                    T = RMD_ROL(rmd_SL[r][w], AL + RMD_F2(BL, CL, DL) + X[rmd_RL[r][w]] + rmd_KL[r]) + EL;
                    AL = EL; EL = DL; DL = RMD_ROL(10, CL); CL = BL; BL = T;
                    T = RMD_ROL(rmd_SR[r][w], AR + RMD_F4(BR, CR, DR) + X[rmd_RR[r][w]] + rmd_KR[r]) + ER;
                    AR = ER; ER = DR; DR = RMD_ROL(10, CR); CR = BR; BR = T;
                    break;
                case 2:
                    T = RMD_ROL(rmd_SL[r][w], AL + RMD_F3(BL, CL, DL) + X[rmd_RL[r][w]] + rmd_KL[r]) + EL;
                    AL = EL; EL = DL; DL = RMD_ROL(10, CL); CL = BL; BL = T;
                    T = RMD_ROL(rmd_SR[r][w], AR + RMD_F3(BR, CR, DR) + X[rmd_RR[r][w]] + rmd_KR[r]) + ER;
                    AR = ER; ER = DR; DR = RMD_ROL(10, CR); CR = BR; BR = T;
                    break;
                case 3:
                    T = RMD_ROL(rmd_SL[r][w], AL + RMD_F4(BL, CL, DL) + X[rmd_RL[r][w]] + rmd_KL[r]) + EL;
                    AL = EL; EL = DL; DL = RMD_ROL(10, CL); CL = BL; BL = T;
                    T = RMD_ROL(rmd_SR[r][w], AR + RMD_F2(BR, CR, DR) + X[rmd_RR[r][w]] + rmd_KR[r]) + ER;
                    AR = ER; ER = DR; DR = RMD_ROL(10, CR); CR = BR; BR = T;
                    break;
                default:
                    T = RMD_ROL(rmd_SL[r][w], AL + RMD_F5(BL, CL, DL) + X[rmd_RL[r][w]] + rmd_KL[r]) + EL;
                    AL = EL; EL = DL; DL = RMD_ROL(10, CL); CL = BL; BL = T;
                    T = RMD_ROL(rmd_SR[r][w], AR + RMD_F1(BR, CR, DR) + X[rmd_RR[r][w]] + rmd_KR[r]) + ER;
                    AR = ER; ER = DR; DR = RMD_ROL(10, CR); CR = BR; BR = T;
                    break;
            }
        }
    }

    /* final mixing */
    T = h[1] + CL + DR;
    h[1] = h[2] + DL + ER;
    h[2] = h[3] + EL + AR;
    h[3] = h[4] + AL + BR;
    h[4] = h[0] + BL + CR;
    h[0] = T;
}

static void ripemd160_init(ripemd160_ctx* ctx) {
    ctx->h[0] = 0x67452301UL;
    ctx->h[1] = 0xEFCDAB89UL;
    ctx->h[2] = 0x98BADCFEUL;
    ctx->h[3] = 0x10325476UL;
    ctx->h[4] = 0xC3D2E1F0UL;
    ctx->len = 0;
    ctx->buf_len = 0;
}

static void ripemd160_update(ripemd160_ctx* ctx, const uint8_t* data, uint32_t len) {
    while (len > 0) {
        uint32_t n = 64 - ctx->buf_len;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->buf_len, data, n);
        ctx->buf_len += n;
        ctx->len += (uint64_t)n << 3;   /* bits */
        data += n;
        len -= n;
        if (ctx->buf_len == 64) {
            ripemd160_compress(ctx->h, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void ripemd160_final(ripemd160_ctx* ctx) {
    uint32_t w14, w15;
    int i;

    /* padding: 0x80, zeros, then 64-bit little-endian bit length */
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
        ripemd160_compress(ctx->h, ctx->buf);
        ctx->buf_len = 0;
    }
    memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);

    w14 = (uint32_t)(ctx->len & 0xFFFFFFFFu);
    w15 = (uint32_t)(ctx->len >> 32);
    ctx->buf[56] = (uint8_t)w14;
    ctx->buf[57] = (uint8_t)(w14 >> 8);
    ctx->buf[58] = (uint8_t)(w14 >> 16);
    ctx->buf[59] = (uint8_t)(w14 >> 24);
    ctx->buf[60] = (uint8_t)w15;
    ctx->buf[61] = (uint8_t)(w15 >> 8);
    ctx->buf[62] = (uint8_t)(w15 >> 16);
    ctx->buf[63] = (uint8_t)(w15 >> 24);
    ripemd160_compress(ctx->h, ctx->buf);

    for (i = 0; i < 5; ++i) {
        ctx->result[i*4]     = (uint8_t)ctx->h[i];
        ctx->result[i*4 + 1] = (uint8_t)(ctx->h[i] >> 8);
        ctx->result[i*4 + 2] = (uint8_t)(ctx->h[i] >> 16);
        ctx->result[i*4 + 3] = (uint8_t)(ctx->h[i] >> 24);
    }
}

#endif /* __RIPEMD160_H__ */