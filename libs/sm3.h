/* SM3 cryptographic hash function (GB/T 32905-2016), 256-bit digest.
 * Header-only pure C implementation.
 */
#ifndef __SM3_H__
#define __SM3_H__

#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t state[8];
    uint64_t totalLen;      /* bytes processed, tracked for the 64-bit length in padding */
    uint8_t  buffer[64];
    uint32_t bufferLen;
    uint8_t  result[32];
} SM3_CTX, *PSM3_CTX;

static uint32_t sm3_rol32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm3_p0(uint32_t x) {
    return x ^ sm3_rol32(x, 9) ^ sm3_rol32(x, 17);
}

static uint32_t sm3_p1(uint32_t x) {
    return x ^ sm3_rol32(x, 15) ^ sm3_rol32(x, 23);
}

static void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68], Wp[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2, Tj;
    int j;

    for (j = 0; j < 16; ++j) {
        W[j] = ((uint32_t)block[j * 4] << 24) |
               ((uint32_t)block[j * 4 + 1] << 16) |
               ((uint32_t)block[j * 4 + 2] << 8) |
               ((uint32_t)block[j * 4 + 3]);
    }
    for (j = 16; j < 68; ++j) {
        W[j] = sm3_p1(W[j - 16] ^ W[j - 9] ^ sm3_rol32(W[j - 3], 15)) ^
               sm3_rol32(W[j - 13], 7) ^ W[j - 6];
    }
    for (j = 0; j < 64; ++j) {
        Wp[j] = W[j] ^ W[j + 4];
    }

    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (j = 0; j < 64; ++j) {
        uint32_t FF, GG;
        Tj = (j < 16) ? 0x79cc4519u : 0x7a879d8au;
        SS1 = sm3_rol32(sm3_rol32(A, 12) + E + sm3_rol32(Tj, (uint32_t)(j % 32)), 7);
        SS2 = SS1 ^ sm3_rol32(A, 12);
        FF = (j < 16) ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C));
        GG = (j < 16) ? (E ^ F ^ G) : ((E & F) | ((~E) & G));
        TT1 = FF + D + SS2 + Wp[j];
        TT2 = GG + H + SS1 + W[j];
        D = C;
        C = sm3_rol32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = sm3_rol32(F, 19);
        F = E;
        E = sm3_p0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

static void SM3Init(PSM3_CTX ctx) {
    ctx->state[0] = 0x7380166fu;
    ctx->state[1] = 0x4914b2b9u;
    ctx->state[2] = 0x172442d7u;
    ctx->state[3] = 0xda8a0600u;
    ctx->state[4] = 0xa96f30bcu;
    ctx->state[5] = 0x163138aau;
    ctx->state[6] = 0xe38dee4du;
    ctx->state[7] = 0xb0fb0e4eu;
    ctx->totalLen = 0;
    ctx->bufferLen = 0;
}

static void SM3Update(PSM3_CTX ctx, const uint8_t* data, uint32_t len) {
    ctx->totalLen += len;
    while (len > 0) {
        uint32_t n = 64 - ctx->bufferLen;
        if (n > len) n = len;
        memcpy(ctx->buffer + ctx->bufferLen, data, n);
        ctx->bufferLen += n;
        data += n;
        len -= n;
        if (ctx->bufferLen == 64) {
            sm3_compress(ctx->state, ctx->buffer);
            ctx->bufferLen = 0;
        }
    }
}

static void SM3Final(PSM3_CTX ctx) {
    uint64_t bitLen = ctx->totalLen << 3;
    uint8_t pad = 0x80;

    SM3Update(ctx, &pad, 1);

    /* bufferLen here is < 64; append zeros up to position 56 */
    {
        uint8_t zero = 0;
        while (ctx->bufferLen != 56) {
            SM3Update(ctx, &zero, 1);
        }
    }

    /* append the 64-bit message length, big-endian */
    {
        uint8_t lenbuf[8];
        int i;
        for (i = 0; i < 8; ++i) {
            lenbuf[i] = (uint8_t)(bitLen >> (56 - i * 8));
        }
        SM3Update(ctx, lenbuf, 8);
    }

    /* the final block was just compressed; write out the result */
    {
        int i;
        for (i = 0; i < 8; ++i) {
            ctx->result[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
            ctx->result[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
            ctx->result[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
            ctx->result[i * 4 + 3] = (uint8_t)(ctx->state[i]);
        }
    }
}

#endif /* __SM3_H__ */