/* BLAKE3 hash function (256-bit output), pure C translation of the official
 * reference implementation (reference_impl.rs). Header-only, single-threaded.
 */
#ifndef __BLAKE3_H__
#define __BLAKE3_H__

#include <stdint.h>
#include <string.h>

#define BLAKE3_OUT_LEN    32
#define BLAKE3_KEY_LEN    32
#define BLAKE3_BLOCK_LEN  64
#define BLAKE3_CHUNK_LEN  1024

#define BLAKE3_CHUNK_START (1 << 0)
#define BLAKE3_CHUNK_END   (1 << 1)
#define BLAKE3_PARENT      (1 << 2)
#define BLAKE3_ROOT        (1 << 3)

static const uint32_t blake3_IV[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

static const uint8_t blake3_msg_permutation[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static uint32_t blake3_rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t blake3_load32(const uint8_t* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void blake3_store32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void blake3_g(uint32_t* state, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = blake3_rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = blake3_rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = blake3_rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = blake3_rotr32(state[b] ^ state[c], 7);
}

static void blake3_round(uint32_t* state, const uint32_t* m) {
    blake3_g(state, 0, 4, 8,  12, m[0],  m[1]);
    blake3_g(state, 1, 5, 9,  13, m[2],  m[3]);
    blake3_g(state, 2, 6, 10, 14, m[4],  m[5]);
    blake3_g(state, 3, 7, 11, 15, m[6],  m[7]);
    blake3_g(state, 0, 5, 10, 15, m[8],  m[9]);
    blake3_g(state, 1, 6, 11, 12, m[10], m[11]);
    blake3_g(state, 2, 7, 8,  13, m[12], m[13]);
    blake3_g(state, 3, 4, 9,  14, m[14], m[15]);
}

static void blake3_permute(uint32_t* m) {
    uint32_t perm[16];
    int i;
    for (i = 0; i < 16; ++i) perm[i] = m[blake3_msg_permutation[i]];
    memcpy(m, perm, sizeof(perm));
}

/* compress; writes the first 8 words (chaining value) into cv. */
static void blake3_compress(uint32_t cv[8], const uint32_t block[16],
                            uint64_t counter, uint32_t block_len, uint32_t flags) {
    uint32_t state[16];
    uint32_t m[16];
    int i, r;

    for (i = 0; i < 8; ++i) state[i] = cv[i];
    for (i = 0; i < 4; ++i) state[i + 8] = blake3_IV[i];
    state[12] = (uint32_t)counter;
    state[13] = (uint32_t)(counter >> 32);
    state[14] = block_len;
    state[15] = flags;

    memcpy(m, block, sizeof(m));

    for (r = 0; r < 7; ++r) {
        blake3_round(state, m);
        blake3_permute(m);
    }

    for (i = 0; i < 8; ++i)
        cv[i] = state[i] ^ state[i + 8];
}

/* Output: a node to be compressed (chunk, parent, or root). */
typedef struct {
    uint32_t cv[8];
    uint32_t block[16];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;
} blake3_output;

static void blake3_output_cv(const blake3_output* o, uint32_t out[8]) {
    uint32_t cv[8];
    int i;
    for (i = 0; i < 8; ++i) cv[i] = o->cv[i];
    blake3_compress(cv, o->block, o->counter, o->block_len, o->flags);
    memcpy(out, cv, 32);
}

typedef struct {
    uint32_t cv[8];        /* chaining value (IV for the hash function) */
    uint64_t chunk_counter;
    uint8_t  block[BLAKE3_BLOCK_LEN];
    uint8_t  block_len;
    uint8_t  blocks_compressed;
} blake3_chunk_state;

static void blake3_chunk_init(blake3_chunk_state* c, uint64_t counter) {
    int i;
    for (i = 0; i < 8; ++i) c->cv[i] = blake3_IV[i];
    c->chunk_counter = counter;
    c->block_len = 0;
    c->blocks_compressed = 0;
}

static uint32_t blake3_chunk_start_flag(const blake3_chunk_state* c) {
    return c->blocks_compressed == 0 ? BLAKE3_CHUNK_START : 0;
}

static uint32_t blake3_chunk_len(const blake3_chunk_state* c) {
    return BLAKE3_BLOCK_LEN * c->blocks_compressed + c->block_len;
}

static void blake3_chunk_update(blake3_chunk_state* c, const uint8_t* input, uint32_t input_len) {
    while (input_len > 0) {
        if (c->block_len == BLAKE3_BLOCK_LEN) {
            uint32_t block[16];
            int i;
            for (i = 0; i < 16; ++i)
                block[i] = blake3_load32(c->block + i * 4);
            blake3_compress(c->cv, block, c->chunk_counter, BLAKE3_BLOCK_LEN,
                            blake3_chunk_start_flag(c));
            c->blocks_compressed++;
            c->block_len = 0;
        }
        {
            uint32_t want = BLAKE3_BLOCK_LEN - c->block_len;
            uint32_t take = want < input_len ? want : input_len;
            memcpy(c->block + c->block_len, input, take);
            c->block_len += (uint8_t)take;
            input += take;
            input_len -= take;
        }
    }
}

static void blake3_chunk_output(const blake3_chunk_state* c, blake3_output* out) {
    int i;
    uint32_t block[16] = {0};
    for (i = 0; i < 16; ++i)
        block[i] = blake3_load32(c->block + i * 4);
    for (i = 0; i < 8; ++i) out->cv[i] = c->cv[i];
    memcpy(out->block, block, sizeof(block));
    out->counter = c->chunk_counter;
    out->block_len = c->block_len;
    out->flags = BLAKE3_CHUNK_END | blake3_chunk_start_flag(c);
}

static void blake3_parent_output(const uint32_t left[8], const uint32_t right[8],
                                 blake3_output* out) {
    int i;
    for (i = 0; i < 8; ++i) out->cv[i] = blake3_IV[i];
    for (i = 0; i < 8; ++i) out->block[i] = left[i];
    for (i = 0; i < 8; ++i) out->block[i + 8] = right[i];
    out->counter = 0;
    out->block_len = BLAKE3_BLOCK_LEN;
    out->flags = BLAKE3_PARENT;
}

typedef struct {
    blake3_chunk_state chunk;
    uint32_t cv_stack[54 * 8];
    uint32_t cv_stack_len;   /* in CVs (8 words each) */
    uint8_t  result[BLAKE3_OUT_LEN];
} blake3_ctx;

static void blake3_push_cv(blake3_ctx* S, const uint32_t cv[8]) {
    memcpy(S->cv_stack + S->cv_stack_len * 8, cv, 32);
    S->cv_stack_len++;
}

static void blake3_pop_cv(blake3_ctx* S, uint32_t cv[8]) {
    S->cv_stack_len--;
    memcpy(cv, S->cv_stack + S->cv_stack_len * 8, 32);
}

static void blake3_add_chunk_cv(blake3_ctx* S, uint32_t* new_cv, uint64_t total_chunks) {
    while ((total_chunks & 1) == 0) {
        uint32_t left[8];
        blake3_output parent;
        blake3_pop_cv(S, left);
        blake3_parent_output(left, new_cv, &parent);
        blake3_output_cv(&parent, new_cv);
        total_chunks >>= 1;
    }
    blake3_push_cv(S, new_cv);
}

static void blake3_init(blake3_ctx* S) {
    memset(S, 0, sizeof(*S));
    blake3_chunk_init(&S->chunk, 0);
    S->cv_stack_len = 0;
}

static void blake3_update(blake3_ctx* S, const uint8_t* data, uint32_t len) {
    while (len > 0) {
        if (blake3_chunk_len(&S->chunk) == BLAKE3_CHUNK_LEN) {
            blake3_output out;
            uint32_t chunk_cv[8];
            uint64_t total_chunks;
            blake3_chunk_output(&S->chunk, &out);
            blake3_output_cv(&out, chunk_cv);
            total_chunks = S->chunk.chunk_counter + 1;
            blake3_add_chunk_cv(S, chunk_cv, total_chunks);
            blake3_chunk_init(&S->chunk, total_chunks);
        }
        {
            uint32_t want = BLAKE3_CHUNK_LEN - blake3_chunk_len(&S->chunk);
            uint32_t take = want < len ? want : len;
            blake3_chunk_update(&S->chunk, data, take);
            data += take;
            len -= take;
        }
    }
}

static void blake3_final(blake3_ctx* S) {
    blake3_output output;
    uint32_t cv[8];
    int i;

    blake3_chunk_output(&S->chunk, &output);
    while (S->cv_stack_len > 0) {
        blake3_output parent;
        uint32_t left[8];
        uint32_t chunk_cv[8];
        blake3_output_cv(&output, chunk_cv);
        blake3_pop_cv(S, left);
        blake3_parent_output(left, chunk_cv, &parent);
        output = parent;
    }

    /* root: same output, plus the ROOT flag, compressed once */
    {
        uint32_t root[8];
        for (i = 0; i < 8; ++i) root[i] = output.cv[i];
        blake3_compress(root, output.block, output.counter, output.block_len,
                        output.flags | BLAKE3_ROOT);
        for (i = 0; i < 8; ++i) cv[i] = root[i];
    }

    for (i = 0; i < 8; ++i)
        blake3_store32(S->result + i * 4, cv[i]);
}

#endif /* __BLAKE3_H__ */