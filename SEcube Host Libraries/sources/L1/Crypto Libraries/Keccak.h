#pragma once

#include <stdint.h>
#include <string.h>

/* --- Ottimizzazioni Host 64-bit --- */
#define ROL64(a, n) ((((a) << (n)) | ((a) >> (64 - (n)))))

static inline uint64_t load64(const uint8_t *x) {
    uint64_t r;
    memcpy(&r, x, sizeof(uint64_t));
    return r;
}

static inline void store64(uint8_t *x, uint64_t u) {
    memcpy(x, &u, sizeof(uint64_t));
}

/* --- Prototipi --- */
void KeccakF1600_StatePermute(uint64_t state[25]);
unsigned int keccak_absorb(uint64_t s[25], unsigned int pos, unsigned int r, const uint8_t *in, size_t inlen);
void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p);
unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25], unsigned int pos, unsigned int r);