/**
  ******************************************************************************
  * File Name          : Keccak.h
  * Author             : Adriano d'Alessandro <adrianodalessandro@yahoo.it>
  * Date               : 2026
  * Description        : Keccak (SHA-3) core definitions per SEcube (Cortex-M4).
  ******************************************************************************
  *
  * Copyright (c) 2026 Adriano d'Alessandro. Tutti i diritti riservati.
  *
  * Dettagli tecnici:
  * Header ottimizzato esclusivamente per sistemi embedded a 32-bit.
  * Implementa macro sicure per l'accesso in memoria (prevenzione HardFault)
  * e rotazioni a 64-bit emulate su registri a 32-bit per massimizzare
  * le performance sul target ARM Cortex-M4 del SEcube.
  *
  ******************************************************************************
  */

#include <stdint.h>  // Per uint64_t, uint8_t, uint32_t
#include <stddef.h>  // Per size_t
#include <string.h>  // Per memcpy

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

void keccak_init(keccak_state *state);


__attribute__((always_inline)) static inline uint64_t load64(const uint8_t *x) {
    uint64_t r;
    memcpy(&r, x, sizeof(uint64_t));
    return r;
}

__attribute__((always_inline)) static inline void store64(uint8_t *x, uint64_t u) {
    memcpy(x, &u, sizeof(uint64_t));
}


__attribute__((always_inline)) static inline uint64_t ROL64(uint64_t a, int offset) {
    if (offset == 0) return a;
    uint32_t hi = (uint32_t)(a >> 32);
    uint32_t lo = (uint32_t)(a);
    uint32_t r_hi, r_lo;

    if (offset < 32) {
        r_hi = (hi << offset) | (lo >> (32 - offset));
        r_lo = (lo << offset) | (hi >> (32 - offset));
    } else if (offset == 32) {
        r_hi = lo;
        r_lo = hi;
    } else {
        int n = offset - 32;
        r_hi = (lo << n) | (hi >> (32 - n));
        r_lo = (hi << n) | (lo >> (32 - n));
    }
    return (((uint64_t)r_hi) << 32) | r_lo;
}


void KeccakF1600_StatePermute(uint64_t state[25]);
void keccak_absorb_once(uint64_t s[25], unsigned int r, const uint8_t *in, size_t inlen, uint8_t p);
unsigned int keccak_absorb(uint64_t s[25], unsigned int pos, unsigned int r, const uint8_t *in, size_t inlen);
void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p);
unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25], unsigned int pos, unsigned int r);
void keccak_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t s[25], unsigned int r);
