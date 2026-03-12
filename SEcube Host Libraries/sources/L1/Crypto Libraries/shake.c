/**
  ******************************************************************************
  * File Name          : shake.c
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : Implementazione SHAKE per Host PC (Dilithium Ready).
  ******************************************************************************
  *
  * Dettagli:
  * A differenza del firmware, qui privilegiamo la velocità pura per
  * la verifica delle firme e l'espansione dei polinomi su CPU moderne.
  * Il padding 0x1F separa il dominio da SHA-3 standard.
  *
  ******************************************************************************
  */

#include "shake.h"
#include <string.h>

/* =========================================================
 * SHAKE128
 * ========================================================= */

void shake128_init(keccak_state *state) {
    memset(state, 0, sizeof(keccak_state));
}

void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen) {
    // Chiama il motore 64-bit
    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

void shake128_finalize(keccak_state *state) {
    // Padding SHAKE (0x1F)
    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);

    // Forziamo pos = RATE. Così al primo squeeze, Keccak farà
    // scattare subito una permutazione dello stato!
    state->pos = 0;
}

void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state) {
    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
}

/* =========================================================
 * SHAKE256
 * ========================================================= */

void shake256_init(keccak_state *state) {
    memset(state, 0, sizeof(keccak_state));
}

void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen) {
    state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}

void shake256_finalize(keccak_state *state) {
    keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = 0;
}

void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state) {
    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}