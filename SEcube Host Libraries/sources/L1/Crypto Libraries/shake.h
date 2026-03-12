/**
******************************************************************************
  * File Name          : shake.h
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : Header SHAKE128/256 (XOF) ottimizzato per Host PC (64-bit).
  ******************************************************************************
  */

#ifndef SHAKE_HOST_H
#define SHAKE_HOST_H

#include <stddef.h>
#include <stdint.h>
#include "Keccak.h" // Include il motore 64-bit dell'Host

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

/* Struttura di contesto per l'Host:
 * Comoda da istanziare nel C++ senza preoccuparsi dei limiti di RAM */
typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

/* =========================================================
 * API SHAKE128
 * ========================================================= */
void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

/* =========================================================
 * API SHAKE256
 * ========================================================= */
void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);

#endif /* SHAKE_HOST_H */