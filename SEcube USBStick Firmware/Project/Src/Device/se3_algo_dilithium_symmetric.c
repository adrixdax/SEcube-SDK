/**
 *=============================================================================
 * File Name          : se3_algo_dilithium_symmetric.c
 * Description        : Implementazione primitive SHAKE per ML-DSA
 *=============================================================================
 */

#include "se3_algo_dilithium_symmetric.h"
#include "shake.h" // Presumo sia l'header interno del core Keccak

/* ========================================================================== *
 * IMPLEMENTAZIONE SHAKE128
 * ========================================================================== */

/**
 * Inizializza SHAKE128 assorbendo il seed e il nonce (usato per espandere A)
 */
void se3_mldsa_shake128_init(se3_shake128_ctx *state, const uint8_t seed[DIL_SEEDBYTES], uint16_t nonce) {
    uint8_t t[DIL_SEEDBYTES + 2];

    // Copia del seed
    for (int i = 0; i < DIL_SEEDBYTES; i++) {
        t[i] = seed[i];
    }

    // Append del nonce in formato Little-Endian
    t[DIL_SEEDBYTES + 0] = (uint8_t)(nonce & 0xFF);
    t[DIL_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    shake128_init(state);
    shake128_absorb(state, t, DIL_SEEDBYTES + 2);
    shake128_finalize(state);
}

/**
 * Estrae blocchi interi di dati dalla spugna SHAKE128
 */
void se3_mldsa_shake128_squeeze(uint8_t *out, size_t outblocks, se3_shake128_ctx *state) {
    // Il rate di SHAKE128 è gestito tramite macro centralizzata
    shake128_squeeze(out, outblocks * DIL_STREAM128_BLOCKBYTES, state);
}

/* ========================================================================== *
 * IMPLEMENTAZIONE SHAKE256
 * ========================================================================== */

/**
 * Inizializza SHAKE256 assorbendo il seed e il nonce (usato per i vettori d'errore)
 */
void se3_mldsa_shake256_init(se3_shake256_ctx *state, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce) {
    uint8_t t[DIL_CRHBYTES + 2];

    for (int i = 0; i < DIL_CRHBYTES; i++) {
        t[i] = seed[i];
    }

    t[DIL_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    t[DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256_init(state);
    shake256_absorb(state, t, DIL_CRHBYTES + 2);
    shake256_finalize(state);
}

/**
 * Estrae blocchi interi di dati dalla spugna SHAKE256
 */
void se3_mldsa_shake256_squeeze(uint8_t *out, size_t outblocks, se3_shake256_ctx *state) {
    // Il rate di SHAKE256 è gestito tramite macro centralizzata
    shake256_squeeze(out, outblocks * DIL_STREAM256_BLOCKBYTES, state);
}