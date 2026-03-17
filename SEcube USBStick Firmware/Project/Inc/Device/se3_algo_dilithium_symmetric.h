/**
 ******************************************************************************
 * File Name          : se3_algo_dilithium_symmetric.h
 * Description        : Primitive Simmetriche (SHAKE) specifiche per ML-DSA
 * Version            : 1.1 - Coerente con API ML-DSA-44/65/87
 ******************************************************************************
 */

#pragma once

#include "se3_algo_dilithium_params.h"
#include "Keccak.h"
#include <stddef.h>

/* --- Tipi di stato basati sulla struttura Keccak del core --- */
typedef keccak_state se3_shake128_ctx;
typedef keccak_state se3_shake256_ctx;

/* ========================================================================== *
 * NIST COMPATIBILITY BRIDGE
 * Mappa le vecchie chiamate NIST sulle nostre nuove funzioni SEcube
 * ========================================================================== */
#define stream128_state         se3_shake128_ctx
#define stream256_state         se3_shake256_ctx

#define stream128_init          se3_mldsa_shake128_init
#define stream128_squeezeblocks se3_mldsa_shake128_squeeze
#define stream256_init          se3_mldsa_shake256_init
#define stream256_squeezeblocks se3_mldsa_shake256_squeeze

/* ========================================================================== *
 * API STREAM 128 (Usata principalmente per espandere la matrice A)
 * ========================================================================== */

/**
 * @brief Inizializza lo stream SHAKE128 con seed e nonce (rho)
 */
void se3_mldsa_shake128_init(
    se3_shake128_ctx *state,
    const uint8_t seed[DIL_SEEDBYTES],
    uint16_t nonce);

/**
 * @brief Estrae blocchi dallo stream SHAKE128
 */
void se3_mldsa_shake128_squeeze(
    uint8_t *out,
    size_t outblocks,
    se3_shake128_ctx *state);


/* ========================================================================== *
 * API STREAM 256 (Usata per CRH e espansione vettori mascherati)
 * ========================================================================== */

/**
 * @brief Inizializza lo stream SHAKE256 con seed lungo e nonce
 */
void se3_mldsa_shake256_init(
    se3_shake256_ctx *state,
    const uint8_t seed[DIL_CRHBYTES],
    uint16_t nonce);

/**
 * @brief Estrae blocchi dallo stream SHAKE256
 */
void se3_mldsa_shake256_squeeze(
    uint8_t *out,
    size_t outblocks,
    se3_shake256_ctx *state);

/* ========================================================================== *
 * HELPER MACROS - Mappatura per compatibilità con i vari livelli
 * ========================================================================== */

// Queste macro permettono alle funzioni interne di ML-DSA-44/65/87
// di chiamare le primitive corrette in base alla necessità dello standard.

#define MLDSA_ABSORB_RHO(ctx, rho, nonce)  se3_mldsa_shake128_init(ctx, rho, nonce)
#define MLDSA_ABSORB_CRH(ctx, crh, nonce)  se3_mldsa_shake256_init(ctx, crh, nonce)
