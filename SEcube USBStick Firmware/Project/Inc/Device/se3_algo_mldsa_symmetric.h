/**
 ******************************************************************************
 * File Name          : se3_algo_dilithium_symmetric.h
 * Description        : Primitive Simmetriche (SHAKE) - Versione Header-Only
 ******************************************************************************
 */

#pragma once

#include "se3_algo_mldsa_params.h"
#include "se3_algo_shake.h"
#include <stddef.h>
#include <string.h>

/* --- Tipi di stato --- */
typedef keccak_state se3_shake128_ctx;
typedef keccak_state se3_shake256_ctx;

/* ========================================================================== *
 * IMPLEMENTAZIONE SHAKE128 (Static Inline)
 * ========================================================================== */

/**
 * @brief Inizializza SHAKE128 assorbendo il seed (rho) e il nonce.
 */
static inline void se3_mldsa_shake128_init(
    se3_shake128_ctx *state,
    const uint8_t seed[DIL_SEEDBYTES],
    uint16_t nonce)
{
    uint8_t t[DIL_SEEDBYTES + 2];

    // Copia veloce del seed (rho)
    memcpy(t, seed, DIL_SEEDBYTES);

    // Append del nonce in formato Little-Endian per FIPS 204
    t[DIL_SEEDBYTES + 0] = (uint8_t)(nonce & 0xFF);
    t[DIL_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    shake128_init(state);
    shake128_absorb(state, t, DIL_SEEDBYTES + 2);
    shake128_finalize(state);
}

/**
 * @brief Estrae blocchi dallo stream SHAKE128.
 */
static inline void se3_mldsa_shake128_squeeze(
    uint8_t *out,
    size_t outblocks,
    se3_shake128_ctx *state)
{
    // Utilizza il rate ufficiale definito nei parametri
    shake128_squeeze(out, outblocks * DIL_SHAKE128_RATE, state);
}

/* ========================================================================== *
 * IMPLEMENTAZIONE SHAKE256 (Static Inline)
 * ========================================================================== */

/**
 * @brief Inizializza SHAKE256 per CRH o espansione vettori segreti.
 */
static inline void se3_mldsa_shake256_init(
    se3_shake256_ctx *state,
    const uint8_t seed[DIL_CRHBYTES],
    uint16_t nonce)
{
    uint8_t t[DIL_CRHBYTES + 2];

    memcpy(t, seed, DIL_CRHBYTES);

    t[DIL_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    t[DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256_init(state);
    shake256_absorb(state, t, DIL_CRHBYTES + 2);
    shake256_finalize(state);
}

/**
 * @brief Estrae blocchi dallo stream SHAKE256.
 */
static inline void se3_mldsa_shake256_squeeze(
    uint8_t *out,
    size_t outblocks,
    se3_shake256_ctx *state)
{
    // Utilizza il rate ufficiale per SHAKE256
    shake256_squeeze(out, outblocks * DIL_SHAKE256_RATE, state);
}

/* ========================================================================== *
 * NIST COMPATIBILITY BRIDGE & HELPER MACROS
 * ========================================================================== */
#define stream128_state         se3_shake128_ctx
#define stream256_state         se3_shake256_ctx
#define stream128_init          se3_mldsa_shake128_init
#define stream128_squeezeblocks se3_mldsa_shake128_squeeze
#define stream256_init          se3_mldsa_shake256_init
#define stream256_squeezeblocks se3_mldsa_shake256_squeeze

#define MLDSA_ABSORB_RHO(ctx, rho, nonce)  se3_mldsa_shake128_init(ctx, rho, nonce)
#define MLDSA_ABSORB_CRH(ctx, crh, nonce)  se3_mldsa_shake256_init(ctx, crh, nonce)
