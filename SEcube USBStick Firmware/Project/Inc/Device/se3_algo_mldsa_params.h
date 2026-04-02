/**
 *=============================================================================
 * File Name          : se3_algo_dilithium_params.h
 * Description        : Parametri ML-DSA (FIPS 204) - Versione Completa
 *=============================================================================
 */

#ifndef SE3_ALGO_DILITHIUM_PARAMS_H
#define SE3_ALGO_DILITHIUM_PARAMS_H

#include <stdint.h>

/* ========================================================================= *
 * Parametri Matematici Globali (FIPS 204 Standard)
 * ========================================================================= */
#define DIL_N            256
#define DIL_Q            8380417
#define DIL_QINV         58728449
#define DIL_ROOT_OF_UNITY 1753
#define DIL_D            13
#define DIL_SEEDBYTES    32
#define DIL_CRHBYTES     64
#define DIL_TRBYTES      64
#define DIL_RNDBYTES     32

/* Parametri per SHAKE (Primitive simmetriche) */
#define DIL_SHAKE128_RATE 168
#define DIL_SHAKE256_RATE 136

/* Dimensioni fisse per il packing dei polinomi (t1 e t0) */
#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416

/* Alias richiesti da se3_arith_poly.c */
#define DIL_STREAM128_BLOCKBYTES DIL_SHAKE128_RATE
#define DIL_STREAM256_BLOCKBYTES DIL_SHAKE256_RATE

/* Costanti per il campionamento uniforme dei polinomi */
#define POLY_UNIFORM_NBLOCKS 5
#define POLY_UNIFORM_BYTES (POLY_UNIFORM_NBLOCKS * DIL_STREAM128_BLOCKBYTES)

/* ========================================================================= *
 * MASSIMALI DI ALLOCAZIONE (Basati sul Livello 5 - Sicurezza Massima)
 * Utilizzati per definire la dimensione dei buffer interni nel dispatcher.
 * ========================================================================= */
#define DIL_K_MAX                    8
#define DIL_L_MAX                    7
#define DIL_OMEGA_MAX                80
#define DIL_CTILDE_MAX               64
#define DIL_POLYZ_PACKEDBYTES_MAX    640
#define DIL_POLYW1_PACKEDBYTES_MAX   192
#define DIL_POLYETA_PACKEDBYTES_MAX  128
#define POLYVECH_PACKEDBYTES_MAX     (DIL_OMEGA_MAX + DIL_K_MAX)

/* Dimensioni massime assolute per l'interfaccia esterna */
#define ML_DSA_MAX_PK_SIZE   2592
#define ML_DSA_MAX_SK_SIZE   4896
#define ML_DSA_MAX_SIG_SIZE  4627

#define DIL_SIGBYTES_MAX 4627  /* ML-DSA-87 (Livello 5) */

/* ========================================================================= *
 * STRUTTURA DINAMICA DEL PROFILO
 * Ordinata per minimizzare il padding sulla memoria del Cortex-M4.
 * ========================================================================= */
typedef struct {
    /* 32-bit (Parametri di soglia) */
    uint32_t gamma1;
    uint32_t gamma2;
    uint32_t beta;

    /* 16-bit (Dimensioni dei dati impaccati) */
    uint16_t ctildebytes;
    uint16_t polyz_packed;
    uint16_t polyw1_packed;
    uint16_t polyeta_packed;
    uint16_t polyvech_packed;
    uint16_t pk_bytes;
    uint16_t sk_bytes;
    uint16_t sig_bytes;

    /* 8-bit (Parametri strutturali del reticolo) */
    uint8_t mode;
    uint8_t k;
    uint8_t l;
    uint8_t eta;
    uint8_t tau;
    uint8_t omega;
    uint8_t poly_gamma1_nblocks;
} dilithium_conf_t;

/* ========================================================================= *
 * ISTANZE DEI PROFILI (FIPS 204 Compliant)
 * Definite come static const per l'integrazione Header-Only.
 * ========================================================================= *
 *
 * Riferimento: FIPS 204, Table 1
 *
 *  Livello | k | l | eta | tau | gamma1  | gamma2        | omega | ctilde
 *  --------+---+---+-----+-----+---------+---------------+-------+-------
 *  ML-DSA-44 | 4 | 4 |  2 |  39 | 2^17    | (Q-1)/88=95232|  80   |  32
 *  ML-DSA-65 | 6 | 5 |  4 |  49 | 2^19    | (Q-1)/32=261888|  55  |  48
 *  ML-DSA-87 | 8 | 7 |  2 |  60 | 2^19    | (Q-1)/32=261888|  75  |  64
 *
 * ========================================================================= */

/**
 * ML-DSA-44 (Livello 2)
 *   gamma1 = 2^17 = 131072
 *   gamma2 = (Q-1)/88 = 95232
 *   beta   = tau * eta = 39 * 2 = 78
 *   polyw1_packed: con gamma2=(Q-1)/88, w1 ∈ [0,43] → 6 bit/coeff → 192 byte
 *   polyz_packed:  con gamma1=2^17,    z  ha 18 bit/coeff → 576 byte
 */
static const dilithium_conf_t SE3_DILITHIUM_L2 = {
    .gamma1          = 131072,
    .gamma2          = 95232,
    .beta            = 78,
    .ctildebytes     = 32,
    .polyz_packed    = 576,
    .polyw1_packed   = 192,   /* FIX: era 128, corretto per gamma2=(Q-1)/88 */
    .polyeta_packed  = 96,
    .polyvech_packed = 84,
    .pk_bytes        = 1312,
    .sk_bytes        = 2560,
    .sig_bytes       = 2420,
    .mode            = 2,
    .k               = 4,
    .l               = 4,
    .eta             = 2,
    .tau             = 39,
    .omega           = 80,
    .poly_gamma1_nblocks = 2
};

/**
 * ML-DSA-65 (Livello 3)
 *   gamma1 = 2^19 = 524288            ← era 524288 ✓ (corretto)
 *   gamma2 = (Q-1)/32 = 261888        ← era 261888 ✓ (corretto)
 *   beta   = tau * eta = 49 * 4 = 196 ← era 196    ✓ (corretto)
 *
 *   FIX: polyw1_packed
 *     con gamma2=(Q-1)/32, w1 ∈ [0,15] → 4 bit/coeff → 128 byte  ✓
 *     (il valore 128 era quindi corretto per L3/L5, non per L2)
 *
 *   FIX: polyvech_packed = omega + k = 55 + 6 = 61  ✓
 */
static const dilithium_conf_t SE3_DILITHIUM_L3 = {
    .gamma1          = 524288,
    .gamma2          = 261888,
    .beta            = 196,
    .ctildebytes     = 48,
    .polyz_packed    = 640,
    .polyw1_packed   = 128,
    .polyeta_packed  = 128,
    .polyvech_packed = 61,
    .pk_bytes        = 1952,
    .sk_bytes        = 4032,
    .sig_bytes       = 3309,
    .mode            = 3,
    .k               = 6,
    .l               = 5,
    .eta             = 4,
    .tau             = 49,
    .omega           = 55,
    .poly_gamma1_nblocks = 4
};

/**
 * ML-DSA-87 (Livello 5)
 *   gamma1 = 2^19 = 524288
 *   gamma2 = (Q-1)/32 = 261888
 *   beta   = tau * eta = 60 * 2 = 120
 */
static const dilithium_conf_t SE3_DILITHIUM_L5 = {
    .gamma1          = 524288,
    .gamma2          = 261888,
    .beta            = 120,
    .ctildebytes     = 64,
    .polyz_packed    = 640,
    .polyw1_packed   = 128,
    .polyeta_packed  = 96,
    .polyvech_packed = 83,
    .pk_bytes        = 2592,
    .sk_bytes        = 4896,
    .sig_bytes       = 4627,
    .mode            = 5,
    .k               = 8,
    .l               = 7,
    .eta             = 2,
    .tau             = 60,
    .omega           = 75,
    .poly_gamma1_nblocks = 4
};

#endif /* SE3_ALGO_DILITHIUM_PARAMS_H */
