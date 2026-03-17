/**
 *=============================================================================
 * File Name          : se3_algo_dilithium_params.h
 * Description        : Parametri per ML-DSA (Dilithium) - Versione Dinamica Ottimizzata
 *=============================================================================
 */

#ifndef SE3_ALGO_DILITHIUM_PARAMS_H
#define SE3_ALGO_DILITHIUM_PARAMS_H

#include <stdint.h>

/* ========================================================================= *
 * Parametri Matematici Globali (Fissi per tutti i livelli)
 * ========================================================================= */
#define DIL_SEEDBYTES 32
#define DIL_CRHBYTES 64
#define DIL_TRBYTES 64
#define DIL_RNDBYTES 32
#define DIL_N 256
#define DIL_Q 8380417
#define DIL_QINV 58728449
#define DIL_D 13
#define DIL_ROOT_OF_UNITY 1753

/* ========================================================================= *
 * Parametri per le primitive simmetriche (SHAKE128/256)
 * ========================================================================= */
#define DIL_STREAM128_BLOCKBYTES 168
#define DIL_STREAM256_BLOCKBYTES 136

#define POLY_UNIFORM_NBLOCKS 5
#define POLY_UNIFORM_BYTES (POLY_UNIFORM_NBLOCKS * DIL_STREAM128_BLOCKBYTES)

/* ========================================================================= *
 * Dimensioni fisse per l'imballaggio (Packing)
 * ========================================================================= */
#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416

/* ========================================================================= *
 * MASSIMALI PER ALLOCAZIONE RAM
 * Gestione dinamica: se compili solo per L2, risparmi molta RAM.
 * ========================================================================= */
#ifdef SE3_DILITHIUM_ONLY_L2
    // Profilo Memory-Saving (Solo ML-DSA-44)
    #define DIL_K_MAX 4
    #define DIL_L_MAX 4
    #define DIL_OMEGA_MAX 80
    #define DIL_CTILDE_MAX 32

    #define DIL_POLYZ_PACKEDBYTES_MAX 576
    #define DIL_POLYW1_PACKEDBYTES_MAX 192
    #define DIL_POLYETA_PACKEDBYTES_MAX 96
#else
    // Profilo Universale (Caso peggiore: Livello 5 o misto)
    #define DIL_K_MAX 8
    #define DIL_L_MAX 7
    #define DIL_OMEGA_MAX 80
    #define DIL_CTILDE_MAX 64

    #define DIL_POLYZ_PACKEDBYTES_MAX 640
    #define DIL_POLYW1_PACKEDBYTES_MAX 192
    #define DIL_POLYETA_PACKEDBYTES_MAX 128
#endif

#define POLYVECH_PACKEDBYTES_MAX (DIL_OMEGA_MAX + DIL_K_MAX)

/* ========================================================================= *
 * STRUTTURA DINAMICA DEL PROFILO (Ottimizzata per Allineamento in RAM)
 * Ordinata dal tipo più grande al più piccolo per evitare il padding.
 * ========================================================================= */
typedef struct {
    // 32-bit (12 bytes)
    uint32_t beta;
    uint32_t gamma1;
    uint32_t gamma2;

    // 16-bit (16 bytes)
    uint16_t ctildebytes;
    uint16_t polyz_packed;
    uint16_t polyw1_packed;
    uint16_t polyeta_packed;
    uint16_t polyvech_packed;
    uint16_t pk_bytes;
    uint16_t sk_bytes;
    uint16_t sig_bytes;

    // 8-bit (7 bytes)
    uint8_t mode;
    uint8_t k;
    uint8_t l;
    uint8_t eta;
    uint8_t tau;
    uint8_t omega;
    uint8_t poly_gamma1_nblocks;
} dilithium_conf_t;

/* ========================================================================= *
 * ISTANZE DEI PROFILI (Definite in un file .c separato per salvare Flash)
 * ========================================================================= */
extern const dilithium_conf_t SE3_DILITHIUM_L2;
extern const dilithium_conf_t SE3_DILITHIUM_L3;
extern const dilithium_conf_t SE3_DILITHIUM_L5;

#endif // SE3_ALGO_DILITHIUM_PARAMS_H