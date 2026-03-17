/**
 *=============================================================================
 * File Name          : se3_algo_dilithium_params.c
 * Description        : Istanziazione in memoria Flash dei profili ML-DSA
 *=============================================================================
 */

#include "se3_algo_dilithium_params.h"

/* ========================================================================= *
 * PROFILO LIVELLO 2 (ML-DSA-44 / Equivalente AES-128)
 * Ottimizzato per performance sui microcontrollori
 * ========================================================================= */
const dilithium_conf_t SE3_DILITHIUM_L2 = {
    // 32-bit
    .beta = 78,
    .gamma1 = (1 << 17),
    .gamma2 = (DIL_Q - 1) / 88,

    // 16-bit
    .ctildebytes = 32,
    .polyz_packed = 576,
    .polyw1_packed = 192,
    .polyeta_packed = 96,
    .polyvech_packed = 80 + 4, // OMEGA + K
    .pk_bytes = 1312,
    .sk_bytes = 2528,
    .sig_bytes = 2420,

    // 8-bit
    .mode = 2,
    .k = 4,
    .l = 4,
    .eta = 2,
    .tau = 39,
    .omega = 80,
    .poly_gamma1_nblocks = 5
};

/* ========================================================================= *
 * PROFILO LIVELLO 3 (ML-DSA-65 / Equivalente AES-192)
 * ========================================================================= */
const dilithium_conf_t SE3_DILITHIUM_L3 = {
    // 32-bit
    .beta = 196,
    .gamma1 = (1 << 19),
    .gamma2 = (DIL_Q - 1) / 32,

    // 16-bit
    .ctildebytes = 48,
    .polyz_packed = 640,
    .polyw1_packed = 128,
    .polyeta_packed = 128,
    .polyvech_packed = 55 + 6, // OMEGA + K
    .pk_bytes = 1952,
    .sk_bytes = 4000,
    .sig_bytes = 3309,

    // 8-bit
    .mode = 3,
    .k = 6,
    .l = 5,
    .eta = 4,
    .tau = 49,
    .omega = 55,
    .poly_gamma1_nblocks = 6
};

/* ========================================================================= *
 * PROFILO LIVELLO 5 (ML-DSA-87 / Equivalente AES-256)
 * Massima sicurezza, massimo consumo di risorse
 * ========================================================================= */
const dilithium_conf_t SE3_DILITHIUM_L5 = {
    // 32-bit
    .beta = 120,
    .gamma1 = (1 << 19),
    .gamma2 = (DIL_Q - 1) / 32,

    // 16-bit
    .ctildebytes = 64,
    .polyz_packed = 640,
    .polyw1_packed = 128,
    .polyeta_packed = 96,
    .polyvech_packed = 75 + 8, // OMEGA + K
    .pk_bytes = 2592,
    .sk_bytes = 4864,
    .sig_bytes = 4595,

    // 8-bit
    .mode = 5,
    .k = 8,
    .l = 7,
    .eta = 2,
    .tau = 60,
    .omega = 75,
    .poly_gamma1_nblocks = 6
};