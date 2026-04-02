/**
  ******************************************************************************
  * File Name          : se3_arith_packing.h
  * Description        : Funzioni per serializzare e deserializzare chiavi e firme.
  * Adattato per i livelli dinamici ML-DSA.
  ******************************************************************************
  */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "se3_algo_mldsa_params.h"
#include "se3_arith_polyvec.h"

/* ========================================================================== *
 * RNG (Random Number Generator) Wrapper
 * ========================================================================== */
/* Dichiara la funzione di generazione casuale attesa dall'algoritmo */
void randombytes(uint8_t *out, size_t outlen);

/* ========================================================================== *
 * Packing/Unpacking Pubblici (Keys e Signatures)
 * ========================================================================== */

/**
 * @brief Comprime la chiave pubblica (rho + t1) in un array di byte
 */
void pack_pk(uint8_t pk[],
             const uint8_t rho[DIL_SEEDBYTES],
             const polyveck *t1,
             const dilithium_conf_t *conf);

/**
 * @brief Estrae rho e t1 dall'array di byte della chiave pubblica
 */
void unpack_pk(uint8_t rho[DIL_SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[],
               const dilithium_conf_t *conf);

/**
 * @brief Comprime la firma (c + z + h) in un array di byte
 */
void pack_sig(uint8_t sig[],
              const uint8_t c[],
              const polyvecl *z,
              const polyveck *h,
              const dilithium_conf_t *conf);

/**
 * @brief Estrae c, z e h dall'array di byte della firma
 * @return 0 se l'estrazione ha successo, 1 se l'hint (h) è malformato
 */
int unpack_sig(uint8_t c[],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[],
               const dilithium_conf_t *conf);

/* ========================================================================== *
 * Packing/Unpacking Privati (Secret Keys)
 * ========================================================================== */

void pack_sk(uint8_t sk[],
             const uint8_t rho[DIL_SEEDBYTES],
             const uint8_t tr[DIL_TRBYTES],
             const uint8_t key[DIL_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2,
             const dilithium_conf_t *conf);

void unpack_sk(uint8_t rho[DIL_SEEDBYTES],
               uint8_t tr[DIL_TRBYTES],
               uint8_t key[DIL_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[],
               const dilithium_conf_t *conf);
