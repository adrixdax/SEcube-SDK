/**
******************************************************************************
  * File Name          : se3_algo_sha3.h
  * Author             : Adriano d'Alessandro <adrianodalessandro@yahoo.it>
  * Date               : 2026
  * Description        : Wrapper per le primitive SHA-3 (Keccak) su SEcube.
  ******************************************************************************
  *
  * Copyright (c) 2026 Adriano d'Alessandro. Tutti i diritti riservati.
  *
  * * Dettagli tecnici:
  * Questa implementazione adatta lo stato di Keccak al dispatcher
  * crittografico del SEcube, mantenendo un basso footprint di memoria
  * per operare in sicurezza sui microcontrollori Cortex-M4.
  *
  ******************************************************************************
  */

#pragma once
#include "se3_security_core.h"

/* =========================================================
 * PROTOTIPI DELLE FUNZIONI PER IL DISPATCHER (SHA-3 Family)
 * ========================================================= */

/* --- SHA3-224 --- */
/**
 * @brief Inizializza il contesto per SHA3-224
 */
uint16_t se3_algo_Sha3_224_init(
    se3_flash_key* key,
    uint16_t mode,
    uint8_t* ctx
);

/**
 * @brief Riceve i blocchi di dati ed estrae l'hash al termine per SHA3-224
 */
uint16_t se3_algo_Sha3_224_update(
    uint8_t* ctx,
    uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout
);

/* --- SHA3-256 --- */
/**
 * @brief Inizializza il contesto per SHA3-256
 */
uint16_t se3_algo_Sha3_256_init(
    se3_flash_key* key,
    uint16_t mode,
    uint8_t* ctx
);

uint16_t se3_algo_Sha3_256_update(
    uint8_t* ctx,
    uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout
);

/* --- SHA3-384 --- */
/**
 * @brief Inizializza il contesto per SHA3-384
 */
uint16_t se3_algo_Sha3_384_init(
    se3_flash_key* key,
    uint16_t mode,
    uint8_t* ctx
);

/**
 * @brief Riceve i blocchi di dati ed estrae l'hash al termine per SHA3-384
 */
uint16_t se3_algo_Sha3_384_update(
    uint8_t* ctx,
    uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout
);

/* --- SHA3-512 --- */
/**
 * @brief Inizializza il contesto per SHA3-512
 */
uint16_t se3_algo_Sha3_512_init(
    se3_flash_key* key,
    uint16_t mode,
    uint8_t* ctx
);

/**
 * @brief Riceve i blocchi di dati ed estrae l'hash al termine per SHA3-512
 */
uint16_t se3_algo_Sha3_512_update(
    uint8_t* ctx,
    uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout
);