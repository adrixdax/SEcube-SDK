/**
  ******************************************************************************
  * File Name          : se3_algo_shake.h
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : Header del dispatcher per algoritmi SHAKE (Dilithium).
  ******************************************************************************
  *
  * Copyright (c) 2026 Adriano d'Alessandro. Tutti i diritti riservati.
  *
  * Dettagli tecnici:
  * Espone i prototipi per le funzioni di interfaccia tra il core SEcube
  * e le primitive crittografiche SHAKE128/256. Queste funzioni devono
  * essere mappate all'interno della se3_algo_table.
  *
  ******************************************************************************
  */

#pragma once
#include "se3_security_core.h"
#include "shake.h"

typedef struct {
    keccak_state keccak;
    uint16_t output_len;
} se3_shake_ctx;

/* =========================================================
 * Prototipi per SHAKE128
 * ========================================================= */

/**
 * @brief Inizializza il contesto per SHAKE128.
 */
uint16_t se3_algo_Shake128_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
/**
 * @brief Gestisce assorbimento ed estrazione (XOF) per SHAKE128.
 */
uint16_t se3_algo_Shake128_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* =========================================================
 * Prototipi per SHAKE256
 * ========================================================= */

/**
 * @brief Inizializza il contesto per SHAKE256.
 */
uint16_t se3_algo_Shake256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
/**
 * @brief Gestisce assorbimento ed estrazione (XOF) per SHAKE256.
 */
uint16_t se3_algo_Shake256_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);
