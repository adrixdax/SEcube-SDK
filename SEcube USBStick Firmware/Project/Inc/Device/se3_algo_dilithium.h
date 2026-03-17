/**
 *========================================================================
 * File Name          : se3_algo_dilithium_expanded.h
 * Description        : API Specifica per i livelli ML-DSA (44, 65, 87)
 * Version            : 1.1 - Expanded per Livelli NIST
 *========================================================================
 */

#pragma once
#include "se3_security_core.h"
#include "se3_algo_dilithium_params.h" // Risolve 'dilithium_conf_t'
#include "Keccak.h"                    // Risolve 'keccak_state'
/* ========================================================================== *
 * CONTEXT STRUCTURE & FLAGS
 * ========================================================================== */

#define SE3_OK          0x0000
#define SE3_ERR_PARAMS  0x0001
#define SE3_ERR_HW      0x0002
#define SE3_ERR_STATE   0x0003
#define SE3_ERR_MEMORY  0x0004

#define SE3_DIR_FINISH  0x0001 // Assicurati di avere questo flag

typedef enum {
    SE3_DILITHIUM_CTX_IDLE      = 0x00,
    SE3_DILITHIUM_CTX_KEYGEN    = 0x01,
    SE3_DILITHIUM_CTX_SIGN      = 0x02,
    SE3_DILITHIUM_CTX_VERIFY    = 0x03,
    SE3_DILITHIUM_CTX_BENCH     = 0x04,
} se3_dilithium_ctx_mode_t;

typedef struct {
    const dilithium_conf_t* conf;
    keccak_state shake_ctx;
    se3_dilithium_ctx_mode_t op_mode;
    uint32_t msg_processed;
    uint32_t timestamp;
} se3_dilithium_ctx;

/* ========================================================================== *
 * PUBLIC API - ML-DSA-44 (Security Level 2)
 * ========================================================================== */

/* --- ML-DSA-44 Keygen --- */
uint16_t se3_algo_Mldsa44_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa44_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);
/* --- ML-DSA-44 SIGN --- */
uint16_t se3_algo_Mldsa44_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa44_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* --- ML-DSA-44 VERIFY --- */
uint16_t se3_algo_Mldsa44_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa44_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);


/* ========================================================================== *
 * PUBLIC API - ML-DSA-65 (Security Level 3)
 * ========================================================================== */

/* --- ML-DSA-65 Keygen --- */
uint16_t se3_algo_Mldsa65_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa65_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* --- ML-DSA-65 SIGN --- */
uint16_t se3_algo_Mldsa65_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa65_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* --- ML-DSA-65 VERIFY --- */
uint16_t se3_algo_Mldsa65_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa65_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);


/* ========================================================================== *
 * PUBLIC API - ML-DSA-87 (Security Level 5)
 * ========================================================================== */

/* --- ML-DSA-87 Keygen --- */
uint16_t se3_algo_Mldsa87_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa87_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* --- ML-DSA-87 SIGN --- */
uint16_t se3_algo_Mldsa87_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa87_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);

/* --- ML-DSA-87 VERIFY --- */
uint16_t se3_algo_Mldsa87_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa87_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout);
