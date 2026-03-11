/**
  ******************************************************************************
  * File Name          : se3_algo_shake.c
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : Dispatcher firmware per algoritmi SHAKE (Dilithium XOF).
  ******************************************************************************
  */
#include "se3_core.h"
#include "se3_algo_shake.h"

/* =========================================================
 * SHAKE128
 * ========================================================= */
uint16_t se3_algo_Shake128_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    se3_shake_ctx* state = (se3_shake_ctx*)ctx;

    state->output_len = mode; // L'Host ci invia la lunghezza qui!

    if (SHAKE_RES_OK != shake128_init(&state->keccak)) {
        return SE3_ERR_PARAMS;
    }
    return SE3_OK;
}

uint16_t se3_algo_Shake128_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    se3_shake_ctx* state = (se3_shake_ctx*)ctx;

    if (datain1_len > 0) {
        if (SHAKE_RES_OK != shake128_absorb(&state->keccak, datain1, datain1_len)) {
            return SE3_ERR_HW;
        }
    }

    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (SHAKE_RES_OK != shake128_finalize(&state->keccak)) return SE3_ERR_HW;

        // Estraiamo esattamente la lunghezza che ci eravamo salvati in Init
        if (SHAKE_RES_OK != shake128_squeeze(dataout, state->output_len, &state->keccak)) return SE3_ERR_HW;

        *dataout_len = state->output_len; // Fondamentale: diciamo all'Host quanti byte abbiamo scritto!
    }

    return SE3_OK;
}

/* =========================================================
 * SHAKE256
 * ========================================================= */
uint16_t se3_algo_Shake256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    se3_shake_ctx* state = (se3_shake_ctx*)ctx;
    state->output_len = mode;
    if (SHAKE_RES_OK != shake256_init(&state->keccak)) return SE3_ERR_PARAMS;
    return SE3_OK;
}

uint16_t se3_algo_Shake256_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    se3_shake_ctx* state = (se3_shake_ctx*)ctx;

    if (datain1_len > 0) {
        if (SHAKE_RES_OK != shake256_absorb(&state->keccak, datain1, datain1_len)) return SE3_ERR_HW;
    }

    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (SHAKE_RES_OK != shake256_finalize(&state->keccak)) return SE3_ERR_HW;
        if (SHAKE_RES_OK != shake256_squeeze(dataout, state->output_len, &state->keccak)) return SE3_ERR_HW;
        *dataout_len = state->output_len;
    }

    return SE3_OK;
}