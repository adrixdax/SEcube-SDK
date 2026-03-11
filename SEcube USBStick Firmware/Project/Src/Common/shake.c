/**
******************************************************************************
  * File Name          : shake.h
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : SHAKE128/256 (XOF) ottimizzato per SEcube (Cortex-M4).
  ******************************************************************************
  */

#include "shake.h"

int32_t shake128_init(keccak_state *state) {
    if(state == NULL) return SHAKE_RES_ERR;
    keccak_init(state);
    return SHAKE_RES_OK;
}

int32_t shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen) {
    if(state == NULL || in == NULL) return SHAKE_RES_ERR;
    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
    return SHAKE_RES_OK;
}

int32_t shake128_finalize(keccak_state *state) {
    if(state == NULL) return SHAKE_RES_ERR;
    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
    state->pos = 0;
    return SHAKE_RES_OK;
}

int32_t shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state) {
    if(state == NULL || out == NULL) return SHAKE_RES_ERR;
    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
    return SHAKE_RES_OK;
}

/* --- SHAKE256 --- */
int32_t shake256_init(keccak_state *state) {
    if(state == NULL) return SHAKE_RES_ERR;
    keccak_init(state);
    return SHAKE_RES_OK;
}

int32_t shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen) {
    if(state == NULL || in == NULL) return SHAKE_RES_ERR;
    state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
    return SHAKE_RES_OK;
}

int32_t shake256_finalize(keccak_state *state) {
    if(state == NULL) return SHAKE_RES_ERR;
    keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = 0;
    return SHAKE_RES_OK;
}

int32_t shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state) {
    if(state == NULL || out == NULL) return SHAKE_RES_ERR;
    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
    return SHAKE_RES_OK;
}
