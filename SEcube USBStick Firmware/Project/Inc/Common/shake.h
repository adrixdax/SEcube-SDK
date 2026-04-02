/**
******************************************************************************
  * File Name          : shake.h
  * Author             : Adriano d'Alessandro
  * Date               : 11/03/2026
  * Description        : SHAKE128/256 (XOF) ottimizzato per SEcube (Cortex-M4).
  ******************************************************************************
  */

#include "Keccak.h"
#include <stddef.h>
#include <stdint.h>

#define SHAKE_RES_OK 0
#define SHAKE_RES_ERR -1

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

#ifndef SE3_SHAKE_CTX
#define SE3_SHAKE_CTX
typedef struct se3_shake_ctx_t {
    keccak_state keccak;
    uint16_t output_len;
} se3_shake_ctx;
#endif

/* --- SHAKE128 --- */
int32_t shake128_init(keccak_state *state);
int32_t shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
int32_t shake128_finalize(keccak_state *state);
int32_t shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
int32_t shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

/* --- SHAKE256 --- */
int32_t shake256_init(keccak_state *state);
int32_t shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
int32_t shake256_finalize(keccak_state *state);
int32_t shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
int32_t shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

