/**
  ******************************************************************************
  * File Name          : sha3.c
  * Author             : Adriano d'Alessandro
  * Date               : 10/03/2026
  * Description        : Implementazione stateful di SHA-3 (Keccak) per SEcube.
  ******************************************************************************
  *
  * Copyright (c) 2026 Adriano d'Alessandro. Tutti i diritti riservati.
  *
  * Dettagli tecnici:
  * L'implementazione utilizza direttamente lo stato interno di Keccak,
  * eliminando i buffer intermedi esterni per risparmiare RAM sul Cortex-M4.
  * Le funzioni di Init, Update e Finit si interfacciano con il core nativo
  * per gestire l'accumulo parziale dei blocchi di dati in modo efficiente.
  *
  ******************************************************************************
  */

#include "Keccak.h" // La libreria Keccak ottimizzata
#include "sha3.h"

#include <stdint.h>
#include <string.h>

/* --- Inizializzazione SHA3-224 --- */
int32_t B5_Sha3_224_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;

    // Inizializza a zero solo i 200 byte dello stato (25 * 8 byte)
    memset(ctx->state, 0, 25 * sizeof(uint64_t));
    ctx->byteIndex = 0;
    ctx->rate = B5_SHA3_224_RATE;           // 144 byte
    ctx->outputLen = B5_SHA3_224_DIGEST_SIZE; // 28 byte

    return B5_SHA3_RES_OK;
}

/* --- Inizializzazione SHA3-256 --- */
int32_t B5_Sha3_256_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;

    memset(ctx->state, 0, 25 * sizeof(uint64_t));
    ctx->byteIndex = 0;
    ctx->rate = B5_SHA3_256_RATE;           // 136 byte
    ctx->outputLen = B5_SHA3_256_DIGEST_SIZE; // 32 byte

    return B5_SHA3_RES_OK;
}

/* --- Inizializzazione SHA3-384 --- */
int32_t B5_Sha3_384_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;

    memset(ctx->state, 0, 25 * sizeof(uint64_t));
    ctx->byteIndex = 0;
    ctx->rate = B5_SHA3_384_RATE;           // 104 byte
    ctx->outputLen = B5_SHA3_384_DIGEST_SIZE; // 48 byte

    return B5_SHA3_RES_OK;
}

/* --- Inizializzazione SHA3-512 --- */
int32_t B5_Sha3_512_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;

    memset(ctx->state, 0, 25 * sizeof(uint64_t));
    ctx->byteIndex = 0;
    ctx->rate = B5_SHA3_512_RATE;           // 72 byte
    ctx->outputLen = B5_SHA3_512_DIGEST_SIZE; // 64 byte

    return B5_SHA3_RES_OK;
}

/* --- Funzione Update (Generica per tutta la famiglia) --- */
int32_t B5_Sha3_Update(B5_tSha3Ctx *ctx, const uint8_t* data, int32_t dataLen) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    if(data == NULL || dataLen < 0) return B5_SHA3_RES_INVALID_ARGUMENT;

    // keccak_absorb gestisce lo XOR nello stato e restituisce i byte residui
    ctx->byteIndex = (uint32_t)keccak_absorb(ctx->state, ctx->byteIndex, ctx->rate, data, (size_t)dataLen);

    return B5_SHA3_RES_OK;
}

/* --- Finalizzazione (Padding e Squeeze) --- */
int32_t B5_Sha3_Finit(B5_tSha3Ctx *ctx, uint8_t* rDigest) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    if(rDigest == NULL) return B5_SHA3_RES_INVALID_ARGUMENT;

    // 1. Padding SHA-3 (0x06) come da standard FIPS 202
    keccak_finalize(ctx->state, ctx->byteIndex, ctx->rate, 0x06);

    // 2. Estrazione del digest finale (Squeeze)
    keccak_squeeze(rDigest, (size_t)ctx->outputLen, ctx->state, 0, ctx->rate);

    return B5_SHA3_RES_OK;
}