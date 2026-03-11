/**
******************************************************************************
  * File Name          : sha3.h
  * Author             : Adriano d'Alessandro <adrianodalessandro@yahoo.it>
  * Date               : 10/03/2026
  * Description        : Definizioni e contesto per le primitive SHA-3 (Keccak).
  ******************************************************************************
  *
  * Copyright (c) 2026 Adriano d'Alessandro. Tutti i diritti riservati.
  *
  * Dettagli tecnici:
  * Definisce il contesto di stato per l'hashing SHA-3.
  * La struttura è stata ottimizzata rimuovendo i buffer intermedi
  * per garantire un footprint di memoria minimo su architetture embedded.
  *
  ******************************************************************************
  */

#define B5_SHA3_RES_OK 0
#define B5_SHA3_RES_INVALID_CONTEXT -1
#define B5_SHA3_RES_INVALID_ARGUMENT -2

#define B5_SHA3_224_RATE              144
#define B5_SHA3_256_RATE              136
#define B5_SHA3_384_RATE              104
#define B5_SHA3_512_RATE              72

#define B5_SHA3_224_DIGEST_SIZE       28
#define B5_SHA3_256_DIGEST_SIZE       32
#define B5_SHA3_384_DIGEST_SIZE       48
#define B5_SHA3_512_DIGEST_SIZE       64

#include <stdint.h> // <--- FONDAMENTALE per int32_t e uint64_t
#include <stddef.h>
typedef struct {
    uint64_t state[25];      // Stato interno di Keccak (200 bytes)
    uint32_t byteIndex;      // Posizione attuale (sostituisce il buffer esterno)
    uint32_t rate;           // Es. 136 per SHA3-256
    uint32_t outputLen;      // Es. 32 per SHA3-256
} B5_tSha3Ctx;

int32_t B5_Sha3_224_Init(B5_tSha3Ctx *ctx);
int32_t B5_Sha3_256_Init(B5_tSha3Ctx *ctx);
int32_t B5_Sha3_384_Init(B5_tSha3Ctx *ctx);
int32_t B5_Sha3_512_Init(B5_tSha3Ctx *ctx);

int32_t B5_Sha3_Update(B5_tSha3Ctx *ctx, const uint8_t* data, int32_t dataLen);
int32_t B5_Sha3_Finit(B5_tSha3Ctx *ctx, uint8_t* rDigest);
