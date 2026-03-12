/**
******************************************************************************
  * File Name          : sha3.h
  * Description        : SHA-3 (Keccak) Host Header file.
  ******************************************************************************
  */

#pragma once

#include <stdint.h>
#include <string.h>

/** \defgroup sha3Return SHA3 return values */
#define B5_SHA3_RES_OK				 		 ( 0)
#define B5_SHA3_RES_INVALID_CONTEXT			(-1)
#define B5_SHA3_RES_INVALID_ARGUMENT         (-3)

/** \defgroup sha3Size SHA3 rate and digest sizes */
#define B5_SHA3_224_DIGEST_SIZE       28
#define B5_SHA3_256_DIGEST_SIZE       32
#define B5_SHA3_384_DIGEST_SIZE       48
#define B5_SHA3_512_DIGEST_SIZE       64

#define B5_SHA3_224_RATE              144
#define B5_SHA3_256_RATE              136
#define B5_SHA3_384_RATE              104
#define B5_SHA3_512_RATE              72
/** \name SHA3 data structures */
typedef struct
{
    uint64_t   state[25];    // Keccak state (1600 bits)
    uint32_t   byteIndex;    // Current position in rate
    uint32_t   rate;         // Selected rate
    uint32_t   outputLen;    // Selected output length
} B5_tSha3Ctx;

/** \name SHA3 functions */
int32_t B5_Sha3_224_Init(B5_tSha3Ctx *ctx);
int32_t B5_Sha3_256_Init (B5_tSha3Ctx *ctx);
int32_t B5_Sha3_384_Init(B5_tSha3Ctx *ctx);
int32_t B5_Sha3_512_Init (B5_tSha3Ctx *ctx);
int32_t B5_Sha3_Update (B5_tSha3Ctx *ctx, const uint8_t *data, int32_t dataLen);
int32_t B5_Sha3_Finit (B5_tSha3Ctx *ctx, uint8_t *rDigest);