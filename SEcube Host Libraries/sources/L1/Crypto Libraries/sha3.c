/**
******************************************************************************
  * File Name          : sha3.c
  * Description        : SHA-3 (Keccak) Host implementation.
  ******************************************************************************
  */

#include "sha3.h"
#include "Keccak.h"

int32_t B5_Sha3_224_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    memset(ctx, 0, sizeof(B5_tSha3Ctx));
    ctx->rate = B5_SHA3_224_RATE;       // 1152 bit (144 bytes)
    ctx->outputLen = B5_SHA3_224_DIGEST_SIZE; // 28 bytes
    return B5_SHA3_RES_OK;
}

int32_t B5_Sha3_256_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    memset(ctx, 0, sizeof(B5_tSha3Ctx));
    ctx->rate = B5_SHA3_256_RATE;
    ctx->outputLen = B5_SHA3_256_DIGEST_SIZE;
    return B5_SHA3_RES_OK;
}

int32_t B5_Sha3_384_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    memset(ctx, 0, sizeof(B5_tSha3Ctx));
    ctx->rate = B5_SHA3_384_RATE;       // 832 bit (104 bytes)
    ctx->outputLen = B5_SHA3_384_DIGEST_SIZE; // 48 bytes
    return B5_SHA3_RES_OK;
}

int32_t B5_Sha3_512_Init(B5_tSha3Ctx *ctx) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    memset(ctx, 0, sizeof(B5_tSha3Ctx));
    ctx->rate = B5_SHA3_512_RATE;
    ctx->outputLen = B5_SHA3_512_DIGEST_SIZE; // Corretto: 512
    return B5_SHA3_RES_OK;
}

int32_t B5_Sha3_Update(B5_tSha3Ctx *ctx, const uint8_t* data, int32_t dataLen) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    if(data == NULL || dataLen < 0) return B5_SHA3_RES_INVALID_ARGUMENT;

    ctx->byteIndex = keccak_absorb(ctx->state, ctx->byteIndex, ctx->rate, data, (size_t)dataLen);
    return B5_SHA3_RES_OK;
}

int32_t B5_Sha3_Finit(B5_tSha3Ctx *ctx, uint8_t* rDigest) {
    if(ctx == NULL) return B5_SHA3_RES_INVALID_CONTEXT;
    if(rDigest == NULL) return B5_SHA3_RES_INVALID_ARGUMENT;

    keccak_finalize(ctx->state, ctx->byteIndex, ctx->rate, 0x06); // Padding SHA-3
    keccak_squeeze(rDigest, (size_t)ctx->outputLen, ctx->state, 0, ctx->rate);

    return B5_SHA3_RES_OK;
}