#include "se3_core.h"
#include "se3_algo_sha3.h"

/* =========================================================
 * SHA3-224
 * ========================================================= */
uint16_t se3_algo_Sha3_224_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (B5_SHA3_RES_OK != B5_Sha3_224_Init(sha)) {
        SE3_TRACE(("[algo_sha3.init224] B5_Sha3_224_Init failed\n"));
        return (SE3_ERR_PARAMS);
    }
    return (SE3_OK);
}

uint16_t se3_algo_Sha3_224_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (datain1_len > 0) {
        if (B5_SHA3_RES_OK != B5_Sha3_Update(sha, datain1, datain1_len)) {
            return SE3_ERR_HW;
        }
    }
    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (B5_SHA3_RES_OK != B5_Sha3_Finit(sha, dataout)) {
            return SE3_ERR_HW;
        }
        *dataout_len = (uint16_t)sha->outputLen;
    }
    return (SE3_OK);
}

/* =========================================================
 * SHA3-256
 * ========================================================= */
uint16_t se3_algo_Sha3_256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (B5_SHA3_RES_OK != B5_Sha3_256_Init(sha)) {
        SE3_TRACE(("[algo_sha3.init256] B5_Sha3_256_Init failed\n"));
        return (SE3_ERR_PARAMS);
    }
    return (SE3_OK);
}

uint16_t se3_algo_Sha3_256_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (datain1_len > 0) {
        if (B5_SHA3_RES_OK != B5_Sha3_Update(sha, datain1, datain1_len)) {
            return SE3_ERR_HW;
        }
    }
    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (B5_SHA3_RES_OK != B5_Sha3_Finit(sha, dataout)) {
            return SE3_ERR_HW;
        }
        *dataout_len = (uint16_t)sha->outputLen;
    }
    return (SE3_OK);
}

/* =========================================================
 * SHA3-384
 * ========================================================= */
uint16_t se3_algo_Sha3_384_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (B5_SHA3_RES_OK != B5_Sha3_384_Init(sha)) {
        SE3_TRACE(("[algo_sha3.init384] B5_Sha3_384_Init failed\n"));
        return (SE3_ERR_PARAMS);
    }
    return (SE3_OK);
}

uint16_t se3_algo_Sha3_384_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (datain1_len > 0) {
        if (B5_SHA3_RES_OK != B5_Sha3_Update(sha, datain1, datain1_len)) {
            return SE3_ERR_HW;
        }
    }
    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (B5_SHA3_RES_OK != B5_Sha3_Finit(sha, dataout)) {
            return SE3_ERR_HW;
        }
        *dataout_len = (uint16_t)sha->outputLen;
    }
    return (SE3_OK);
}

/* =========================================================
 * SHA3-512
 * ========================================================= */
uint16_t se3_algo_Sha3_512_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (B5_SHA3_RES_OK != B5_Sha3_512_Init(sha)) {
        SE3_TRACE(("[algo_sha3.init512] B5_Sha3_512_Init failed\n"));
        return (SE3_ERR_PARAMS);
    }
    return (SE3_OK);
}

uint16_t se3_algo_Sha3_512_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout) {

    B5_tSha3Ctx* sha = (B5_tSha3Ctx*)ctx;
    if (datain1_len > 0) {
        if (B5_SHA3_RES_OK != B5_Sha3_Update(sha, datain1, datain1_len)) {
            return SE3_ERR_HW;
        }
    }
    if (flags & SE3_CRYPTO_FLAG_FINIT) {
        if (B5_SHA3_RES_OK != B5_Sha3_Finit(sha, dataout)) {
            return SE3_ERR_HW;
        }
        *dataout_len = (uint16_t)sha->outputLen;
    }
    return (SE3_OK);
}