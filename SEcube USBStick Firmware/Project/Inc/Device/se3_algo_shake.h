#include "shake.h" 

typedef struct {
    keccak_state keccak;
    uint16_t output_len;
} se3_shake_ctx;

/* =========================================================
 * Prototipi per SHAKE128 e SHAKE256
 * ========================================================= */
uint16_t se3_algo_Shake128_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Shake128_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);

uint16_t se3_algo_Shake256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Shake256_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);
