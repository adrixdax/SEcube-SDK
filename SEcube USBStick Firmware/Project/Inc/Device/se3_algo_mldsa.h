/**
 * ============================================================================
 * File Name          : se3_algo_mldsa.h
 * Description        : ML-DSA (FIPS 204) wrapper for SEcube
 * Version            : Safe Memory + All Bugs Fixed
 *
 * Supports:
 *   - ML-DSA-44 (Security Level 2)
 *   - ML-DSA-65 (Security Level 3)
 *   - ML-DSA-87 (Security Level 5)
 *
 * Features:
 *   - Memory-safe workspace allocation
 *   - Chunked Sign/Verify with bounds checking
 *   - Proper context handling (FIPS 204)
 *   - NULL pointer validation
 *   - Dynamic configuration support
 * ============================================================================
 */

#pragma once

#include "se3_security_core.h"
#include "se3_algo_mldsa_params.h"
#include "Keccak.h"
#include "se3_arith_poly.h"


/* ============================================================================
 * 1. CONSTANTS AND ENUMERATIONS
 * ============================================================================ */

/**
 * @brief Context mode enumeration
 */
typedef enum {
    SE3_DILITHIUM_CTX_IDLE      = 0x00,  /**< Uninitialized context */
    SE3_DILITHIUM_CTX_KEYGEN    = 0x01,  /**< KeyGen in progress */
    SE3_DILITHIUM_CTX_SIGN      = 0x02,  /**< Sign in progress */
    SE3_DILITHIUM_CTX_VERIFY    = 0x03,  /**< Verify in progress */
} se3_dilithium_ctx_mode_t;

/**
 * @brief Operation completion flag
 */
#define SE3_DILITHIUM_FINAL_FLAG  0x8000

/**
 * @brief Maximum signature size (ML-DSA-87)
 */
#define SE3_DILITHIUM_SIG_MAX     2701

/**
 * @brief Maximum public key size (ML-DSA-87)
 */
#define SE3_DILITHIUM_PK_MAX      1952

/**
 * @brief Maximum secret key size (ML-DSA-87)
 */
#define SE3_DILITHIUM_SK_MAX      4000

/* ============================================================================
 * 2. CONTEXT STRUCTURE
 * ============================================================================
 *
 * MEMORY LAYOUT:
 * - conf: Points to global ML-DSA parameters (44/65/87)
 * - op_mode: Current operation mode (IDLE, KEYGEN, SIGN, VERIFY)
 * - cached_pk: Pointer to public key (for Verify operations)
 * - cached_sk: Pointer to secret key (for Sign/KeyGen operations)
 * - shake_ctx: Persistent SHAKE256 state for message absorption
 * - tr_computed: Flag to avoid recomputing tr = H(pk)
 * - sig_offset: Internal offset tracker for signature packing
 */

typedef struct {
    /** @brief Pointer to ML-DSA configuration (determined by level) */
    const dilithium_conf_t* conf;

    /** @brief Current operation mode */
    uint8_t op_mode;

    /** @brief Cached public key pointer (NULL if not set) */
    const uint8_t* cached_pk;

    /** @brief Cached secret key pointer (NULL if not set) */
    const uint8_t* cached_sk;

    /** @brief SHAKE256 state for incremental message hashing */
    keccak_state shake_ctx;

    /** @brief Flag: has tr = H(pk) been computed? */
    uint8_t tr_computed;

    /** @brief Internal offset for signature packing (reserved) */
    uint16_t sig_offset;

    /** @brief Reserved for future use */
    uint8_t reserved[8];

} se3_dilithium_ctx;

/* ============================================================================
 * 3. ERROR CODES
 * ============================================================================ */

/**
 * @brief ML-DSA specific error codes
 */
#define SE3_DILITHIUM_OK              SE3_OK           /**< Success */
#define SE3_DILITHIUM_ERR_PARAMS      SE3_ERR_PARAMS   /**< Invalid parameters */
#define SE3_DILITHIUM_ERR_STATE       SE3_ERR_STATE    /**< Invalid state */
#define SE3_DILITHIUM_ERR_BUFFER      0x1001           /**< Buffer overflow */
#define SE3_DILITHIUM_ERR_BOUNDS      0x1002           /**< Bounds violation */
#define SE3_DILITHIUM_ERR_SIGNATURE   0x1003           /**< Signature verification failed */

/* ============================================================================
 * 4. ML-DSA-44 FUNCTION PROTOTYPES (Security Level 2)
 * ============================================================================
 */

void mldsa_derive_sign_rhoprime(const uint8_t key[32], const uint8_t rnd[32],
                                       const uint8_t mu[64], uint8_t rhoprime[64]);

void mldsa_derive_keygen_seeds(const uint8_t zeta[32], uint8_t k, uint8_t l,
                                      uint8_t rho[32], uint8_t rhoprime[64], uint8_t key[32]);

uint16_t poly_challenge_fips(poly *c, const uint8_t *seed, const dilithium_conf_t *conf);
/**
 * @brief Initialize ML-DSA-44 KeyGen operation
 *
 * @param key Pointer to flash key structure (optional)
 * @param mode Operation mode (reserved, use 0)
 * @param ctx Context buffer (pointer to se3_dilithium_ctx)
 *
 * @return SE3_OK on success, error code otherwise
 */
uint16_t se3_algo_Mldsa_44_KeyGen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);

/**
 * @brief Execute ML-DSA-44 KeyGen operation
 *
 * @param ctx Context buffer
 * @param flags Operation flags (SE3_DILITHIUM_FINAL_FLAG for completion)
 * @param datain1_len Length of first input (unused for KeyGen)
 * @param datain1 Pointer to first input (unused for KeyGen)
 * @param datain2_len Length of second input (unused for KeyGen)
 * @param datain2 Pointer to second input (unused for KeyGen)
 * @param dataout_len Output length (pk_bytes + sk_bytes)
 * @param dataout Output buffer containing PK || SK
 *
 * @return SE3_OK on success, error code otherwise
 *
 * @note Output format: [PK (1312 bytes)] || [SK (2528 bytes)]
 */
uint16_t se3_algo_Mldsa_44_KeyGen_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

/**
 * @brief Initialize ML-DSA-44 Sign operation
 *
 * @param key Pointer to secret key (required)
 * @param mode Operation mode (reserved, use 0)
 * @param ctx Context buffer
 *
 * @return SE3_OK on success, error code otherwise
 */
uint16_t se3_algo_Mldsa_44_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);

/**
 * @brief Execute chunked ML-DSA-44 Sign operation
 *
 * PROTOCOL:
 *   1. Loop calls: d1=SK chunk (0-800 bytes), d2=0, flags=0
 *   2. Final call: d1=0, d2=[ctx_len|ctx|message], flags=FINAL_FLAG
 *
 * @param ctx Context buffer
 * @param flags Operation flags
 * @param datain1_len SK chunk size (in loop calls)
 * @param datain1 SK chunk pointer
 * @param datain2_len Message size (only in final call)
 * @param datain2 Message pointer: [ctx_len (1 byte)] || [context] || [message]
 * @param dataout_len Signature length (2420 bytes for ML-DSA-44)
 * @param dataout Signature output buffer
 *
 * @return SE3_OK on success, error code otherwise
 *
 * @warning datain1/datain2 cannot both be NULL
 * @warning Total SK size must match key structure
 */
uint16_t se3_algo_Mldsa_44_Sign_update(uint8_t* ctx, uint16_t flags,
                                       uint16_t datain1_len, const uint8_t* datain1,
                                       uint16_t datain2_len, const uint8_t* datain2,
                                       uint16_t* dataout_len, uint8_t* dataout);

/**
 * @brief Initialize ML-DSA-44 Verify operation
 *
 * @param key Pointer to public key (required)
 * @param mode Operation mode (reserved, use 0)
 * @param ctx Context buffer
 *
 * @return SE3_OK on success, error code otherwise
 */
uint16_t se3_algo_Mldsa_44_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);

/**
 * @brief Execute chunked ML-DSA-44 Verify operation
 *
 * PROTOCOL:
 *   1. Loop calls: d1=0, d2=PK chunk (0-800 bytes), flags=0
 *   2. Final call: d1=signature, d2=[ctx_len|ctx|message], flags=FINAL_FLAG
 *
 * @param ctx Context buffer
 * @param flags Operation flags
 * @param datain1_len Signature size (only in final call)
 * @param datain1 Signature pointer
 * @param datain2_len PK chunk size (in loop) or message size (final)
 * @param datain2 PK chunk pointer (in loop) or message pointer (final)
 * @param dataout_len Result length (always 1)
 * @param dataout Result buffer: [0]=PASS, [0]=1 FAIL
 *
 * @return SE3_OK on success, error code otherwise
 *
 * @note Output: 0 = signature valid, 1 = signature invalid
 */
uint16_t se3_algo_Mldsa_44_Verify_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

/* ============================================================================
 * 5. ML-DSA-65 FUNCTION PROTOTYPES (Security Level 3)
 * ============================================================================
 */

uint16_t se3_algo_Mldsa_65_KeyGen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_65_KeyGen_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

uint16_t se3_algo_Mldsa_65_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_65_Sign_update(uint8_t* ctx, uint16_t flags,
                                       uint16_t datain1_len, const uint8_t* datain1,
                                       uint16_t datain2_len, const uint8_t* datain2,
                                       uint16_t* dataout_len, uint8_t* dataout);

uint16_t se3_algo_Mldsa_65_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_65_Verify_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

/* ============================================================================
 * 6. ML-DSA-87 FUNCTION PROTOTYPES (Security Level 5)
 * ============================================================================
 */

uint16_t se3_algo_Mldsa_87_KeyGen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_87_KeyGen_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

uint16_t se3_algo_Mldsa_87_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_87_Sign_update(uint8_t* ctx, uint16_t flags,
                                       uint16_t datain1_len, const uint8_t* datain1,
                                       uint16_t datain2_len, const uint8_t* datain2,
                                       uint16_t* dataout_len, uint8_t* dataout);

uint16_t se3_algo_Mldsa_87_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);
uint16_t se3_algo_Mldsa_87_Verify_update(uint8_t* ctx, uint16_t flags,
                                         uint16_t datain1_len, const uint8_t* datain1,
                                         uint16_t datain2_len, const uint8_t* datain2,
                                         uint16_t* dataout_len, uint8_t* dataout);

/* ============================================================================
 * 7. UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Get ML-DSA parameter set by security level
 *
 * @param level Security level (2=ML-DSA-44, 3=ML-DSA-65, 5=ML-DSA-87)
 *
 * @return Pointer to dilithium_conf_t, NULL if invalid level
 */
const dilithium_conf_t* se3_dilithium_get_config(uint16_t level);

/**
 * @brief Reset context to IDLE state
 *
 * @param ctx Context to reset
 *
 * @return SE3_OK on success
 */
uint16_t se3_dilithium_ctx_reset(se3_dilithium_ctx* ctx);

/**
 * @brief Validate context structure
 *
 * @param ctx Context to validate
 *
 * @return SE3_OK if valid, error code otherwise
 */
uint16_t se3_dilithium_ctx_validate(const se3_dilithium_ctx* ctx);

/* ============================================================================
 * 8. HELPER MACROS
 * ============================================================================
 */

/**
 * @brief Get signature size for given level
 */
#define SE3_DILITHIUM_SIG_SIZE(level) \
    ((level) == 2 ? 2420 : (level) == 3 ? 3293 : (level) == 5 ? 4627 : 0)

/**
 * @brief Get public key size for given level
 */
#define SE3_DILITHIUM_PK_SIZE(level) \
    ((level) == 2 ? 1312 : (level) == 3 ? 1952 : (level) == 5 ? 2592 : 0)

/**
 * @brief Get secret key size for given level
 */
#define SE3_DILITHIUM_SK_SIZE(level) \
    ((level) == 2 ? 2528 : (level) == 3 ? 4000 : (level) == 5 ? 5216 : 0)

/**
 * @brief Check if signature verification passed
 */
#define SE3_DILITHIUM_VERIFY_SUCCESS(result) ((result)[0] == 0)

/**
 * @brief Check if signature verification failed
 */
#define SE3_DILITHIUM_VERIFY_FAILURE(result) ((result)[0] != 0)

/* ============================================================================
 * 9. USAGE EXAMPLE
 * ============================================================================
 *
 * SIGN OPERATION:
 *
 *   se3_dilithium_ctx ctx;
 *   uint8_t signature[2420];
 *   uint16_t sig_len;
 *
 *   // Initialize
 *   se3_algo_Mldsa_44_Sign_init(key_with_sk, 0, (uint8_t*)&ctx);
 *
 *   // Send SK in chunks
 *   for(i = 0; i < sk_size; i += 800) {
 *       uint16_t chunk = min(800, sk_size - i);
 *       se3_algo_Mldsa_44_Sign_update((uint8_t*)&ctx, 0,
 *                                      chunk, sk + i,
 *                                      0, NULL,
 *                                      &dummy_len, dummy_buf);
 *   }
 *
 *   // Send message and get signature
 *   uint8_t msg_with_ctx[msg_len + 1];
 *   msg_with_ctx[0] = 0;  // ctx_len = 0 for Pure ML-DSA
 *   memcpy(msg_with_ctx + 1, message, msg_len);
 *
 *   se3_algo_Mldsa_44_Sign_update((uint8_t*)&ctx, SE3_DILITHIUM_FINAL_FLAG,
 *                                  0, NULL,
 *                                  msg_len + 1, msg_with_ctx,
 *                                  &sig_len, signature);
 *
 * VERIFY OPERATION:
 *
 *   // Initialize
 *   se3_algo_Mldsa_44_Verify_init(key_with_pk, 0, (uint8_t*)&ctx);
 *
 *   // Send PK in chunks
 *   for(i = 0; i < pk_size; i += 800) {
 *       uint16_t chunk = min(800, pk_size - i);
 *       se3_algo_Mldsa_44_Verify_update((uint8_t*)&ctx, 0,
 *                                        0, NULL,
 *                                        chunk, pk + i,
 *                                        &dummy_len, dummy_buf);
 *   }
 *
 *   // Send signature and message
 *   uint8_t result[1];
 *   uint16_t result_len;
 *   se3_algo_Mldsa_44_Verify_update((uint8_t*)&ctx, SE3_DILITHIUM_FINAL_FLAG,
 *                                    sig_len, signature,
 *                                    msg_len + 1, msg_with_ctx,
 *                                    &result_len, result);
 *
 *   if (SE3_DILITHIUM_VERIFY_SUCCESS(result)) {
 *       // Signature is valid
 *   } else {
 *       // Signature is invalid
 *   }
 *
 * ========================================================================== */

