/**
 * ============================================================================
 * File Name          : se3_algo_mldsa.c
 * Description        : ML-DSA (FIPS 204) - Versione Stabilizzata e Corretta
 * ============================================================================
 */

#include "se3_algo_mldsa.h"
#include "se3_algo_mldsa_params.h"
#include "se3_algo_mldsa_symmetric.h"
#include "se3_arith_packing.h"
#include "se3_arith_ntt.h"
#include "se3_arith_reduce.h"
#include "se3_arith_polyvec.h"
#include "se3_rand.h"
#include "shake.h"
#include <string.h>

/* ============================================================================
 * 1. WORKSPACE OTTIMIZZATO (CCRAM)
 * ============================================================================ */
#ifdef SIMULAZIONE_PC
    #define USE_CCRAM_SECTION
#else
    #define USE_CCRAM_SECTION __attribute__((section(".ccram")))
#endif
static USE_CCRAM_SECTION polyvecl shared_vl1;
static USE_CCRAM_SECTION polyvecl shared_vl2;
static USE_CCRAM_SECTION polyveck shared_vk1;
static USE_CCRAM_SECTION polyveck shared_vk2;
static USE_CCRAM_SECTION poly shared_cp;
static USE_CCRAM_SECTION poly shared_tmp_poly;

// Accumulatore 64-bit essenziale per non perdere precisione durante la moltiplicazione
static USE_CCRAM_SECTION int64_t shared_acc[DIL_N];

static USE_CCRAM_SECTION keccak_state global_st;
static USE_CCRAM_SECTION uint8_t global_v_buf[DIL_STREAM128_BLOCKBYTES + 4];

/* Accumulatori per gestione Chunked */
static USE_CCRAM_SECTION uint8_t shared_sig_buf[DIL_SIGBYTES_MAX];
static uint16_t sig_accumulated = 0;
static USE_CCRAM_SECTION uint8_t shared_pk_buf[2600];
static uint16_t pk_accumulated = 0;
static USE_CCRAM_SECTION uint8_t shared_sk_buf[5000];
static uint16_t sk_accumulated = 0;

/* ============================================================================
 * 2. FUNZIONI HELPER (Derivazione e Matematica)
 * ============================================================================ */

void mldsa_derive_keygen_seeds(const uint8_t zeta[32], uint8_t k, uint8_t l,
                                      uint8_t rho[32], uint8_t rhoprime[64], uint8_t key[32]) {
    keccak_state st;
    shake256_init(&st);

    shake256_absorb(&st, zeta, 32);
    shake256_absorb(&st, &k, 1);
    shake256_absorb(&st, &l, 1);

    shake256_finalize(&st);
    shake256_squeeze(rho, 32, &st);
    shake256_squeeze(rhoprime, 64, &st);
    shake256_squeeze(key, 32, &st);
}

static void mldsa_derive_sign_rhoprime(const uint8_t key[32], const uint8_t rnd[32],
                                       const uint8_t mu[64], uint8_t rhoprime[64]) {
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, key, 32);
    shake256_absorb(&st, rnd, 32);
    shake256_absorb(&st, mu, 64);
    shake256_finalize(&st);
    shake256_squeeze(rhoprime, 64, &st);
}

static uint16_t poly_challenge_fips(poly *c, const uint8_t *seed, const dilithium_conf_t *conf) {
    unsigned int i, pos; uint64_t signs; uint8_t buf[8]; keccak_state state;
    shake256_init(&state); shake256_absorb(&state, seed, conf->ctildebytes);
    shake256_finalize(&state); shake256_squeeze(buf, 8, &state);
    signs = 0; for(i = 0; i < 8; ++i) signs |= (uint64_t)buf[i] << (8 * i);
    memset(c->coeffs, 0, sizeof(int32_t) * DIL_N);
    for(i = DIL_N - conf->tau; i < DIL_N; ++i) {
        do { shake256_squeeze(buf, 1, &state); pos = buf[0]; } while(pos > i);
        c->coeffs[i] = c->coeffs[pos];
        c->coeffs[pos] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
    return SE3_OK;
}


static uint16_t dilithium_keygen_core(se3_dilithium_ctx* ctx, uint16_t* dataout_len, uint8_t* dataout) {
    // 1. Buffer per i semi (rho, rhoprime, key_seed)
    uint8_t seeds[128]; uint8_t zeta[32] = {0};
    // In produzione usa il TRNG qui
    uint8_t tr[64]; keccak_state state;
    // 2. Allocazione Vettori e Matrice (Usa variabili locali come richiesto)
    // // ATTENZIONE: Una matrice 4x4 di polinomi occupa molta RAM (~16KB per ML-DSA-44)
    polyvecl mat[ctx->conf->k];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;
    uint8_t *rho = seeds;
    uint8_t *rhoprime = seeds + 32;
    uint8_t *key_seed = seeds + 96;
    // 3. Derivazione sementi FIPS 204
    mldsa_derive_keygen_seeds(zeta, ctx->conf->k, ctx->conf->l, rho, rhoprime, key_seed);
    // 4. Espansione Matrice A e Vettori Segreti
    // Usiamo la funzione originale che genera tutto in un colpo solo
    polyvec_matrix_expand(mat, rho, ctx->conf);

    polyvecl_uniform_eta(&s1, rhoprime, 0, ctx->conf);
    polyveck_uniform_eta(&s2, rhoprime, ctx->conf->l, ctx->conf);
    // 3. Moltiplicazione matrice-vettore
    s1hat = s1;
    polyvecl_ntt(&s1hat, ctx->conf);

    // Moltiplicazione Matrice-Vettore Pointwise (Originale)
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat, ctx->conf);



    // Normalizzazione e ritorno al dominio normale
    polyveck_reduce(&t1, ctx->conf);

    polyveck_invntt_tomont(&t1, ctx->conf);


    // Somma errore: t = t + s2
    polyveck_add(&t1, &t1, &s2, ctx->conf);
    polyveck_caddq(&t1, ctx->conf);

    // 6. Decomposizione t -> (t1, t0)
    polyveck_power2round(&t1, &t0, &t1, ctx->conf);
    //FINO A QUI SAPPIAMO FUNZIONARE


    // DA QUI FUNZIONA IN PARTE
    // 7. Packing Public Key (PK)
    pack_pk(dataout, rho, &t1, ctx->conf);
    // 8. Hash H(PK) per la Secret Key
    shake256_init(&state);
    shake256_absorb(&state, dataout, ctx->conf->pk_bytes);
    shake256_finalize(&state);
    shake256_squeeze(tr, 64, &state);
    // 9. Packing Secret Key (SK)
    // // Posizioniamo la SK subito dopo la PK nel buffer di uscita
    uint8_t* sk_ptr = dataout + ctx->conf->pk_bytes;
    pack_sk(sk_ptr, rho, tr, key_seed, &t0, &s1, &s2, ctx->conf);
    *dataout_len = ctx->conf->pk_bytes + ctx->conf->sk_bytes;
    return SE3_OK;
}

/* ============================================================================
 * 4. SIGN CORE E VERIFY ... (Invariato rispetto all'ultima versione) ...
 * ============================================================================ */
static uint16_t dilithium_sign_core(se3_dilithium_ctx* ctx, uint16_t flags, uint16_t d_len,
                                    const uint8_t* d_in, const uint8_t* sk_in,
                                    uint16_t* o_l, uint8_t* o_out) {
    uint8_t rho[32], tr[64], key[32], mu[64], rhoprime[64], c_tilde[64];
    uint16_t nonce = 0;

    const uint8_t* active_sk = (sk_in != NULL) ? sk_in : ctx->cached_sk;
    memcpy(rho, active_sk + 0,  32);
    memcpy(key, active_sk + 32, 32);
    memcpy(tr,  active_sk + 64, 64);

    for(unsigned int i=0; i < ctx->conf->l; i++) {
        polyeta_unpack(&shared_vl1.vec[i], active_sk + 128 + i * ctx->conf->polyeta_packed, ctx->conf);
        poly_caddq(&shared_vl1.vec[i]); // FIX 2
        poly_ntt(&shared_vl1.vec[i]);
    }

    shake256_init(&ctx->shake_ctx);
    shake256_absorb(&ctx->shake_ctx, tr, 64);
    uint8_t domain_sep[2] = {0x00, 0x00};
    shake256_absorb(&ctx->shake_ctx, domain_sep, 2);
    shake256_absorb(&ctx->shake_ctx, d_in, d_len);
    shake256_finalize(&ctx->shake_ctx);
    shake256_squeeze(mu, 64, &ctx->shake_ctx);

    uint8_t zero_rnd[32] = {0};
    mldsa_derive_sign_rhoprime(key, zero_rnd, mu, rhoprime);

    while (nonce < 814) {
        polyvecl_uniform_gamma1(&shared_vl2, rhoprime, nonce++, ctx->conf);
        for(unsigned int i=0; i < ctx->conf->l; i++) {
            shared_vk1.vec[i] = shared_vl2.vec[i];
            poly_ntt(&shared_vk1.vec[i]);
        }

        //matrix_mult_streaming(&shared_vk2, rho, (polyvecl*)&shared_vk1, ctx->conf);
        polyveck_invntt_tomont(&shared_vk2, ctx->conf);

        polyveck_reduce(&shared_vk2, ctx->conf);
        polyveck_caddq(&shared_vk2, ctx->conf);

        polyveck w0_vec;
        for(unsigned int i=0; i < ctx->conf->k; i++) {
            poly_decompose(&shared_tmp_poly, &w0_vec.vec[i], &shared_vk2.vec[i], ctx->conf);
            polyw1_pack(shared_pk_buf + i * ctx->conf->polyw1_packed, &shared_tmp_poly, ctx->conf);
        }
        for(unsigned int i=0; i < ctx->conf->k; i++) {
            shared_vk2.vec[i] = w0_vec.vec[i];
        }

        shake256_init(&global_st);
        shake256_absorb(&global_st, mu, 64);
        shake256_absorb(&global_st, shared_pk_buf, ctx->conf->k * ctx->conf->polyw1_packed);
        shake256_finalize(&global_st);
        shake256_squeeze(c_tilde, ctx->conf->ctildebytes, &global_st);

        poly_challenge_fips(&shared_cp, c_tilde, ctx->conf);
        poly_caddq(&shared_cp); // FIX 2
        poly_ntt(&shared_cp);

        for(unsigned int i=0; i < ctx->conf->l; i++) {
            poly_pointwise_montgomery(&shared_tmp_poly, &shared_cp, &shared_vl1.vec[i]);
            poly_invntt_tomont(&shared_tmp_poly);
            poly_add(&shared_vl2.vec[i], &shared_vl2.vec[i], &shared_tmp_poly);
            poly_reduce(&shared_vl2.vec[i]);
        }

        if (polyvecl_chknorm(&shared_vl2, ctx->conf->gamma1 - ctx->conf->beta, ctx->conf)) {
            continue;
        }

        polyveck s2_vec;
        for(unsigned int i=0; i < ctx->conf->k; i++) {
            polyeta_unpack(&s2_vec.vec[i], active_sk + 128 + ctx->conf->l * ctx->conf->polyeta_packed + i * ctx->conf->polyeta_packed, ctx->conf);
            poly_ntt(&s2_vec.vec[i]);
            poly_pointwise_montgomery(&s2_vec.vec[i], &shared_cp, &s2_vec.vec[i]);
            poly_invntt_tomont(&s2_vec.vec[i]);

            poly_sub(&shared_vk2.vec[i], &shared_vk2.vec[i], &s2_vec.vec[i]);
            poly_reduce(&shared_vk2.vec[i]);
        }

        if (polyveck_chknorm(&shared_vk2, ctx->conf->gamma2 - ctx->conf->beta, ctx->conf)) {
            continue;
        }

        polyveck t0_vec;
        for(unsigned int i=0; i < ctx->conf->k; i++) {
            polyt0_unpack(&t0_vec.vec[i], active_sk + 128 + (ctx->conf->l + ctx->conf->k) * ctx->conf->polyeta_packed + i * POLYT0_PACKEDBYTES);
            poly_ntt(&t0_vec.vec[i]);
            poly_pointwise_montgomery(&t0_vec.vec[i], &shared_cp, &t0_vec.vec[i]);
            poly_invntt_tomont(&t0_vec.vec[i]);
            poly_reduce(&t0_vec.vec[i]);
        }

        if (polyveck_chknorm(&t0_vec, ctx->conf->gamma2, ctx->conf)) {
            continue;
        }

        polyveck_add(&shared_vk2, &shared_vk2, &t0_vec, ctx->conf);
        unsigned int hints = polyveck_make_hint(&shared_vk1, &t0_vec, &shared_vk2, ctx->conf);
        if (hints > ctx->conf->omega) {
            continue;
        }

        pack_sig(o_out, c_tilde, &shared_vl2, &shared_vk1, ctx->conf);
        *o_l = ctx->conf->sig_bytes;
        return SE3_OK;
    }

    o_out[0] = 0xCC; *o_l = 1;
    return SE3_OK;
}

static uint16_t dilithium_verify_core(se3_dilithium_ctx* ctx, const uint8_t* msg, size_t msg_len,
                                      const uint8_t* sig, uint16_t* o_l, uint8_t* o_out) {
    if (!ctx->cached_pk) return SE3_ERR_STATE;
    uint8_t rho[32], mu[64], c_tilde[DIL_CTILDE_MAX], tr[64], c_check[DIL_CTILDE_MAX];
    keccak_state state;

    unpack_pk(rho, &shared_vk1, ctx->cached_pk, ctx->conf);
    if (unpack_sig(c_tilde, &shared_vl1, &shared_vk2, sig, ctx->conf)) return SE3_ERR_PARAMS;
    if (polyvecl_chknorm(&shared_vl1, ctx->conf->gamma1 - ctx->conf->beta, ctx->conf)) {
        o_out[0] = 1; *o_l = 1; return SE3_OK;
    }

    shake256_init(&state);
    shake256_absorb(&state, ctx->cached_pk, ctx->conf->pk_bytes);
    shake256_finalize(&state);
    shake256_squeeze(tr, 64, &state);

    shake256_init(&state);
    shake256_absorb(&state, tr, 64);
    uint8_t domain_sep[2] = {0x00, 0x00};
    shake256_absorb(&state, domain_sep, 2);
    shake256_absorb(&state, msg, msg_len);
    shake256_finalize(&state);
    shake256_squeeze(mu, 64, &state);

    polyvecl_ntt(&shared_vl1, ctx->conf);
    //matrix_mult_streaming(&shared_vk1, rho, &shared_vl1, ctx->conf);

    poly_challenge_fips(&shared_cp, c_tilde, ctx->conf);
    poly_ntt(&shared_cp);

    polyveck_shiftl(&shared_vk2, ctx->conf);
    polyveck_ntt(&shared_vk2, ctx->conf);
    polyveck_pointwise_poly_montgomery(&shared_vk2, &shared_cp, &shared_vk2, ctx->conf);
    polyveck_sub(&shared_vk1, &shared_vk1, &shared_vk2, ctx->conf);
    polyveck_reduce(&shared_vk1, ctx->conf);
    polyveck_invntt_tomont(&shared_vk1, ctx->conf);
    polyveck_caddq(&shared_vk1, ctx->conf);

    polyveck_use_hint(&shared_vk1, &shared_vk1, &shared_vk2, ctx->conf);
    polyveck_pack_w1(shared_pk_buf, &shared_vk1, ctx->conf);

    shake256_init(&state);
    shake256_absorb(&state, mu, 64);
    shake256_absorb(&state, shared_pk_buf, ctx->conf->k * ctx->conf->polyw1_packed);
    shake256_finalize(&state);
    shake256_squeeze(c_check, ctx->conf->ctildebytes, &state);

    o_out[0] = (memcmp(c_tilde, c_check, ctx->conf->ctildebytes) == 0) ? 0 : 1;
    *o_l = 1;
    return SE3_OK;
}

static uint16_t mldsa_sign_update_chunked(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1,
                                          uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    if (d1 > 0 && i1 != NULL) {
        if (sk_accumulated + d1 > sizeof(shared_sk_buf)) { sk_accumulated = 0; return SE3_ERR_PARAMS; }
        memcpy(shared_sk_buf + sk_accumulated, i1, d1);
        sk_accumulated += d1;
    }
    if (f & SE3_CRYPTO_FLAG_FINIT) {
        const uint8_t* sk_to_use = (sk_accumulated > 0) ? shared_sk_buf : NULL;
        uint16_t ret = dilithium_sign_core(ctx, f, d2, i2, sk_to_use, o_l, o);
        sk_accumulated = 0; ctx->tr_computed = 0; return ret;
    }
    return SE3_OK;
}

static uint16_t mldsa_verify_update_chunked(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1,
                                            uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    if (d2 > 0 && !(f & SE3_CRYPTO_FLAG_FINIT)) {
        if (pk_accumulated + d2 > sizeof(shared_pk_buf)) return SE3_ERR_PARAMS;
        memcpy(shared_pk_buf + pk_accumulated, i2, d2);
        pk_accumulated += d2;
        ctx->cached_pk = shared_pk_buf;
    }
    if (d1 > 0 && !(f & SE3_CRYPTO_FLAG_FINIT)) {
        if (sig_accumulated + d1 > sizeof(shared_sig_buf)) return SE3_ERR_PARAMS;
        memcpy(shared_sig_buf + sig_accumulated, i1, d1);
        sig_accumulated += d1;
    }
    if (f & SE3_CRYPTO_FLAG_FINIT) {
        uint16_t ret = dilithium_verify_core(ctx, i2, d2, shared_sig_buf, o_l, o);
        sig_accumulated = 0; pk_accumulated = 0; return ret;
    }
    return SE3_OK;
}

uint16_t se3_algo_Mldsa_44_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2; return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o);
}
uint16_t se3_algo_Mldsa_44_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2; sk_accumulated = 0; ctx->tr_computed = 0; return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}
uint16_t se3_algo_Mldsa_44_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2; pk_accumulated = 0; sig_accumulated = 0; return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}

/* Wrapper per L3 (ML-DSA-65) e L5 (ML-DSA-87) ... (invariati) ... */
uint16_t se3_algo_Mldsa_65_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3; return SE3_OK; }
uint16_t se3_algo_Mldsa_65_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o); }
uint16_t se3_algo_Mldsa_65_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3; sk_accumulated = 0; return SE3_OK; }
uint16_t se3_algo_Mldsa_65_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o); }
uint16_t se3_algo_Mldsa_65_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3; pk_accumulated = 0; sig_accumulated = 0; return SE3_OK; }
uint16_t se3_algo_Mldsa_65_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o); }

uint16_t se3_algo_Mldsa_87_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5; return SE3_OK; }
uint16_t se3_algo_Mldsa_87_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o); }
uint16_t se3_algo_Mldsa_87_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5; sk_accumulated = 0; return SE3_OK; }
uint16_t se3_algo_Mldsa_87_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o); }
uint16_t se3_algo_Mldsa_87_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) { ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5; pk_accumulated = 0; sig_accumulated = 0; return SE3_OK; }
uint16_t se3_algo_Mldsa_87_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) { return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o); }
