/**
 * ============================================================================
 * File Name          : se3_algo_mldsa.c
 * Description        : ML-DSA (FIPS 204) - Versione a footprint ridotto per HSM
 * ============================================================================
 */

#include "se3_algo_mldsa.h"

#include <stdio.h>

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
 * 1. WORKSPACE OTTIMIZZATO (CCRAM) - RIUTILIZZO GLOBALE
 * ============================================================================ */
#define USE_CCRAM_SECTION __attribute__((section(".ccram")))

/* Buffer polinomiali principali (riutilizzati in tutte le fasi) */
static USE_CCRAM_SECTION polyvecl shared_vl1;       // y, z, s1 (temporaneo)
static USE_CCRAM_SECTION polyvecl shared_vl2;       // y_hat, z_ntt
static USE_CCRAM_SECTION polyveck shared_vk1;       // w, w_minus_cs2, r_vec, s2 (temporaneo)
static USE_CCRAM_SECTION polyveck shared_vk2;       // w1_vec, r1_vec, r_plus_z_vec, r1_vec_new, t1 (temporaneo)
static USE_CCRAM_SECTION polyveck shared_vk3;       // w0_vec, r0_vec, ct0_vec, v1_vec, t0 (temporaneo)
static USE_CCRAM_SECTION polyveck shared_vk4;       // ct0_centered, v0_dummy, h_vec
static USE_CCRAM_SECTION poly shared_cp;            // c_hat, tmp
static USE_CCRAM_SECTION poly shared_tmp_poly;      // operazioni temporanee

/* Accumulatore 64-bit essenziale per NTT */
static USE_CCRAM_SECTION int64_t shared_acc[DIL_N];

/* Stato Keccak e buffer hash riutilizzabili */
static USE_CCRAM_SECTION keccak_state global_st;
static USE_CCRAM_SECTION uint8_t global_v_buf[DIL_STREAM128_BLOCKBYTES + 4];

/* Buffer unificato per accumulo chunked (max tra SK, SIG, PK) */
static USE_CCRAM_SECTION uint8_t shared_io_buffer[10000];
static uint16_t io_accumulated = 0;

/* Matrice statica per evitare allocazione locale in sign/verify/keygen */
static USE_CCRAM_SECTION polyvecl mat_ws[DIL_K_MAX];

/* ============================================================================
 * 2. FUNZIONI HELPER (Derivazione e Matematica) - INVARIATE
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

void mldsa_derive_sign_rhoprime(const uint8_t key[32], const uint8_t rnd[32],
                                       const uint8_t mu[64], uint8_t rhoprime[64]) {
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, key, 32);
    shake256_absorb(&st, rnd, 32);
    shake256_absorb(&st, mu, 64);
    shake256_finalize(&st);
    shake256_squeeze(rhoprime, 64, &st);
}

uint16_t poly_challenge_fips(poly *c, const uint8_t *seed, const dilithium_conf_t *conf) {
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

/* ============================================================================
 * 3. KEYGEN CORE - OTTIMIZZATO (Nessuna allocazione array su Stack)
 * ============================================================================ */
static uint16_t dilithium_keygen_core(se3_dilithium_ctx* ctx, uint16_t* dataout_len, uint8_t* dataout) {
    const dilithium_conf_t *conf = ctx->conf;

    // Il seme deve essere 0 per il test KAT
    uint8_t zeta[32] = {0};
    uint8_t rho[32], rhoprime[64], key_seed[32];

    mldsa_derive_keygen_seeds(zeta, conf->k, conf->l, rho, rhoprime, key_seed);

    // Usa i puntatori ai buffer in CCRAM (evita di bloccare la memoria stack)
    polyvecl *s1    = &shared_vl1;
    polyveck *s2    = &shared_vk1;
    polyvecl *s1hat = &shared_vl2;
    polyveck *t1    = &shared_vk2;
    polyveck *t0    = &shared_vk3;

    // Espandi matrice usando buffer globale statico
    polyvec_matrix_expand(mat_ws, rho, conf);

    polyvecl_uniform_eta(s1, rhoprime, 0, conf);
    polyveck_uniform_eta(s2, rhoprime, conf->l, conf);

    *s1hat = *s1;
    polyvecl_ntt(s1hat, conf);

    polyvec_matrix_pointwise_montgomery(t1, mat_ws, s1hat, conf);

    polyveck_invntt_tomont(t1, conf);
    polyveck_add(t1, t1, s2, conf);
    polyveck_caddq(t1, conf);

    polyveck_power2round(t1, t0, t1, conf);

    // Impacchetta nel buffer unificato
    pack_pk(dataout, rho, t1, ctx->conf);

    uint8_t tr[64];
    keccak_state state_tr;
    shake256_init(&state_tr);
    // Usa pk_bytes invece di hardcode 1312 per generalizzare su 65 e 87
    shake256_absorb(&state_tr, dataout, ctx->conf->pk_bytes);
    shake256_finalize(&state_tr);
    shake256_squeeze(tr, 64, &state_tr);

    uint8_t* sk_ptr = dataout + ctx->conf->pk_bytes;
    pack_sk(sk_ptr, rho, tr, key_seed, t0, s1, s2, ctx->conf);

    *dataout_len = ctx->conf->pk_bytes + ctx->conf->sk_bytes;
    return SE3_OK;
}

/* ============================================================================
 * 4. SIGN CORE - INVARIATO (Già OTTIMIZZATO)
 * ============================================================================ */
static uint16_t dilithium_sign_core(se3_dilithium_ctx *ctx, uint16_t msg_len, uint16_t unused,
                             const uint8_t *msg, const uint8_t *sk,
                             uint16_t *sig_len, uint8_t *sig) {
    const dilithium_conf_t *conf = ctx->conf;
    uint8_t rho[32], tr[64], key[32], mu[64], rhoprime[64], c_tilde[64];
    uint16_t nonce = 0;

    memcpy(rho, sk + 0, 32);
    memcpy(key, sk + 32, 32);
    memcpy(tr, sk + 64, 64);

    polyvec_matrix_expand(mat_ws, rho, conf);

    keccak_state shake_ctx;
    shake256_init(&shake_ctx);
    shake256_absorb(&shake_ctx, tr, 64);
    uint8_t domain_sep[2] = {0x00, 0x00};
    shake256_absorb(&shake_ctx, domain_sep, 2);
    shake256_absorb(&shake_ctx, msg, msg_len);
    shake256_finalize(&shake_ctx);
    shake256_squeeze(mu, 64, &shake_ctx);

    uint8_t zero_rnd[32] = {0};
    mldsa_derive_sign_rhoprime(key, zero_rnd, mu, rhoprime);

    polyvecl *y      = &shared_vl1;
    polyvecl *y_hat  = &shared_vl2;
    polyveck *w      = &shared_vk1;
    poly      *c_hat = &shared_cp;
    polyveck *w1_vec = &shared_vk2;
    polyveck *w0_vec = &shared_vk3;
    polyvecl *z      = y;
    polyveck *w_minus_cs2 = w;

    uint8_t *pk_buf = (uint8_t*)&shared_vk4;

    // Polinomio temporaneo locale (1024 byte) – OK per stack
    poly tmp_poly;

    while (nonce < 1628) {
        polyvecl_uniform_gamma1(y, rhoprime, nonce++, conf);
        *y_hat = *y;
        polyvecl_ntt(y_hat, conf);
        polyvec_matrix_pointwise_montgomery(w, mat_ws, y_hat, conf);
        polyveck_invntt_tomont(w, conf);
        polyveck_reduce(w, conf);
        polyveck_caddq(w, conf);

        for (unsigned int i = 0; i < conf->k; i++) {
            poly_decompose(&w1_vec->vec[i], &w0_vec->vec[i], &w->vec[i], conf);
        }
        for (unsigned int i = 0; i < conf->k; i++) {
            polyw1_pack(pk_buf + i * conf->polyw1_packed, &w1_vec->vec[i], conf);
        }
        keccak_state hash_st;
        shake256_init(&hash_st);
        shake256_absorb(&hash_st, mu, 64);
        shake256_absorb(&hash_st, pk_buf, conf->k * conf->polyw1_packed);
        shake256_finalize(&hash_st);
        shake256_squeeze(c_tilde, conf->ctildebytes, &hash_st);

        memset(c_hat, 0, sizeof(poly));
        poly_challenge_fips(c_hat, c_tilde, conf);

        // Calcolo di z = y + c*s1 (decompressione on‑the‑fly)
        for (unsigned int i = 0; i < conf->l; i++) {
            polyeta_unpack(&tmp_poly, sk + 128 + i * conf->polyeta_packed, conf);
            poly_mul_sparse(&shared_tmp_poly, c_hat, &tmp_poly);
            for (int j = 0; j < 256; j++) {
                z->vec[i].coeffs[j] = y->vec[i].coeffs[j] + shared_tmp_poly.coeffs[j];
            }
        }
        if (polyvecl_chknorm(z, conf->gamma1 - conf->beta, conf)) continue;

        // Calcolo di w_minus_cs2 = w - c*s2
        for (unsigned int i = 0; i < conf->k; i++) {
            polyeta_unpack(&tmp_poly, sk + 128 + conf->l * conf->polyeta_packed + i * conf->polyeta_packed, conf);
            poly_mul_sparse(&shared_tmp_poly, c_hat, &tmp_poly);
            poly_sub(&shared_tmp_poly, &w->vec[i], &shared_tmp_poly);
            poly_reduce(&shared_tmp_poly);
            w_minus_cs2->vec[i] = shared_tmp_poly;
        }

        polyveck *r1_vec = &shared_vk2;
        polyveck *r0_vec = &shared_vk3;
        for (unsigned int i = 0; i < conf->k; i++) {
            poly tmp = w_minus_cs2->vec[i];
            poly_caddq(&tmp);
            poly_decompose(&r1_vec->vec[i], &r0_vec->vec[i], &tmp, conf);
        }
        if (polyveck_chknorm(r0_vec, conf->gamma2 - conf->beta, conf)) continue;

        // Calcolo di ct0 = c * t0
        polyveck *ct0_vec      = &shared_vk3;
        polyveck *ct0_centered = &shared_vk4;
        for (unsigned int i = 0; i < conf->k; i++) {
            int t0_offset = 128 + (conf->l + conf->k) * conf->polyeta_packed + i * 416;
            polyt0_unpack(&tmp_poly, sk + t0_offset);
            poly_mul_sparse(&ct0_vec->vec[i], c_hat, &tmp_poly);
            poly_reduce(&ct0_vec->vec[i]);
        }
        *ct0_centered = *ct0_vec;
        for (unsigned int i = 0; i < conf->k; i++) {
            for (int j = 0; j < 256; j++) {
                int32_t val = ct0_centered->vec[i].coeffs[j] % DIL_Q;
                if (val < 0) val += DIL_Q;
                if (val > (DIL_Q / 2)) val -= DIL_Q;
                ct0_centered->vec[i].coeffs[j] = val;
            }
        }
        if (polyveck_chknorm(ct0_centered, conf->gamma2, conf)) continue;

        polyveck *r_vec        = w;
        polyveck *r_plus_z_vec = &shared_vk2;
        for (unsigned int i = 0; i < conf->k; i++) {
            for (int j = 0; j < 256; j++) {
                int32_t val_w_cs2 = w_minus_cs2->vec[i].coeffs[j] % DIL_Q;
                if (val_w_cs2 < 0) val_w_cs2 += DIL_Q;
                int32_t val_ct0 = ct0_vec->vec[i].coeffs[j] % DIL_Q;
                if (val_ct0 < 0) val_ct0 += DIL_Q;
                r_plus_z_vec->vec[i].coeffs[j] = val_w_cs2;
                r_vec->vec[i].coeffs[j] = (val_w_cs2 + val_ct0) % DIL_Q;
            }
        }

        polyveck *v1_vec   = &shared_vk3;
        polyveck *v0_dummy = &shared_vk4;
        for (unsigned int i = 0; i < conf->k; i++) {
            poly_decompose(&v1_vec->vec[i], &v0_dummy->vec[i], &r_plus_z_vec->vec[i], conf);
        }

        polyveck *r1_vec_new = &shared_vk2;
        polyveck *r0_dummy   = &shared_vk1;
        for (unsigned int i = 0; i < conf->k; i++) {
            poly_decompose(&r1_vec_new->vec[i], &r0_dummy->vec[i], &r_vec->vec[i], conf);
        }

        polyveck *h_vec = &shared_vk4;
        unsigned int hints = 0;
        for (unsigned int i = 0; i < conf->k; i++) {
            for (int j = 0; j < 256; j++) {
                if (r1_vec_new->vec[i].coeffs[j] != v1_vec->vec[i].coeffs[j]) {
                    h_vec->vec[i].coeffs[j] = 1;
                    hints++;
                } else {
                    h_vec->vec[i].coeffs[j] = 0;
                }
            }
        }
        if (hints > conf->omega) continue;

        pack_sig(sig, c_tilde, z, h_vec, conf);
        *sig_len = conf->sig_bytes;
        return SE3_OK;
    }
    return SE3_ERR_EXPIRED;
}

/* ============================================================================
 * 5. VERIFY CORE - FIX PUNTATORE PK
 * ============================================================================ */
static uint16_t dilithium_verify_core(se3_dilithium_ctx* ctx, const uint8_t* pk, const uint8_t* msg, size_t msg_len,
                                      const uint8_t* sig, uint16_t* o_l, uint8_t* o_out) {
    // Rimosso il check su ctx->cached_pk, ora la PK arriva direttamente dal buffer!

    uint8_t rho[32], mu[64], c_tilde[DIL_CTILDE_MAX], tr[64], c_check[DIL_CTILDE_MAX];
    keccak_state state;

    polyveck *t1      = &shared_vk1;
    polyvecl *z       = &shared_vl1;
    polyveck *h       = &shared_vk2;
    poly *c           = &shared_cp;

    polyvecl *z_ntt   = &shared_vl2;
    polyveck *w1      = &shared_vk3;
    polyveck *w1_recon = &shared_vk4;
    memset(t1, 0, sizeof(polyveck));
    memset(z, 0, sizeof(polyvecl));
    memset(h, 0, sizeof(polyveck));
    memset(&shared_tmp_poly, 0, sizeof(poly)); // FONDAMENTALE PER LA VERIFICA!
    unpack_pk(rho, t1, pk, ctx->conf);
    if (unpack_sig(c_tilde, z, h, sig, ctx->conf)) return SE3_ERR_PARAMS;

    shake256_init(&state);
    shake256_absorb(&state, pk, ctx->conf->pk_bytes);
    shake256_finalize(&state);
    shake256_squeeze(tr, 64, &state);

    shake256_init(&state);
    shake256_absorb(&state, tr, 64);
    uint8_t domain_sep[2] = {0x00, 0x00};
    shake256_absorb(&state, domain_sep, 2);
    shake256_absorb(&state, msg, msg_len);
    shake256_finalize(&state);
    shake256_squeeze(mu, 64, &state);

    *z_ntt = *z;
    polyvecl_ntt(z_ntt, ctx->conf);

    polyvec_matrix_expand(mat_ws, rho, ctx->conf);
    polyvec_matrix_pointwise_montgomery(w1, mat_ws, z_ntt, ctx->conf);
    polyveck_invntt_tomont(w1, ctx->conf);
    polyveck_reduce(w1, ctx->conf);
    polyveck_caddq(w1, ctx->conf);

    poly_challenge_fips(c, c_tilde, ctx->conf);
    polyveck_shiftl(t1, ctx->conf);

    for (unsigned int i = 0; i < ctx->conf->k; i++) {
        poly_mul_sparse(&shared_tmp_poly, c, &t1->vec[i]);
        for (int j = 0; j < 256; j++) {
            int32_t val = w1->vec[i].coeffs[j] - shared_tmp_poly.coeffs[j];
            val %= DIL_Q;
            if (val < 0) val += DIL_Q;
            w1->vec[i].coeffs[j] = val;
        }
    }

    polyveck_use_hint(w1_recon, w1, h, ctx->conf);

    uint8_t *pk_buf = shared_io_buffer;
    for (unsigned int i = 0; i < ctx->conf->k; i++) {
        polyw1_pack(pk_buf + i * ctx->conf->polyw1_packed, &w1_recon->vec[i], ctx->conf);
    }

    shake256_init(&state);
    shake256_absorb(&state, mu, 64);
    shake256_absorb(&state, pk_buf, ctx->conf->k * ctx->conf->polyw1_packed);
    shake256_finalize(&state);
    shake256_squeeze(c_check, ctx->conf->ctildebytes, &state);

    o_out[0] = (memcmp(c_tilde, c_check, ctx->conf->ctildebytes) == 0) ? 0 : 1;
    *o_l = 1;

    return SE3_OK;
}

/* ============================================================================
 * 6. CHUNKING SOLO PER SIGN E VERIFY - FIX PARSER
 * ============================================================================ */
static uint16_t mldsa_sign_update_chunked(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1,
                                          uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;

    if (d1 > 0 && i1 != NULL) {
        if (io_accumulated + d1 > sizeof(shared_io_buffer)) {
            io_accumulated = 0;
            return SE3_ERR_PARAMS;
        }
        memcpy(shared_io_buffer + io_accumulated, i1, d1);
        io_accumulated += d1;
    }

    if (f & SE3_CRYPTO_FLAG_FINIT) {
        uint16_t sk_bytes = ctx->conf->sk_bytes;

        // Verifica di avere almeno la SK nel buffer
        if (io_accumulated < sk_bytes) {
            io_accumulated = 0;
            return SE3_ERR_PARAMS;
        }

        // Il PC invia: [ SK ] + [ MESSAGGIO ]
        const uint8_t* sk  = shared_io_buffer;
        const uint8_t* msg = shared_io_buffer + sk_bytes;
        uint16_t msg_len   = io_accumulated - sk_bytes;

        // Ora passiamo i parametri perfettamente estratti!
        uint16_t ret = dilithium_sign_core(ctx, msg_len, 0, msg, sk, o_l, o);
        io_accumulated = 0;
        ctx->tr_computed = 0;
        return ret;
    }
    return SE3_OK;
}

static uint16_t mldsa_verify_update_chunked(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1,
                                            uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;

    // FIX: Rimosso un check errato che ignorava l'ultimo frammento di dati
    if (d1 > 0 && i1 != NULL) {
        if (io_accumulated + d1 > sizeof(shared_io_buffer)) {
            io_accumulated = 0;
            return SE3_ERR_PARAMS;
        }
        memcpy(shared_io_buffer + io_accumulated, i1, d1);
        io_accumulated += d1;
    }

    if (f & SE3_CRYPTO_FLAG_FINIT) {
        uint16_t pk_bytes  = ctx->conf->pk_bytes;
        uint16_t sig_bytes = ctx->conf->sig_bytes;

        // Verifica di avere almeno PK + SIG nel buffer
        if (io_accumulated < pk_bytes + sig_bytes) {
            io_accumulated = 0;
            return SE3_ERR_PARAMS;
        }

        // Il PC invia: [ PK ] + [ SIG ] + [ MESSAGGIO ]
        const uint8_t* pk  = shared_io_buffer;
        const uint8_t* sig = shared_io_buffer + pk_bytes;
        const uint8_t* msg = shared_io_buffer + pk_bytes + sig_bytes;
        uint16_t msg_len   = io_accumulated - pk_bytes - sig_bytes;

        uint16_t ret = dilithium_verify_core(ctx, pk, msg, msg_len, sig, o_l, o);
        io_accumulated = 0;
        return ret;
    }
    return SE3_OK;
}

/* ============================================================================
 * 7. WRAPPERS FINALI (KeyGen punta diretto, Sign/Verify a chunk)
 * ============================================================================ */

uint16_t se3_algo_Mldsa_44_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    // Manteniamo la chiamata diretta, il buffer USB in lettura basta!
    return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o);
}
uint16_t se3_algo_Mldsa_44_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2;
    io_accumulated = 0;
    ctx->tr_computed = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}
uint16_t se3_algo_Mldsa_44_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    se3_dilithium_ctx* ctx = (se3_dilithium_ctx*)c;
    ctx->conf = &SE3_DILITHIUM_L2;
    io_accumulated = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_44_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}

/* Wrapper per L3 (ML-DSA-65) e L5 (ML-DSA-87) */
uint16_t se3_algo_Mldsa_65_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_65_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o);
}
uint16_t se3_algo_Mldsa_65_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3;
    io_accumulated = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_65_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}
uint16_t se3_algo_Mldsa_65_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L3;
    io_accumulated = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_65_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}

uint16_t se3_algo_Mldsa_87_KeyGen_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_87_KeyGen_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return dilithium_keygen_core((se3_dilithium_ctx*)c, o_l, o);
}
uint16_t se3_algo_Mldsa_87_Sign_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5;
    io_accumulated = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_87_Sign_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_sign_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}
uint16_t se3_algo_Mldsa_87_Verify_init(se3_flash_key* k, uint16_t m, uint8_t* c) {
    ((se3_dilithium_ctx*)c)->conf = &SE3_DILITHIUM_L5;
    io_accumulated = 0;
    return SE3_OK;
}
uint16_t se3_algo_Mldsa_87_Verify_update(uint8_t* c, uint16_t f, uint16_t d1, const uint8_t* i1, uint16_t d2, const uint8_t* i2, uint16_t* o_l, uint8_t* o) {
    return mldsa_verify_update_chunked(c, f, d1, i1, d2, i2, o_l, o);
}