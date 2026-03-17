/**
 *========================================================================
 * File Name          : se3_algo_dilithium.c
 * Description        : Implementazione ML-DSA (Streaming Init/Update)
 *========================================================================
 */

#include "se3_algo_dilithium.h"
#include "se3_algo_dilithium_params.h"
#include "se3_algo_dilithium_symmetric.h"

/* Header della libreria matematica di base */
#include "se3_arith_packing.h"
#include "se3_rand.h"
#include "shake.h"

/* ========================================================================== *
 * SEZIONE 0: CORE COMUNE PER LA GENERAZIONE CHIAVI (KEYGEN)
 * ========================================================================== */

static uint16_t dilithium_keygen_init_core(se3_dilithium_ctx* ctx, se3_flash_key* key, const dilithium_conf_t* conf) {
    ctx->conf = conf;
    ctx->op_mode = SE3_DILITHIUM_CTX_KEYGEN;
    return SE3_OK;
}

static uint16_t dilithium_keygen_update_core(
    se3_dilithium_ctx* ctx, uint16_t flags,
    uint16_t datain_len, const uint8_t* datain,
    uint16_t* dataout_len, uint8_t* dataout)
{
    if (!(flags & SE3_DIR_FINISH)) {
        *dataout_len = 0;
        return SE3_OK;
    }

    uint8_t seedbuf[2 * DIL_SEEDBYTES + DIL_CRHBYTES];
    uint8_t tr[DIL_TRBYTES];
    const uint8_t *rho, *rhoprime, *key_seed;

    // Allocazione buffer con i MAX (attenzioni allo stack su M4)
    polyvecl mat[DIL_K_MAX];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;
    keccak_state state;

    // 1. Estrazione entropia iniziale
    se3_rand(DIL_SEEDBYTES,seedbuf);
    seedbuf[DIL_SEEDBYTES + 0] = ctx->conf->k;
    seedbuf[DIL_SEEDBYTES + 1] = ctx->conf->l;

    shake256_init(&state);
    shake256_absorb(&state, seedbuf, DIL_SEEDBYTES + 2);
    shake256_finalize(&state);
    shake256_squeeze(seedbuf, 2 * DIL_SEEDBYTES + DIL_CRHBYTES, &state);

    rho = seedbuf;
    rhoprime = rho + DIL_SEEDBYTES;
    key_seed = rhoprime + DIL_CRHBYTES;

    // 2. Espansione matrice e vettori segreti
    polyvec_matrix_expand(mat, rho, ctx->conf);
    polyvecl_uniform_eta(&s1, rhoprime, 0, ctx->conf);
    polyveck_uniform_eta(&s2, rhoprime, ctx->conf->l, ctx->conf);

    // 3. Moltiplicazione matrice-vettore
    s1hat = s1;
    polyvecl_ntt(&s1hat, ctx->conf);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat, ctx->conf);
    polyveck_reduce(&t1, ctx->conf);
    polyveck_invntt_tomont(&t1, ctx->conf);

    // 4. Aggiunta errore ed estrazione t1
    polyveck_add(&t1, &t1, &s2, ctx->conf);
    polyveck_caddq(&t1, ctx->conf);
    polyveck_power2round(&t1, &t0, &t1, ctx->conf);

    // 5. Generazione Chiave Pubblica (PK)
    // Usiamo la prima parte del buffer dataout per la PK
    pack_pk(dataout, rho, &t1, ctx->conf);

    // 6. Calcolo hash H(rho, t1) per la Secret Key
    shake256_init(&state);
    shake256_absorb(&state, dataout, ctx->conf->pk_bytes);
    shake256_finalize(&state);
    shake256_squeeze(tr, DIL_TRBYTES, &state);

    // 7. Generazione Chiave Privata (SK)
    // Posizioniamo la SK subito dopo la PK nel buffer dataout
    pack_sk(dataout + ctx->conf->pk_bytes, rho, tr, key_seed, &t0, &s1, &s2, ctx->conf);

    // Output totale: PK + SK (il dispatcher estrarrà le due parti conoscendone la lunghezza)
    *dataout_len = ctx->conf->pk_bytes + ctx->conf->sk_bytes;

    return SE3_OK;
}

/* ========================================================================== *
 * SEZIONE 1: CORE COMUNE PER LA FIRMA (SIGN)
 * ========================================================================== */

static uint16_t dilithium_sign_init_core(se3_dilithium_ctx* ctx, se3_flash_key* key, const dilithium_conf_t* conf) {
    uint8_t pre[257];
    uint8_t tr[DIL_TRBYTES];

    ctx->conf = conf;
    ctx->op_mode = SE3_DILITHIUM_CTX_SIGN;
    ctx->msg_processed = 0;

    /* * In un ambiente reale SEcube, tr e rho vengono estratti dalla chiave
     * privata passata in 'key'. Qui diamo per scontato che tu abbia
     * una funzione interna per estrarre l'hash della chiave pubblica (tr).
     */

    // Preparazione del prefisso standard (0, ctxlen, ctx...). Qui ctxlen = 0.
    pre[0] = 0;
    pre[1] = 0;

    // Inizializza SHAKE per calcolare mu = CRH(tr, pre, msg)
    shake256_init(&ctx->shake_ctx);
    shake256_absorb(&ctx->shake_ctx, tr, DIL_TRBYTES);
    shake256_absorb(&ctx->shake_ctx, pre, 2);

    return SE3_OK;
}

static uint16_t dilithium_sign_update_core(
    se3_dilithium_ctx* ctx, uint16_t flags,
    uint16_t datain_len, const uint8_t* datain,
    uint16_t* dataout_len, uint8_t* dataout)
{
    // 1. Assorbiamo i dati in arrivo man mano che arrivano (Streaming)
    if (datain_len > 0 && datain != NULL) {
        shake256_absorb(&ctx->shake_ctx, datain, datain_len);
        ctx->msg_processed += datain_len;
    }

    // 2. Se non abbiamo finito di ricevere i dati, usciamo.
    if (!(flags & SE3_DIR_FINISH)) {
        *dataout_len = 0;
        return SE3_OK;
    }

    // 3. SEZIONE FINALE: Il messaggio è completo, eseguiamo la firma vera e propria
    unsigned int n;
    uint8_t mu[DIL_CRHBYTES];
    uint8_t rhoprime[DIL_CRHBYTES];
    uint8_t rnd[DIL_RNDBYTES];
    uint16_t nonce = 0;

    // Variabili matematiche (usiamo i MAX per allocare in sicurezza sullo stack)
    polyvecl mat[DIL_K_MAX], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    keccak_state state;

    /* Estraiamo le parti della chiave privata (simulato) */
    uint8_t rho[DIL_SEEDBYTES], key[DIL_SEEDBYTES]; // Da riempire con i dati di 'key'

    // Finalizziamo il calcolo di 'mu'
    shake256_finalize(&ctx->shake_ctx);
    shake256_squeeze(mu, DIL_CRHBYTES, &ctx->shake_ctx);

    //randombytes(rnd, DIL_RNDBYTES);
    se3_rand(DIL_RNDBYTES,rnd);

    // Calcolo rhoprime = CRH(key, rnd, mu)
    shake256_init(&state);
    shake256_absorb(&state, key, DIL_SEEDBYTES);
    shake256_absorb(&state, rnd, DIL_RNDBYTES);
    shake256_absorb(&state, mu, DIL_CRHBYTES);
    shake256_finalize(&state);
    shake256_squeeze(rhoprime, DIL_CRHBYTES, &state);

    // Espansione matrice e trasformate
    polyvec_matrix_expand(mat, rho, ctx->conf);
    polyvecl_ntt(&s1, ctx->conf);
    polyveck_ntt(&s2, ctx->conf);
    polyveck_ntt(&t0, ctx->conf);

rej:
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++, ctx->conf);

    z = y;
    polyvecl_ntt(&z, ctx->conf);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z, ctx->conf);
    polyveck_reduce(&w1, ctx->conf);
    polyveck_invntt_tomont(&w1, ctx->conf);

    polyveck_caddq(&w1, ctx->conf);
    polyveck_decompose(&w1, &w0, &w1, ctx->conf);
    polyveck_pack_w1(dataout, &w1, ctx->conf);

    shake256_init(&state);
    shake256_absorb(&state, mu, DIL_CRHBYTES);
    shake256_absorb(&state, dataout, ctx->conf->k * ctx->conf->polyw1_packed);
    shake256_finalize(&state);
    shake256_squeeze(dataout, ctx->conf->ctildebytes, &state);

    poly_challenge(&cp, dataout, ctx->conf);
    poly_ntt(&cp);

    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1, ctx->conf);
    polyvecl_invntt_tomont(&z, ctx->conf);
    polyvecl_add(&z, &z, &y, ctx->conf);
    polyvecl_reduce(&z, ctx->conf);

    // Controllo norma usando i parametri dinamici
    if(polyvecl_chknorm(&z, ctx->conf->gamma1 - ctx->conf->beta, ctx->conf)) goto rej;

    polyveck_pointwise_poly_montgomery(&h, &cp, &s2, ctx->conf);
    polyveck_invntt_tomont(&h, ctx->conf);
    polyveck_sub(&w0, &w0, &h, ctx->conf);
    polyveck_reduce(&w0, ctx->conf);

    if(polyveck_chknorm(&w0, ctx->conf->gamma2 - ctx->conf->beta, ctx->conf)) goto rej;

    polyveck_pointwise_poly_montgomery(&h, &cp, &t0, ctx->conf);
    polyveck_invntt_tomont(&h, ctx->conf);
    polyveck_reduce(&h, ctx->conf);

    if(polyveck_chknorm(&h, ctx->conf->gamma2, ctx->conf)) goto rej;

    polyveck_add(&w0, &w0, &h, ctx->conf);
    n = polyveck_make_hint(&h, &w0, &w1, ctx->conf);

    if(n > ctx->conf->omega) goto rej;

    // Scrive la firma finale nel buffer di output
    pack_sig(dataout, dataout, &z, &h, ctx->conf);
    *dataout_len = ctx->conf->sig_bytes;

    return SE3_OK;
}

/* ========================================================================== *
 * SEZIONE 2: CORE COMUNE PER LA VERIFICA (VERIFY)
 * ========================================================================== */

static uint16_t dilithium_verify_init_core(se3_dilithium_ctx* ctx, se3_flash_key* key, const dilithium_conf_t* conf) {
    uint8_t pre[257];
    uint8_t mu[DIL_CRHBYTES]; // tr simulato

    ctx->conf = conf;
    ctx->op_mode = SE3_DILITHIUM_CTX_VERIFY;
    ctx->msg_processed = 0;

    pre[0] = 0;
    pre[1] = 0;

    shake256_init(&ctx->shake_ctx);
    shake256_absorb(&ctx->shake_ctx, mu, DIL_TRBYTES);
    shake256_absorb(&ctx->shake_ctx, pre, 2);

    return SE3_OK;
}

static uint16_t dilithium_verify_update_core(
    se3_dilithium_ctx* ctx, uint16_t flags,
    uint16_t datain_len, const uint8_t* datain,
    const uint8_t* sig, const uint8_t* pk, // Aggiunti firma e chiave per la validazione
    uint16_t* dataout_len, uint8_t* dataout)
{
    if (datain_len > 0 && datain != NULL) {
        shake256_absorb(&ctx->shake_ctx, datain, datain_len);
    }

    if (!(flags & SE3_DIR_FINISH)) {
        *dataout_len = 0;
        return SE3_OK;
    }

    // Esecuzione verifica
    unsigned int i;
    uint8_t buf[DIL_K_MAX * DIL_POLYW1_PACKEDBYTES_MAX];
    uint8_t rho[DIL_SEEDBYTES], mu[DIL_CRHBYTES], c[DIL_CTILDE_MAX], c2[DIL_CTILDE_MAX];
    poly cp;
    polyvecl mat[DIL_K_MAX], z;
    polyveck t1, w1, h;
    keccak_state state;

    unpack_pk(rho, &t1, pk, ctx->conf);
    if(unpack_sig(c, &z, &h, sig, ctx->conf)) return SE3_ERR_STATE; // Firma malformata
    if(polyvecl_chknorm(&z, ctx->conf->gamma1 - ctx->conf->beta, ctx->conf)) return SE3_ERR_STATE;

    shake256_finalize(&ctx->shake_ctx);
    shake256_squeeze(mu, DIL_CRHBYTES, &ctx->shake_ctx);

    poly_challenge(&cp, c, ctx->conf);
    polyvec_matrix_expand(mat, rho, ctx->conf);
    polyvecl_ntt(&z, ctx->conf);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z,ctx->conf);

    poly_ntt(&cp);
    polyveck_shiftl(&t1, ctx->conf);
    polyveck_ntt(&t1, ctx->conf);
    polyveck_pointwise_poly_montgomery(&t1, &cp, &t1,ctx->conf);

    polyveck_sub(&w1, &w1, &t1, ctx->conf);
    polyveck_reduce(&w1, ctx->conf);
    polyveck_invntt_tomont(&w1, ctx->conf);

    polyveck_caddq(&w1, ctx->conf);
    polyveck_use_hint(&w1, &w1, &h, ctx->conf);
    polyveck_pack_w1(buf, &w1, ctx->conf);

    shake256_init(&state);
    shake256_absorb(&state, mu, DIL_CRHBYTES);
    shake256_absorb(&state, buf, ctx->conf->k * ctx->conf->polyw1_packed);
    shake256_finalize(&state);
    shake256_squeeze(c2, ctx->conf->ctildebytes, &state);

    for(i = 0; i < ctx->conf->ctildebytes; ++i) {
        if(c[i] != c2[i]) return SE3_ERR_STATE; // Firma non valida
    }

    *dataout_len = 0; // Verify non produce dati in output, solo un codice di ritorno
    return SE3_OK;
}

/* ========================================================================== *
 * SEZIONE 3: API PUBBLICHE (Wrapper per Livelli)
 * ========================================================================== */

/* --- ML-DSA-44 (Livello 2) --- */

uint16_t se3_algo_Mldsa44_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_keygen_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L2);
}
uint16_t se3_algo_Mldsa44_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}

uint16_t se3_algo_Mldsa44_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_sign_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L2);
}
uint16_t se3_algo_Mldsa44_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_sign_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_sign_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}
uint16_t se3_algo_Mldsa44_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_verify_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L2);
}

uint16_t se3_algo_Mldsa44_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    /* NOTA: In fase di VERIFY, l'algoritmo ha bisogno del messaggio per fare l'hash (streaming),
     * e alla fine (quando c'è il flag SE3_DIR_FINISH) ha bisogno della Firma e della Chiave Pubblica.
     * In questo wrapper, passiamo datain1 e datain2 come firma e chiave per l'ultima chiamata.
     * Dovrai adattare i puntatori "sig" e "pk" in base a come il tuo host PC invia i dati. */
    const uint8_t* sig = datain1;
    const uint8_t* pk = datain2;

    dilithium_verify_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, sig, pk, dataout_len, dataout);
    return dilithium_verify_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, sig, pk, dataout_len, dataout);
}

/* --- ML-DSA-65 (Livello 3) --- */

uint16_t se3_algo_Mldsa65_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_keygen_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L3);
}
uint16_t se3_algo_Mldsa65_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}

uint16_t se3_algo_Mldsa65_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_sign_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L3);
}
uint16_t se3_algo_Mldsa65_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_sign_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_sign_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}
uint16_t se3_algo_Mldsa65_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_verify_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L3);
}

uint16_t se3_algo_Mldsa65_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    const uint8_t* sig = datain1;
    const uint8_t* pk = datain2;

    dilithium_verify_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, sig, pk, dataout_len, dataout);
    return dilithium_verify_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, sig, pk, dataout_len, dataout);
}

/* --- ML-DSA-87 (Livello 5) --- */

uint16_t se3_algo_Mldsa87_Keygen_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_keygen_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L5);
}
uint16_t se3_algo_Mldsa87_Keygen_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_keygen_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}

uint16_t se3_algo_Mldsa87_Sign_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_sign_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L5);
}
uint16_t se3_algo_Mldsa87_Sign_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    dilithium_sign_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, dataout_len, dataout);
    return dilithium_sign_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, dataout_len, dataout);
}
uint16_t se3_algo_Mldsa87_Verify_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
    return dilithium_verify_init_core((se3_dilithium_ctx*)ctx, key, &SE3_DILITHIUM_L5);
}

uint16_t se3_algo_Mldsa87_Verify_update(uint8_t* ctx, uint16_t flags, uint16_t datain1_len, const uint8_t* datain1, uint16_t datain2_len, const uint8_t* datain2, uint16_t* dataout_len, uint8_t* dataout) {
    const uint8_t* sig = datain1;
    const uint8_t* pk = datain2;

    dilithium_verify_update_core((se3_dilithium_ctx*)ctx, 0, datain1_len, datain1, sig, pk, dataout_len, dataout);
    return dilithium_verify_update_core((se3_dilithium_ctx*)ctx, flags, datain2_len, datain2, sig, pk, dataout_len, dataout);
}
