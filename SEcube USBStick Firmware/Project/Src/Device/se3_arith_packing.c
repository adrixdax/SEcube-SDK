/**
  ******************************************************************************
  * File Name          : se3_arith_packing.c
  * Description        : Implementazione dinamica del packing ML-DSA.
  * Ottimizzazione     : Loop Unrolling x2 esplicito per architetture Cortex-M
  ******************************************************************************
  */

#include "se3_arith_packing.h"
#include <string.h>

/* ========================================================================== *
 * PUBLIC KEY PACKING
 * ========================================================================== */

void pack_pk(uint8_t pk[], const uint8_t rho[DIL_SEEDBYTES], const polyveck *t1, const dilithium_conf_t *conf) {
    unsigned int i;

    // DIL_SEEDBYTES (32) è sempre pari
    for(i = 0; i < DIL_SEEDBYTES; i += 2) {
        pk[i]   = rho[i];
        pk[i+1] = rho[i+1];
    }
    pk += DIL_SEEDBYTES;

    // conf->k (4, 6, 8) è sempre pari
    for(i = 0; i < conf->k; i += 2) {
        polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
        polyt1_pack(pk + (i+1) * POLYT1_PACKEDBYTES, &t1->vec[i+1]);
    }
}

void unpack_pk(uint8_t rho[DIL_SEEDBYTES], polyveck *t1, const uint8_t pk[], const dilithium_conf_t *conf) {
    unsigned int i;

    for(i = 0; i < DIL_SEEDBYTES; i += 2) {
        rho[i]   = pk[i];
        rho[i+1] = pk[i+1];
    }
    pk += DIL_SEEDBYTES;

    for(i = 0; i < conf->k; i += 2) {
        polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
        polyt1_unpack(&t1->vec[i+1], pk + (i+1) * POLYT1_PACKEDBYTES);
    }
}

/* ========================================================================== *
 * SIGNATURE PACKING
 * ========================================================================== */

void pack_sig(uint8_t sig[], const uint8_t c[], const polyvecl *z, const polyveck *h, const dilithium_conf_t *conf) {
    unsigned int i, j, k;

    // conf->ctildebytes (32, 48, 64) è sempre pari
    for(i = 0; i < conf->ctildebytes; i += 2) {
        sig[i]   = c[i];
        sig[i+1] = c[i+1];
    }
    sig += conf->ctildebytes;

    // conf->l (4, 5, 7) può essere dispari: usiamo limite pari + coda
    unsigned int l_even = conf->l & ~1U;
    for(i = 0; i < l_even; i += 2) {
        polyz_pack(sig + i * conf->polyz_packed, &z->vec[i], conf);
        polyz_pack(sig + (i+1) * conf->polyz_packed, &z->vec[i+1], conf);
    }
    if(conf->l & 1) { // Gestione dell'eventuale elemento dispari finale
        polyz_pack(sig + i * conf->polyz_packed, &z->vec[i], conf);
    }
    sig += conf->l * conf->polyz_packed;

    // Azzeramento array hint: (omega + k) può essere dispari
    unsigned int om_k_even = (conf->omega + conf->k) & ~1U;
    for(i = 0; i < om_k_even; i += 2) {
        sig[i]   = 0;
        sig[i+1] = 0;
    }
    if((conf->omega + conf->k) & 1) {
        sig[i] = 0;
    }

    // Codifica Hint (h) - Unroll sul loop interno lungo (DIL_N = 256, pari)
    k = 0;
    for(i = 0; i < conf->k; ++i) {
        for(j = 0; j < DIL_N; j += 2) {
            if(h->vec[i].coeffs[j] != 0)   sig[k++] = j;
            if(h->vec[i].coeffs[j+1] != 0) sig[k++] = j+1;
        }
        sig[conf->omega + i] = k;
    }
}

int unpack_sig(uint8_t c[], polyvecl *z, polyveck *h, const uint8_t sig[], const dilithium_conf_t *conf) {
    unsigned int i, j, k;

    for(i = 0; i < conf->ctildebytes; i += 2) {
        c[i]   = sig[i];
        c[i+1] = sig[i+1];
    }
    sig += conf->ctildebytes;

    // conf->l può essere dispari
    unsigned int l_even = conf->l & ~1U;
    for(i = 0; i < l_even; i += 2) {
        polyz_unpack(&z->vec[i], sig + i * conf->polyz_packed, conf);
        polyz_unpack(&z->vec[i+1], sig + (i+1) * conf->polyz_packed, conf);
    }
    if(conf->l & 1) {
        polyz_unpack(&z->vec[i], sig + i * conf->polyz_packed, conf);
    }
    sig += conf->l * conf->polyz_packed;

    // Decodifica Hint (loop stretti e data-dependent, srotolare qui abbatterebbe le performance)
    k = 0;
    for(i = 0; i < conf->k; ++i) {
        memset(h->vec[i].coeffs, 0, DIL_N * sizeof(int32_t));

        if(sig[conf->omega + i] < k || sig[conf->omega + i] > conf->omega) {
            return 1;
        }

        for(j = k; j < sig[conf->omega + i]; ++j) {
            if(j > k && sig[j] <= sig[j-1]) return 1;
            h->vec[i].coeffs[sig[j]] = 1;
        }
        k = sig[conf->omega + i];
    }

    // Check padding - conf->omega può essere dispari
    unsigned int omega_even = conf->omega & ~1U;
    for(j = k; j < omega_even; j += 2) {
        if(sig[j] || sig[j+1]) return 1;
    }
    for(; j < conf->omega; ++j) {
        if(sig[j]) return 1;
    }

    return 0;
}

/* ========================================================================== *
 * SECRET KEY PACKING
 * ========================================================================== */

void pack_sk(uint8_t sk[], const uint8_t rho[DIL_SEEDBYTES], const uint8_t tr[DIL_TRBYTES],
             const uint8_t key[DIL_SEEDBYTES], const polyveck *t0, const polyvecl *s1,
             const polyveck *s2, const dilithium_conf_t *conf)
{
    unsigned int i;

    for(i = 0; i < DIL_SEEDBYTES; i += 2) { sk[i] = rho[i]; sk[i+1] = rho[i+1]; }
    sk += DIL_SEEDBYTES;

    for(i = 0; i < DIL_SEEDBYTES; i += 2) { sk[i] = key[i]; sk[i+1] = key[i+1]; }
    sk += DIL_SEEDBYTES;

    // DIL_TRBYTES (64) è sempre pari
    for(i = 0; i < DIL_TRBYTES; i += 2) { sk[i] = tr[i]; sk[i+1] = tr[i+1]; }
    sk += DIL_TRBYTES;

    unsigned int l_even = conf->l & ~1U;
    for(i = 0; i < l_even; i += 2) {
        polyeta_pack(sk + i * conf->polyeta_packed, &s1->vec[i], conf);
        polyeta_pack(sk + (i+1) * conf->polyeta_packed, &s1->vec[i+1], conf);
    }
    if(conf->l & 1) polyeta_pack(sk + i * conf->polyeta_packed, &s1->vec[i], conf);
    sk += conf->l * conf->polyeta_packed;

    for(i = 0; i < conf->k; i += 2) {
        polyeta_pack(sk + i * conf->polyeta_packed, &s2->vec[i], conf);
        polyeta_pack(sk + (i+1) * conf->polyeta_packed, &s2->vec[i+1], conf);
    }
    sk += conf->k * conf->polyeta_packed;

    for(i = 0; i < conf->k; i += 2) {
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
        polyt0_pack(sk + (i+1) * POLYT0_PACKEDBYTES, &t0->vec[i+1]);
    }
}

void unpack_sk(uint8_t rho[DIL_SEEDBYTES], uint8_t tr[DIL_TRBYTES], uint8_t key[DIL_SEEDBYTES],
               polyveck *t0, polyvecl *s1, polyveck *s2, const uint8_t sk[], const dilithium_conf_t *conf)
{
    unsigned int i;

    for(i = 0; i < DIL_SEEDBYTES; i += 2) { rho[i] = sk[i]; rho[i+1] = sk[i+1]; }
    sk += DIL_SEEDBYTES;

    for(i = 0; i < DIL_SEEDBYTES; i += 2) { key[i] = sk[i]; key[i+1] = sk[i+1]; }
    sk += DIL_SEEDBYTES;

    for(i = 0; i < DIL_TRBYTES; i += 2) { tr[i] = sk[i]; tr[i+1] = sk[i+1]; }
    sk += DIL_TRBYTES;

    unsigned int l_even = conf->l & ~1U;
    for(i=0; i < l_even; i += 2) {
        polyeta_unpack(&s1->vec[i], sk + i * conf->polyeta_packed, conf);
        polyeta_unpack(&s1->vec[i+1], sk + (i+1) * conf->polyeta_packed, conf);
    }
    if(conf->l & 1) polyeta_unpack(&s1->vec[i], sk + i * conf->polyeta_packed, conf);
    sk += conf->l * conf->polyeta_packed;

    for(i=0; i < conf->k; i += 2) {
        polyeta_unpack(&s2->vec[i], sk + i * conf->polyeta_packed, conf);
        polyeta_unpack(&s2->vec[i+1], sk + (i+1) * conf->polyeta_packed, conf);
    }
    sk += conf->k * conf->polyeta_packed;

    for(i=0; i < conf->k; i += 2) {
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
        polyt0_unpack(&t0->vec[i+1], sk + (i+1) * POLYT0_PACKEDBYTES);
    }
}
