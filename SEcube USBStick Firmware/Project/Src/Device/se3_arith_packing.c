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

void pack_pk(uint8_t pk[], const uint8_t rho[DIL_SEEDBYTES],
             const polyveck *t1, const dilithium_conf_t *conf) {
    memcpy(pk, rho, DIL_SEEDBYTES);
    pk += DIL_SEEDBYTES;
    for (unsigned int i = 0; i < conf->k; ++i)
        polyt1_pack(pk + i * 320, &t1->vec[i]);
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

void pack_sig(uint8_t * __restrict__ sig,
              const uint8_t *c,
              const polyvecl * __restrict__ z,
              const polyveck * __restrict__ h,
              const dilithium_conf_t *conf) {
    memcpy(sig, c, conf->ctildebytes);
    sig += conf->ctildebytes;
    for (unsigned int i = 0; i < conf->l; ++i)
        polyz_pack(sig + i * conf->polyz_packed, &z->vec[i], conf);
    sig += conf->l * conf->polyz_packed;
    memset(sig, 0, conf->omega + conf->k);
    unsigned int k = 0;
    for (unsigned int i = 0; i < conf->k; ++i) {
        const int32_t * __restrict__ coeffs = h->vec[i].coeffs;
        for (unsigned int j = 0; j < DIL_N; ++j) {
            if (coeffs[j] != 0) {
                if (k >= conf->omega) return;
                sig[k++] = (uint8_t)j;
            }
        }
        sig[conf->omega + i] = (uint8_t)k;
    }
}

int unpack_sig(uint8_t c[], polyvecl *z, polyveck *h, const uint8_t sig[], const dilithium_conf_t *conf) {
    unsigned int i, j, k;
    if (!sig || !c || !z || !h || !conf) {
        return 1;
    }
    for(i = 0; i < conf->ctildebytes; ++i) {
        c[i] = sig[i];
    }
    for(i = 0; i < conf->l; ++i) {
        polyz_unpack(&z->vec[i],
                     sig + conf->ctildebytes + i * conf->polyz_packed,
                     conf);
    }
    k = 0;
    const uint8_t *sig_hints = sig + conf->ctildebytes + conf->l * conf->polyz_packed;
    for(i = 0; i < conf->k; ++i) {
        memset(h->vec[i].coeffs, 0, DIL_N * sizeof(int32_t));
        uint8_t limit = sig_hints[conf->omega + i];
        if(limit < k || limit > conf->omega) {
            return 1;
        }
        if(limit - k > DIL_N) {
            return 1;
        }

        uint8_t prev_idx = 0;
        int first_in_poly = 1;
        for(j = k; j < limit; ++j) {
            uint8_t idx = sig_hints[j];

            /* Bounds check: indice deve essere un coefficiente valido */
            if(idx >= DIL_N) {
                return 1;
            }

            /*
             * Ordine strettamente crescente degli indici all'interno
             * dello stesso polinomio.
             * FIX: confronta idx con prev_idx (indice del coeff precedente),
             * non con sig_hints[j-1] (byte precedente nell'array, che
             * all'inizio di ogni polinomio è il campo `limit`).
             */
            if(!first_in_poly && idx <= prev_idx) {
                return 1;
            }

            h->vec[i].coeffs[idx] = 1;
            prev_idx = idx;
            first_in_poly = 0;
        }
        k = limit;
    }

    /* 4. Controllo Padding: i byte da k a omega-1 devono essere zero */
    for(j = k; j < conf->omega; ++j) {
        if(sig_hints[j] != 0) {
            return 1;
        }
    }

    return 0;
}

/* ========================================================================== *
 * SECRET KEY PACKING
 * ========================================================================== */

void pack_sk(uint8_t * __restrict__ sk,
             const uint8_t rho[DIL_SEEDBYTES],
             const uint8_t tr[DIL_TRBYTES],
             const uint8_t key[DIL_SEEDBYTES],
             const polyveck * __restrict__ t0,
             const polyvecl * __restrict__ s1,
             const polyveck * __restrict__ s2,
             const dilithium_conf_t *conf) {
    // 1. Loop manuali → memcpy
    memcpy(sk, rho, DIL_SEEDBYTES); sk += DIL_SEEDBYTES;
    memcpy(sk, key, DIL_SEEDBYTES); sk += DIL_SEEDBYTES;
    memcpy(sk, tr,  DIL_TRBYTES);   sk += DIL_TRBYTES;

    // 2. Loop s1 — rimosso unrolling manuale (il compilatore lo fa meglio)
    for (unsigned int i = 0; i < conf->l; ++i)
        polyeta_pack(sk + i * conf->polyeta_packed, &s1->vec[i], conf);
    sk += conf->l * conf->polyeta_packed;

    // 3. Loop s2 — aveva bug: se k dispari andava OOB
    for (unsigned int i = 0; i < conf->k; ++i)
        polyeta_pack(sk + i * conf->polyeta_packed, &s2->vec[i], conf);
    sk += conf->k * conf->polyeta_packed;

    for (unsigned int i = 0; i < conf->k; ++i)
        polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
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
    for(i = 0; i < l_even; i += 2) {
        polyeta_unpack(&s1->vec[i], sk + i * conf->polyeta_packed, conf);
        polyeta_unpack(&s1->vec[i+1], sk + (i+1) * conf->polyeta_packed, conf);
    }
    if(conf->l & 1) polyeta_unpack(&s1->vec[i], sk + i * conf->polyeta_packed, conf);
    sk += conf->l * conf->polyeta_packed;

    for(i = 0; i < conf->k; i += 2) {
        polyeta_unpack(&s2->vec[i], sk + i * conf->polyeta_packed, conf);
        polyeta_unpack(&s2->vec[i+1], sk + (i+1) * conf->polyeta_packed, conf);
    }
    sk += conf->k * conf->polyeta_packed;

    for(i = 0; i < conf->k; i += 2) {
        polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
        polyt0_unpack(&t0->vec[i+1], sk + (i+1) * POLYT0_PACKEDBYTES);
    }
}