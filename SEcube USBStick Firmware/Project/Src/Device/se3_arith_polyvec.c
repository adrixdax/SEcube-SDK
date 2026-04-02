#include <stdint.h>
#include <stddef.h>
#include "se3_arith_polyvec.h"
#include "se3_core.h"

#define DIL_Q 8380417
#define DIL_QINV 58728449

/* Funzione inline per la riduzione Montgomery veloce a 64 bit usata in Pointwise_Acc */
static inline int32_t internal_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)a * DIL_QINV;
    t = (a - (int64_t)t * DIL_Q) >> 32;
    return t;
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza L                                         */
/* ========================================================================== */

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_uniform_eta(&v->vec[i], seed, nonce++, conf);
    }
}

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
    unsigned int i;
    uint16_t base_nonce = conf->l * nonce;
    for(i = 0; i < conf->l; ++i) {
        poly_uniform_gamma1(&v->vec[i], seed, base_nonce + i, conf);
    }
}

void polyvecl_reduce(polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_reduce(&v->vec[i]);
    }
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyvecl_ntt(polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_ntt(&v->vec[i]);
    }
}

void polyvecl_invntt_tomont(polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_invntt_tomont(&v->vec[i]);
    }
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i, j;
    for(i = 0; i < DIL_N; ++i) {
        int64_t t = 0;
        for(j = 0; j < conf->l; ++j) {
            // montgomery_reduce su ogni prodotto, non sull'accumulato
            t += internal_montgomery_reduce((int64_t)u->vec[j].coeffs[i] * v->vec[j].coeffs[i]);
        }
        w->coeffs[i] = (int32_t)t;
    }
}

int polyvecl_chknorm(const polyvecl *v, int32_t bound, const dilithium_conf_t *conf) {
    if (conf == NULL || v == NULL) return 1;
    unsigned int i;
    uint32_t t = 0;
    for(i = 0; i < conf->l; ++i) {
        t |= (uint32_t)poly_chknorm(&v->vec[i], bound);
    }
    return (t != 0) ? 1 : 0;
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza K                                         */
/* ========================================================================== */

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_uniform_eta(&v->vec[i], seed, nonce++, conf);
    }
}

void polyveck_reduce(polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_reduce(&v->vec[i]);
    }
}

void polyvecl_caddq(polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->l; ++i) {
        poly_caddq(&v->vec[i]);
    }
}

void polyveck_caddq(polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_caddq(&v->vec[i]);
    }
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void polyveck_shiftl(polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_shiftl(&v->vec[i]);
    }
}

void polyveck_ntt(polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_ntt(&v->vec[i]);
    }
}

void polyveck_invntt_tomont(polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_invntt_tomont(&v->vec[i]);
    }
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int polyveck_chknorm(const polyveck *v, int32_t bound, const dilithium_conf_t *conf) {
    if (conf == NULL || v == NULL) return 1;
    unsigned int i;
    uint32_t t = 0;
    for(i = 0; i < conf->k; ++i) {
        t |= (uint32_t)poly_chknorm(&v->vec[i], bound);
    }
    return (t != 0) ? 1 : 0;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i], conf);
    }
}

unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1, const dilithium_conf_t *conf) {
    unsigned int i, s = 0;
    for(i = 0; i < conf->k; ++i) {
        s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i], conf);
    }
    return s;
}

void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i], conf);
    }
}

void polyveck_pack_w1(uint8_t *r, const polyveck *w1, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        polyw1_pack(&r[i * conf->polyw1_packed], &w1->vec[i], conf);
    }
}

/* ========================================================================== */
/* Operazioni sulle Matrici (ExpandA & Moltiplicazione)                       */
/* ========================================================================== */

void polyvec_matrix_expand(polyvecl mat[DIL_K_MAX], const uint8_t rho[DIL_SEEDBYTES], const dilithium_conf_t *conf) {
    unsigned int r, s; // Uso i nomi del NIST per non sbagliare
    for(r = 0; r < conf->k; ++r) {
        for(s = 0; s < conf->l; ++s) {
            uint16_t nonce = (uint16_t)((s << 8) | r);
            poly_uniform(&mat[r].vec[s], rho, nonce);
        }
    }
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DIL_K_MAX], const polyvecl *v, const dilithium_conf_t *conf) {
    unsigned int i;
    for(i = 0; i < conf->k; ++i) {
        polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v, conf);
    }
}
