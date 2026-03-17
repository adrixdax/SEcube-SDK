/**
  ******************************************************************************
  * File Name          : se3_arith_polyvec.c
  * Description        : Implementazione vettoriale dinamica.
  * I cicli sono pilotati dalla struttura dilithium_conf_t passata a runtime.
  ******************************************************************************
  */

#include <stdint.h>
#include <string.h>
#include "se3_arith_polyvec.h"
#include "se3_core.h"

/* ========================================================================== */
/* Operazioni sulle Matrici (ExpandA)                                         */
/* ========================================================================== */

void polyvec_matrix_expand(polyvecl mat[DIL_K_MAX], const uint8_t rho[DIL_SEEDBYTES], const dilithium_conf_t *conf) {
  unsigned int i, j;
  for(i = 0; i < conf->k; ++i) {
    for(j = 0; j < conf->l; ++j) {
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j); // poly_uniform non dipende dal livello
    }
  }
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DIL_K_MAX], const polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i) {
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v, conf);
  }
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza L                                         */
/* ========================================================================== */

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++, conf);
}

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, conf->l * nonce + i, conf);
}

void polyvecl_reduce(polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_reduce(&v->vec[i]);
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyvecl_ntt(polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf) {
  unsigned int i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < conf->l; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

int polyvecl_chknorm(const polyvecl *v, int32_t bound, const dilithium_conf_t *conf)  {
  unsigned int i;
  for(i = 0; i < conf->l; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;
  return 0;
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza K                                         */
/* ========================================================================== */

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++, conf);
}

void polyveck_reduce(polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_reduce(&v->vec[i]);
}

void polyveck_caddq(polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_caddq(&v->vec[i]);
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_shiftl(polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_shiftl(&v->vec[i]);
}

void polyveck_ntt(polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_ntt(&v->vec[i]);
}

void polyveck_invntt_tomont(polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

int polyveck_chknorm(const polyveck *v, int32_t bound, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;
  return 0;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i], conf);
}

unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1, const dilithium_conf_t *conf) {
  unsigned int i, s = 0;
  for(i = 0; i < conf->k; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i], conf);
  return s;
}

void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i],conf);
}

void polyveck_pack_w1(uint8_t *r, const polyveck *w1, const dilithium_conf_t *conf) {
  unsigned int i;
  for(i = 0; i < conf->k; ++i)
    polyw1_pack(&r[i * conf->polyw1_packed], &w1->vec[i], conf);
}

