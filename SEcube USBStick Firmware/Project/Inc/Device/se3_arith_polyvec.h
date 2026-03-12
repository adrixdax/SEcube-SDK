/**
  ******************************************************************************
  * File Name          : se3_arith_polyvec.h
  * Description        : Definizioni per i vettori di polinomi (PolyVec)
  ******************************************************************************
  */

#include <stdint.h>
#include "se3_algo_dilithium_params.h"
#include "se3_arith_poly.h"

/* Vettori di polinomi di lunghezza L (usati per s1, y, z, ecc.) */
typedef struct {
  poly vec[DIL_L];
} polyvecl;

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce);
void polyvecl_reduce(polyvecl *v);
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_tomont(polyvecl *v);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v);
int polyvecl_chknorm(const polyvecl *v, int32_t bound);

/* Vettori di polinomi di lunghezza K (usati per t0, t1, w, s2, ecc.) */
typedef struct {
  poly vec[DIL_K];
} polyveck;

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce);
void polyveck_reduce(polyveck *v);
void polyveck_caddq(polyveck *v);
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_shiftl(polyveck *v);
void polyveck_ntt(polyveck *v);
void polyveck_invntt_tomont(polyveck *v);
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
int polyveck_chknorm(const polyveck *v, int32_t bound);
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1);
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h);
void polyveck_pack_w1(uint8_t r[DIL_K * DIL_POLYW1_PACKEDBYTES], const polyveck *w1);

/* Operazioni sulle Matrici */
void polyvec_matrix_expand(polyvecl mat[DIL_K], const uint8_t rho[DIL_SEEDBYTES]);
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DIL_K], const polyvecl *v);
