/**
  ******************************************************************************
  * File Name          : se3_arith_polyvec.c
  * Description        : Implementazione vettoriale. Eredita le performance
  * dal livello base se3_arith_poly.
  ******************************************************************************
  */

#include <stdint.h>
#include "se3_arith_polyvec.h"

/* ========================================================================== */
/* Operazioni sulle Matrici (ExpandA)                                         */
/* ========================================================================== */

void polyvec_matrix_expand(polyvecl mat[DIL_K], const uint8_t rho[DIL_SEEDBYTES]) {
  unsigned int i, j;
  for(i = 0; i < DIL_K; ++i) {
    for(j = 0; j < DIL_L; ++j) {
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DIL_K], const polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i) {
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
  }
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza L                                         */
/* ========================================================================== */

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, DIL_L * nonce + i);
}

void polyvecl_reduce(polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_reduce(&v->vec[i]);
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyvecl_ntt(polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v) {
  unsigned int i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < DIL_L; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

int polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
  unsigned int i;
  for(i = 0; i < DIL_L; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;
  return 0;
}

/* ========================================================================== */
/* Vettori di Polinomi di lunghezza K                                         */
/* ========================================================================== */

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyveck_reduce(polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_reduce(&v->vec[i]);
}

void polyveck_caddq(polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_caddq(&v->vec[i]);
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyveck_shiftl(polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_shiftl(&v->vec[i]);
}

void polyveck_ntt(polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_ntt(&v->vec[i]);
}

void polyveck_invntt_tomont(polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

int polyveck_chknorm(const polyveck *v, int32_t bound) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;
  return 0;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1) {
  unsigned int i, s = 0;
  for(i = 0; i < DIL_K; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
  return s;
}

void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(uint8_t r[DIL_K * DIL_POLYW1_PACKEDBYTES], const polyveck *w1) {
  unsigned int i;
  for(i = 0; i < DIL_K; ++i)
    polyw1_pack(&r[i * DIL_POLYW1_PACKEDBYTES], &w1->vec[i]);
}

static uint8_t op_counter = 0; // Persistente tra le chiamate
static polyveck u_bench, v_bench, w_bench;

uint16_t se3_algo_polyvec_bench_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
  // Nessun contesto persistente necessario per il benchmark
  return SE3_OK;
}

uint16_t se3_algo_polyvec_bench_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout)
{
  // 1. Validazione parametri e buffer
  if (datain1_len < (DIL_K * 1024) || dataout == NULL) return SE3_ERR_PARAMS;

  // Caricamento dei dati dal client (Host)
  memcpy(u_bench.vec, datain1, DIL_K * 1024);
  memcpy(v_bench.vec, u_bench.vec, DIL_K * 1024);

  uint32_t t_op = 0;

  // 2. Abilitazione sicura del contatore di cicli
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

  // 3. Esecuzione dell'operazione basata sul contatore
  __disable_irq();
  DWT->CYCCNT = 0; // Azzeramento immediato prima dello switch

  switch(op_counter) {
    case 0: polyveck_add(&w_bench, &u_bench, &v_bench); break;
    case 1: polyveck_sub(&w_bench, &u_bench, &v_bench); break;
    case 2: polyveck_reduce(&u_bench); break;
    case 3: polyveck_caddq(&u_bench); break;
    case 4: polyveck_ntt(&u_bench); break;
    case 5:polyveck_invntt_tomont(&u_bench);break;
    case 6: polyveck_shiftl(&u_bench); break;
    default: op_counter = 0; break;
  }

  t_op = DWT->CYCCNT; // Cattura immediata dopo l'operazione
  __enable_irq();

  // 4. Copia dei risultati nel buffer di uscita
  if (op_counter <= 1) {
    memcpy(dataout, w_bench.vec, DIL_K * 1024);
  } else {
    memcpy(dataout, u_bench.vec, DIL_K * 1024);
  }

  // 5. Gestione dei Tick di performance (sempre a 4124 byte totali)
  // Scriviamo il tick dell'operazione corrente
  memcpy(dataout + (DIL_K * 1024), &t_op, 4);

  // Opzionale: azzera i restanti 24 byte dei tick per pulizia
  memset(dataout + (DIL_K * 1024) + 4, 0, 24);

  // Incremento circolare del contatore
  op_counter = (op_counter + 1) % 7;

  // Restituiamo 4124 byte (4096 dati + 28 tick) come richiesto dall'Host
  if (dataout_len) *dataout_len = (DIL_K * 1024) + 28;

  return SE3_OK;
}
