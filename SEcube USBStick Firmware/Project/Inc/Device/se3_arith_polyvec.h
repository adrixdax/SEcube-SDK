#include <stdint.h>
#include "se3_algo_dilithium_params.h"
#include "se3_arith_poly.h"

/* Vettori di polinomi di lunghezza L (usiamo il MAX per la RAM) */
typedef struct {
  poly vec[DIL_L_MAX]; // <-- Modificato da DIL_L
} polyvecl;

/* Aggiungiamo 'conf' alle firme per dire alla funzione quanto è grande 'l' */
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf);
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf);
void polyvecl_reduce(polyvecl *v, const dilithium_conf_t *conf);
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf);
void polyvecl_ntt(polyvecl *v, const dilithium_conf_t *conf);
void polyvecl_invntt_tomont(polyvecl *v, const dilithium_conf_t *conf);
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v, const dilithium_conf_t *conf);
void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v, const dilithium_conf_t *conf);
int polyvecl_chknorm(const polyvecl *v, int32_t bound, const dilithium_conf_t *conf);

/* Vettori di polinomi di lunghezza K (usiamo il MAX per la RAM) */
typedef struct {
  poly vec[DIL_K_MAX]; // <-- Modificato da DIL_K
} polyveck;

/* Stesso discorso per le funzioni che iterano su K */
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf);
void polyveck_reduce(polyveck *v, const dilithium_conf_t *conf);
void polyveck_caddq(polyveck *v, const dilithium_conf_t *conf);
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v, const dilithium_conf_t *conf);
void polyveck_shiftl(polyveck *v, const dilithium_conf_t *conf);
void polyveck_ntt(polyveck *v, const dilithium_conf_t *conf);
void polyveck_invntt_tomont(polyveck *v, const dilithium_conf_t *conf);
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v, const dilithium_conf_t *conf);
int polyveck_chknorm(const polyveck *v, int32_t bound, const dilithium_conf_t *conf);
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v, const dilithium_conf_t *conf);
unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1, const dilithium_conf_t *conf);
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h, const dilithium_conf_t *conf);

/* NOTA: Rimuoviamo la dimensione fissa dall'array 'r' e passiamo 'conf' */
void polyveck_pack_w1(uint8_t *r, const polyveck *w1, const dilithium_conf_t *conf);

/* Operazioni sulle Matrici (Anche qui sostituiamo gli array fissi) */
void polyvec_matrix_expand(polyvecl mat[DIL_K_MAX], const uint8_t rho[DIL_SEEDBYTES], const dilithium_conf_t *conf);
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DIL_K_MAX], const polyvecl *v, const dilithium_conf_t *conf);



uint16_t se3_algo_polyvec_bench_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);

uint16_t se3_algo_polyvec_bench_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);
