#include "se3_arith_ntt.h"
#include "se3_algo_dilithium_params.h"
#include "se3_core.h"
#include "se3_security_core.h"
#include "Keccak.h"
/**
 * @brief Struttura base del polinomio per Dilithium.
 * L'allineamento a 8 byte è cruciale sul Cortex-M4 per permettere 
 * al compilatore di usare istruzioni di caricamento doppio (LDRD/STRD).
 */
typedef struct {
    int32_t coeffs[DIL_N] __attribute__((aligned(8)));
} poly;

/* ========================================================================= *
 * Funzioni di Aritmetica Polinomiale (Ottimizzate Cortex-M4)
 * ========================================================================= */
void poly_reduce(poly *a);
void poly_caddq(poly *a);
void poly_shiftl(poly *a);

/* L'uso di __restrict__ garantisce al compilatore che i puntatori non si 
 * sovrappongano (aliasing), permettendo srotolamenti più aggressivi. */
void poly_add(poly * __restrict__ c, const poly * __restrict__ a, const poly * __restrict__ b);
void poly_sub(poly * __restrict__ c, const poly * __restrict__ a, const poly * __restrict__ b);

/* ========================================================================= *
 * Trasformazioni NTT
 * ========================================================================= */
void poly_ntt(poly *a);
void poly_invntt_tomont(poly *a);
void poly_pointwise_montgomery(poly * __restrict__ c, const poly * __restrict__ a, const poly * __restrict__ b);

/* ========================================================================= *
 * Funzioni di Hashing, Arrotondamento e Hint
 * ========================================================================= */
void poly_power2round(poly *a1, poly *a0, const poly *a);
void poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int poly_make_hint(poly * __restrict__ h, const poly * __restrict__ a0, const poly * __restrict__ a1);
void poly_use_hint(poly *b, const poly *a, const poly *h);

/* ========================================================================= *
 * Funzioni di Campionamento e Controllo (Rejection Sampling)
 * ========================================================================= */
int poly_chknorm(const poly *a, int32_t B);
void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);

void poly_uniform(poly *a, const uint8_t seed[DIL_SEEDBYTES], uint16_t nonce);
void poly_uniform_eta(poly *a, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce);
void poly_uniform_gamma1(poly *a, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce);

unsigned int rej_eta(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen);
unsigned int rej_uniform(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen);

/* ========================================================================= *
 * Funzioni di Compressione e Decompressione (Packing/Unpacking)
 * ========================================================================= */
void polyt1_pack(uint8_t *r, const poly *a);
void polyt1_unpack(poly *a, const uint8_t *r);

void polyt0_pack(uint8_t *r, const poly *a);
void polyt0_unpack(poly *a, const uint8_t *r);

void polyeta_pack(uint8_t *r, const poly *a);
void polyeta_unpack(poly *a, const uint8_t *r);

void polyz_pack(uint8_t *r, const poly *a);
void polyz_unpack(poly *a, const uint8_t *r);

void polyw1_pack(uint8_t * __restrict__ r, const poly * __restrict__ a);
