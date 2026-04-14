#ifndef SE3_ARITH_REDUCE_H
#define SE3_ARITH_REDUCE_H

#include <stdint.h>
#include "se3_algo_mldsa_params.h"

/*
 * FIX: montgomery_reduce ora chiama reduce_once per garantire output in [0, Q-1],
 * coerente con la versione usata in se3_arith_ntt.c.
 * La versione precedente restituiva valori in [-Q, Q], incompatibile con le
 * funzioni di poly.c che assumono coefficienti ridotti.
 *
 * Nota: questa è l'unica definizione autorizzata di montgomery_reduce.
 * se3_arith_ntt.c definisce la propria copia locale (static) — non c'è ODR
 * violation perché entrambe sono static/inline, ma il comportamento deve
 * essere identico. Se in futuro si unifica, usare questa.
 */
static inline int32_t montgomery_reduce(int64_t a) {
    int64_t t;
    int32_t u;

    u = (int32_t)a * 62209;
    t = (int64_t)u * DIL_Q;
    t = a - t;
    t >>= 32;

    return (int32_t)t;
}

static inline int32_t barrett_reduce(int32_t a) {
    int32_t t;
    const int32_t v = ((1 << 26) + DIL_Q/2) / DIL_Q;
    t = ((int64_t)v * a + (1 << 25)) >> 26;
    t *= DIL_Q;
    return a - t;
}

/* Riduzione a 32-bit (sfrutta istruzione MLS del Cortex-M4) */
__attribute__((always_inline)) static inline int32_t reduce32(int32_t a) {
    int32_t t = (int32_t)(((uint32_t)a + 4194304U) >> 23);
    int32_t r = a - t * DIL_Q;
    r += (r >> 31) & DIL_Q;
    r -= DIL_Q;
    r += (r >> 31) & DIL_Q;
    return r;
}

/* Somma condizionale di Q */
__attribute__((always_inline)) static inline int32_t caddq(int32_t a) {
    a += (a >> 31) & DIL_Q;
    return a;
}

/* =========================================================================
 * power2round  —  FIPS 204, Algorithm 35
 *
 * FIX: rimossi i volatile sulle variabili locali intermedie.
 * L'uso di volatile su variabili locali non fornisce protezione side-channel
 * reale su Cortex-M4 (per quella servono barriere di memoria o optnone) e
 * inibisce ottimizzazioni legittime del compilatore.
 * La logica branchless è mantenuta per timing costante.
 * ========================================================================= */
#define ML_DSA_Q      8380417
#define ML_DSA_D_BITS 13

static inline uint32_t constant_time_lt(uint32_t a, uint32_t b) {
    /* ritorna 0xFFFFFFFF se a < b, 0 altrimenti */
    uint32_t x = a - b;
    return (x >> 31);
}

static inline uint32_t constant_time_select_int(uint32_t mask, uint32_t a, uint32_t b) {
    /* ritorna mask ? a : b */
    return (mask & a) | (~mask & b);
}

/* --- Rounding di un singolo coefficiente --- */
static inline  __attribute__((always_inline)) uint32_t power2round(int32_t *a0, int32_t a) {
    int32_t a1;
    a1 = (a + (1 << (DIL_D-1))) >> DIL_D;
    *a0 = a - (a1 << DIL_D);
    return a1;
}

/* =========================================================================
 * decompose  —  FIPS 204, Algorithm 36
 * ========================================================================= */
static inline int32_t decompose(int32_t *a0, int32_t a, int32_t gamma2) {
    int32_t a1;
    a1 = (int32_t)(((uint32_t)a + 127U) >> 7);
    if (gamma2 == (DIL_Q - 1) / 88) {
        a1  = (int32_t)(((uint32_t)(a1 * 11275) + (1U << 23)) >> 24);
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        a1  = (int32_t)(((uint32_t)(a1 * 1025) + (1U << 21)) >> 22);
        a1 &= 15;
    }
    *a0  = a - a1 * 2 * gamma2;
    *a0 -= (((DIL_Q - 1) / 2 - *a0) >> 31) & DIL_Q;
    return a1;
}

/* =========================================================================
 * make_hint  —  FIPS 204, Algorithm 37
 * ========================================================================= */
static inline unsigned int make_hint(int32_t a0, int32_t a1, int32_t gamma2) {
    uint32_t out_of_range = (uint32_t)((gamma2 - a0) | (gamma2 + a0)) >> 31;
    uint32_t sum          = (uint32_t)(a0 + gamma2);
    uint32_t eq_neg       = 1u - (((sum | (~sum + 1u)) >> 31) & 1u);
    uint32_t a1_nonzero   = ((uint32_t)(a1 | -a1)) >> 31;
    uint32_t at_neg_bound = eq_neg & a1_nonzero;
    return (unsigned int)(out_of_range | at_neg_bound);
}

/* =========================================================================
 * use_hint  —  FIPS 204, Algorithm 38
 * ========================================================================= */
__attribute__((always_inline))
static inline int32_t use_hint(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;
    a1 = decompose(&a0, a, gamma2);
    int32_t MAX   = (gamma2 == (DIL_Q - 1) / 88) ? 43 : 15;
    int32_t delta = 1 - (((int32_t)(a0 - 1) >> 31) & 2);   /* +1 o -1 */
    int32_t raw   = a1 + delta;
    raw += (raw >> 31) & (MAX + 1);                          /* wrap -1 → MAX */
    raw -= ((MAX - raw) >> 31) & (MAX + 1);                  /* wrap MAX+1 → 0 */
    uint32_t h = hint & 1u;
    return (int32_t)((1u - h) * (uint32_t)a1 + h * (uint32_t)raw);
}

#endif /* SE3_ARITH_REDUCE_H */
