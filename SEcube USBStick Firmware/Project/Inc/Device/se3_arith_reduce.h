#include <stdint.h>
#include "se3_algo_dilithium_params.h"

/* Riduzione di Montgomery in-linea a 64-bit */
__attribute__((always_inline)) static inline int32_t montgomery_reduce(int64_t a) {
		int32_t m = (int32_t)a * (int32_t)DIL_QINV; // Q_INV deve essere definito come 58728449
	    int64_t r = a + (int64_t)m * DIL_Q;
	    return (int32_t)(r >> 32);
	}

/* Riduzione a 32-bit (sfrutta istruzione MLS del Cortex-M4) */
__attribute__((always_inline)) static inline int32_t reduce32(int32_t a) {
    int32_t t = (a + 4194304) >> 23;
    return a - t * DIL_Q;
}

/* Somma condizionale di Q */
__attribute__((always_inline)) static inline int32_t caddq(int32_t a) {
    a += (a >> 31) & DIL_Q;
    return a;
}

/* Arrotondamenti e scomposizioni per Dilithium */
static inline int32_t power2round(int32_t *a0, int32_t a) {
    int32_t a1 = (a + (1 << (DIL_D-1)) - 1) >> DIL_D;
    *a0 = a - (a1 << DIL_D);
    return a1;
}

static inline int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1 = (a + 127) >> 7;
#if GAMMA2 == (Q-1)/32
    a1  = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
#elif GAMMA2 == (Q-1)/88
    a1  = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
#endif
    *a0  = a - a1*2*GAMMA2;
    *a0 -= (((GAMMA2 - 1) - *a0) >> 31) & DIL_Q;
    return a1;
}

static inline unsigned int make_hint(int32_t a0, int32_t a1) {
    if(a0 <= GAMMA2 || a0 > DIL_Q - GAMMA2 || (a0 == DIL_Q - GAMMA2 && a1 == 0))
        return 0;
    return 1;
}

static inline int32_t use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;
    a1 = decompose(&a0, a);
    if(hint == 0) return a1;
#if GAMMA2 == (Q-1)/32
    if(a0 > 0) return (a1 + 1) & 15;
    return (a1 - 1) & 15;
#elif GAMMA2 == (Q-1)/88
    if(a0 > 0) return (a1 == 43) ?  0 : a1 + 1;
    return (a1 ==  0) ? 43 : a1 - 1;
#endif
}
