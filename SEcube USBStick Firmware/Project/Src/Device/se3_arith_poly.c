#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "se3_arith_poly.h"

#include "se3_arith_reduce.h"
#include "se3_algo_shake.h"
#include "se3_algo_mldsa_symmetric.h"
#include "Keccak.h"



/* ========================================================================= *
 * Funzioni di Hashing, Arrotondamento e Hint
 * ========================================================================= */

/* In se3_arith_poly.c */

void poly_center_inplace(poly *a) {
    for (int i = 0; i < DIL_N; i++) {
        int32_t v = a->coeffs[i] % DIL_Q;
        if (v > (DIL_Q / 2)) v -= DIL_Q;
        else if (v < -(DIL_Q / 2)) v += DIL_Q;
        a->coeffs[i] = v;
    }
}

/**
 * Moltiplicazione tra un polinomio challenge 'c' (molto sparso) e un polinomio generico 's'.
 * Ottimizzata per processare solo i coefficienti non nulli di c.
 */
void poly_mul_sparse(poly *res, const poly *c, const poly *s) {
    int nonzero_indices[DIL_N];
    int8_t nonzero_signs[DIL_N];
    int count = 0;

    // Individuazione dei coefficienti non nulli del challenge
    for (int i = 0; i < DIL_N; ++i) {
        if (c->coeffs[i] != 0) {
            nonzero_indices[count] = i;
            nonzero_signs[count] = (int8_t)c->coeffs[i];
            count++;
        }
    }

    memset(res->coeffs, 0, DIL_N * sizeof(int32_t));

    // Moltiplicazione nel dominio temporale sfruttando la struttura di R_q
    for (int k = 0; k < count; k++) {
        int i = nonzero_indices[k];
        int sign = nonzero_signs[k];
        const int split = DIL_N - i;

        if (sign == 1) {
            for (int j = 0; j < split; ++j) res->coeffs[i + j] += s->coeffs[j];
            for (int j = split; j < DIL_N; ++j) res->coeffs[i + j - DIL_N] -= s->coeffs[j];
        } else {
            for (int j = 0; j < split; ++j) res->coeffs[i + j] -= s->coeffs[j];
            for (int j = split; j < DIL_N; ++j) res->coeffs[i + j - DIL_N] += s->coeffs[j];
        }
    }
}

void poly_challenge(poly *c, const uint8_t *seed, const dilithium_conf_t *conf) {
    unsigned int i, b, pos;
    uint64_t signs;
    /* Buffer allineato per performance LDRD/STRD */
    uint8_t buf[SHAKE256_RATE * 2] __attribute__((aligned(8)));
    keccak_state state;

    shake256_init(&state);
    shake256_absorb(&state, seed, conf->ctildebytes);
    shake256_finalize(&state);
    /* Estraiamo i primi 2 blocchi per coprire quasi certamente TAU */
    shake256_squeezeblocks(buf, 2, &state);

    /* I primi 8 byte del buffer sono dedicati ai segni dei TAU coefficienti */
    memcpy(&signs, buf, 8);
    pos = 8;

    /* Reset veloce del polinomio */
    memset(c->coeffs, 0, sizeof(int32_t) * DIL_N);

    /* Campionamento dei TAU coefficienti non-zero in base al livello */
    for(i = DIL_N - conf->tau; i < DIL_N; ++i) {
        while (1) {
            if (pos >= SHAKE256_RATE * 2) {
                shake256_squeezeblocks(buf, 1, &state);
                pos = 0;
            }
            b = buf[pos++];
            if (b <= i) break;
        }

        c->coeffs[i] = c->coeffs[b];

        int32_t s = (int32_t)(signs & 1);
        c->coeffs[b] = 1 - (s << 1); // 0 -> 1, 1 -> -1

        signs >>= 1;
    }
}

int poly_chknorm(const poly * __restrict__ a, uint32_t B) {
    const int32_t limit = B - 1;
    const int32_t * __restrict__ c = a->coeffs;
    int32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0;
    for (unsigned int i = 0; i < DIL_N; i += 4) {
        int32_t v0 = c[i+0], v1 = c[i+1], v2 = c[i+2], v3 = c[i+3];
        int32_t m0 = v0 >> 31; v0 = (v0 ^ m0) - m0;
        int32_t m1 = v1 >> 31; v1 = (v1 ^ m1) - m1;
        int32_t m2 = v2 >> 31; v2 = (v2 ^ m2) - m2;
        int32_t m3 = v3 >> 31; v3 = (v3 ^ m3) - m3;
        r0 |= (limit - v0);
        r1 |= (limit - v1);
        r2 |= (limit - v2);
        r3 |= (limit - v3);
    }
    uint32_t ret = (uint32_t)(r0 | r1 | r2 | r3);
    return (int)(ret >> 31);
}

/* ========================================================================= *
 * Funzioni di Compressione e Decompressione (Packing/Unpacking)
 * ========================================================================= */

void polyt0_pack(uint8_t * __restrict__ r, const poly * __restrict__ a) {
    const int32_t *coeffs = a->coeffs;
    const uint32_t offset = 1U << (DIL_D - 1);
    for (unsigned int i = 0; i < DIL_N; i += 8) {
        uint32_t t0 = offset - (uint32_t)coeffs[i+0];
        uint32_t t1 = offset - (uint32_t)coeffs[i+1];
        uint32_t t2 = offset - (uint32_t)coeffs[i+2];
        uint32_t t3 = offset - (uint32_t)coeffs[i+3];
        uint32_t t4 = offset - (uint32_t)coeffs[i+4];
        uint32_t t5 = offset - (uint32_t)coeffs[i+5];
        uint32_t t6 = offset - (uint32_t)coeffs[i+6];
        uint32_t t7 = offset - (uint32_t)coeffs[i+7];
        uint32_t w0 =  t0        | (t1 << 13) | (t2 << 26);
        uint32_t w1 = (t2 >>  6) | (t3 <<  7) | (t4 << 20);
        uint32_t w2 = (t4 >> 12) | (t5 <<  1) | (t6 << 14) | (t7 << 27);
        memcpy(r,    &w0, 4);
        memcpy(r+4,  &w1, 4);
        memcpy(r+8,  &w2, 4);
        r[12] = (uint8_t)(t7 >> 5);
        r += 13;
    }
}

void polyt0_unpack(poly * __restrict__ r, const uint8_t * __restrict__ a) {
    const uint32_t offset = 1U << (DIL_D - 1);  /* 4096 */
    int32_t * __restrict__ coeffs = r->coeffs;

    for (unsigned int i = 0; i < DIL_N / 8; ++i) {
        uint32_t w0, w1, w2;
        uint8_t  b12;
        memcpy(&w0, a,    4);
        memcpy(&w1, a+4,  4);
        memcpy(&w2, a+8,  4);
        b12 = a[12];
        a  += 13;
        uint32_t t0 =  w0        & 0x1FFF;
        uint32_t t1 = (w0 >> 13) & 0x1FFF;
        uint32_t t2 = (w0 >> 26) | ((w1 & 0x7F)  <<  6);  // 6 bit da w0, 7 da w1
        uint32_t t3 = (w1 >>  7) & 0x1FFF;
        uint32_t t4 = (w1 >> 20) | ((w2 & 0x1)   << 12);  // 12 bit da w1, 1 da w2
        uint32_t t5 = (w2 >>  1) & 0x1FFF;
        uint32_t t6 = (w2 >> 14) & 0x1FFF;
        uint32_t t7 = (w2 >> 27) | ((uint32_t)b12 <<  5);  // 5 bit da w2, 8 da b12
        coeffs[8*i+0] = (int32_t)offset - (int32_t)t0;
        coeffs[8*i+1] = (int32_t)offset - (int32_t)t1;
        coeffs[8*i+2] = (int32_t)offset - (int32_t)t2;
        coeffs[8*i+3] = (int32_t)offset - (int32_t)t3;
        coeffs[8*i+4] = (int32_t)offset - (int32_t)t4;
        coeffs[8*i+5] = (int32_t)offset - (int32_t)t5;
        coeffs[8*i+6] = (int32_t)offset - (int32_t)t6;
        coeffs[8*i+7] = (int32_t)offset - (int32_t)t7;
    }
}

void polyeta_pack(uint8_t * __restrict__ r,
                  const poly * __restrict__ a,
                  const dilithium_conf_t *conf) {
    const int32_t *coeffs = a->coeffs;
    if (conf->eta == 2) {
        for (unsigned int i = 0; i < DIL_N / 8; ++i) {
            uint32_t w;
            w  =  ((uint32_t)(2 - coeffs[8*i+0]) & 7);
            w |= (((uint32_t)(2 - coeffs[8*i+1]) & 7) << 3);
            w |= (((uint32_t)(2 - coeffs[8*i+2]) & 7) << 6);
            w |= (((uint32_t)(2 - coeffs[8*i+3]) & 7) << 9);
            w |= (((uint32_t)(2 - coeffs[8*i+4]) & 7) << 12);
            w |= (((uint32_t)(2 - coeffs[8*i+5]) & 7) << 15);
            w |= (((uint32_t)(2 - coeffs[8*i+6]) & 7) << 18);
            w |= (((uint32_t)(2 - coeffs[8*i+7]) & 7) << 21);
            memcpy(r + 3*i, &w, 3);
        }
    } else { /* eta == 4 */
        for (unsigned int i = 0; i < DIL_N / 2; ++i)
            r[i] = (uint8_t)(((4 - coeffs[2*i+0]) & 0xF) |
                            (((4 - coeffs[2*i+1]) & 0xF) << 4));
    }
}


void polyeta_unpack(poly * __restrict__ r,
                    const uint8_t * __restrict__ a,
                    const dilithium_conf_t *conf)
{
    int32_t * __restrict__ coeffs = r->coeffs;

    if (conf->eta == 2) {
        for (unsigned int i = 0; i < DIL_N / 8; ++i) {
            uint32_t w = 0;
            memcpy(&w, a + 3*i, 3);   // carica 3 byte, il 4° rimane 0
            coeffs[8*i+0] = 2 - (int32_t)((w >>  0) & 7);
            coeffs[8*i+1] = 2 - (int32_t)((w >>  3) & 7);
            coeffs[8*i+2] = 2 - (int32_t)((w >>  6) & 7);
            coeffs[8*i+3] = 2 - (int32_t)((w >>  9) & 7);
            coeffs[8*i+4] = 2 - (int32_t)((w >> 12) & 7);
            coeffs[8*i+5] = 2 - (int32_t)((w >> 15) & 7);
            coeffs[8*i+6] = 2 - (int32_t)((w >> 18) & 7);
            coeffs[8*i+7] = 2 - (int32_t)((w >> 21) & 7);
        }
    } else { /* eta == 4 */
        for (unsigned int i = 0; i < DIL_N / 8; ++i) {
            uint32_t w;
            memcpy(&w, a + 4*i, 4);
            coeffs[8*i+0] = 4 - (int32_t)( w        & 0xF);
            coeffs[8*i+1] = 4 - (int32_t)((w >>  4) & 0xF);
            coeffs[8*i+2] = 4 - (int32_t)((w >>  8) & 0xF);
            coeffs[8*i+3] = 4 - (int32_t)((w >> 12) & 0xF);
            coeffs[8*i+4] = 4 - (int32_t)((w >> 16) & 0xF);
            coeffs[8*i+5] = 4 - (int32_t)((w >> 20) & 0xF);
            coeffs[8*i+6] = 4 - (int32_t)((w >> 24) & 0xF);
            coeffs[8*i+7] = 4 - (int32_t)( w >> 28);  // no maschera: bit alti già 0
        }
    }
}

// In se3_arith_poly.c
void polyt1_pack(uint8_t * __restrict__ r, const poly * __restrict__ a) {
    for (unsigned int i = 0; i < DIL_N / 4; ++i) {
        uint64_t t0 = (uint32_t)a->coeffs[4*i+0] & 0x3FF;
        uint64_t t1 = (uint32_t)a->coeffs[4*i+1] & 0x3FF;
        uint64_t t2 = (uint32_t)a->coeffs[4*i+2] & 0x3FF;
        uint64_t t3 = (uint32_t)a->coeffs[4*i+3] & 0x3FF;
        uint64_t word = t0 | (t1 << 10) | (t2 << 20) | (t3 << 30);
        memcpy(r + 5*i, &word, 5);
    }
}

void polyt1_unpack(poly *r, const uint8_t *a) {
    int32_t *coeffs = r->coeffs;
    for(unsigned int i = 0; i < DIL_N/4; ++i) {
        uint64_t w = 0;
        memcpy(&w, a + 5*i, 5);
        coeffs[4*i+0] = (int32_t)(w >> 0)  & 0x3FF;
        coeffs[4*i+1] = (int32_t)(w >> 10) & 0x3FF;
        coeffs[4*i+2] = (int32_t)(w >> 20) & 0x3FF;
        coeffs[4*i+3] = (int32_t)(w >> 30) & 0x3FF;
    }
}

void polyz_pack(uint8_t * __restrict__ r,
                const poly * __restrict__ a,
                const dilithium_conf_t *conf){
    if (conf->gamma1 == (1 << 17)) {
        for (unsigned int i = 0; i < DIL_N / 4; ++i) {
            uint32_t t0 = (uint32_t)(conf->gamma1 - a->coeffs[4*i+0]);
            uint32_t t1 = (uint32_t)(conf->gamma1 - a->coeffs[4*i+1]);
            uint32_t t2 = (uint32_t)(conf->gamma1 - a->coeffs[4*i+2]);
            uint32_t t3 = (uint32_t)(conf->gamma1 - a->coeffs[4*i+3]);
            uint64_t w0 = (uint64_t)t0
                        | ((uint64_t)t1 << 18)
                        | ((uint64_t)t2 << 36)
                        | ((uint64_t)t3 << 54);
            memcpy(r,   &w0, 8);            /* STR64 (o STR32+STR32) */
            r[8] = (uint8_t)(t3 >> 10);    /* 2 bit residui di t3 */
            r += 9;
        }

    } else { /* gamma1 == (1 << 19) */
        for (unsigned int i = 0; i < DIL_N / 2; ++i) {
            uint32_t t0 = (uint32_t)(conf->gamma1 - a->coeffs[2*i+0]);
            uint32_t t1 = (uint32_t)(conf->gamma1 - a->coeffs[2*i+1]);
            uint64_t w = (uint64_t)t0 | ((uint64_t)t1 << 20);
            memcpy(r, &w, 5);              /* STR32 + STRB */
            r += 5;
        }
    }
}

void polyz_unpack(poly * __restrict__ r, const uint8_t * __restrict__ a, const dilithium_conf_t *conf) {
    if (conf->gamma1 == (1 << 17)) {
        for (unsigned int i = 0; i < DIL_N/4; ++i) {
            uint64_t w;
            memcpy(&w, a, 8);
            uint32_t b8 = a[8];
            r->coeffs[4*i+0] = conf->gamma1 - (int32_t)( w         & 0x3FFFF);
            r->coeffs[4*i+1] = conf->gamma1 - (int32_t)((w >> 18)  & 0x3FFFF);
            r->coeffs[4*i+2] = conf->gamma1 - (int32_t)((w >> 36)  & 0x3FFFF);
            r->coeffs[4*i+3] = conf->gamma1 - (int32_t)(((w >> 54) | ((uint64_t)b8 << 10)) & 0x3FFFF);
            a += 9;
        }
    } else if (conf->gamma1 == (1 << 19)) {
        for (unsigned int i = 0; i < DIL_N/2; ++i) {
            uint64_t w = 0;
            memcpy(&w, a, 5);
            r->coeffs[2*i+0] = conf->gamma1 - (int32_t)( w        & 0xFFFFF);
            r->coeffs[2*i+1] = conf->gamma1 - (int32_t)((w >> 20) & 0xFFFFF);
            a += 5;
        }
    }
}

void polyw1_pack(uint8_t * __restrict__ r,
                 const poly * __restrict__ a,
                 const dilithium_conf_t *conf)
{
    const int32_t * __restrict__ c   = a->coeffs;
    const int32_t *              end = c + DIL_N;
    if (conf->gamma2 == (DIL_Q-1)/88) {
        while (c < end) {
            uint64_t w = (uint64_t)c[0]
                       | ((uint64_t)c[1] <<  6)
                       | ((uint64_t)c[2] << 12)
                       | ((uint64_t)c[3] << 18)
                       | ((uint64_t)c[4] << 24)
                       | ((uint64_t)c[5] << 30)
                       | ((uint64_t)c[6] << 36)
                       | ((uint64_t)c[7] << 42);
            memcpy(r, &w, 6);   /* STR32 + STR16 sul Cortex-M4 */
            r += 6; c += 8;
        }
    } else { /* gamma2 == (Q-1)/32 */
        while (c < end) {
            uint32_t w = (uint32_t)c[0]
                       | ((uint32_t)c[1] <<  4)
                       | ((uint32_t)c[2] <<  8)
                       | ((uint32_t)c[3] << 12)
                       | ((uint32_t)c[4] << 16)
                       | ((uint32_t)c[5] << 20)
                       | ((uint32_t)c[6] << 24)
                       | ((uint32_t)c[7] << 28);
            memcpy(r, &w, 4);   /* singolo STR32 */
            r += 4; c += 8;
        }
    }
}

/* ========================================================================= *
 * Funzioni di Campionamento e Controllo (Rejection Sampling)
 * ========================================================================= */

__attribute__((optimize("O3")))
unsigned int rej_eta(int32_t * __restrict__ a, unsigned int len,
                     const uint8_t * __restrict__ buf, unsigned int buflen,
                     const dilithium_conf_t *conf)
{
    unsigned int ctr = 0, pos = 0;

    if (conf->eta == 2) {
        static const int32_t lut[16] = {
            2, 1, 0, -1, -2,  2, 1, 0, -1, -2,  2, 1, 0, -1, -2,  0
        };
        while (ctr < len && pos < buflen) {
            uint32_t b  = buf[pos++];
            uint32_t t0 = b & 0x0F;
            uint32_t t1 = b >> 4;

            uint32_t ok0 = (t0 < 15);           /* 1 se valido, 0 se rifiutato */
            uint32_t ok1 = (t1 < 15);

            a[ctr] = lut[t0];                   /* scrittura speculativa (sempre) */
            ctr   += ok0;                        /* avanza solo se valido */
            ok1   &= (unsigned)(ctr < len);     /* ← FIX: blocca ok1 se già pieni */
            a[ctr] = lut[t1];                   /* speculativo: richiede a[len] allocato! */
            ctr   += ok1;
        }

    } else if (conf->eta == 4) {
        static const int32_t lut[16] = {
            4, 3, 2, 1, 0, -1, -2, -3, -4,  0, 0, 0, 0, 0, 0, 0
        };
        while (ctr < len && pos < buflen) {
            uint32_t b  = buf[pos++];
            uint32_t t0 = b & 0x0F;
            uint32_t t1 = b >> 4;

            uint32_t ok0 = (t0 <= 8);
            uint32_t ok1 = (t1 <= 8);

            a[ctr] = lut[t0];
            ctr   += ok0;
            ok1   &= (unsigned)(ctr < len);
            a[ctr] = lut[t1];
            ctr   += ok1;
        }
    }

    return ctr;
}

unsigned int rej_uniform(int32_t * __restrict__ a, unsigned int len, const uint8_t * __restrict__ buf, unsigned int buflen) {
    unsigned int ctr = 0;
    unsigned int pos = 0;
    int32_t * __restrict__ pa = a;
    while (pos + 2 < buflen && ctr < len) {
        uint32_t t = (*(const uint32_t*)(buf + pos)) & 0x7FFFFF;
        if (t < DIL_Q) {
            *pa++ = t;
            ctr++;
        }
        pos += 3;
    }
    return ctr;
}

void poly_uniform(poly *a, const uint8_t seed[DIL_SEEDBYTES], uint16_t nonce) {
    unsigned int ctr = 0;
    keccak_state state;
    uint8_t ext_seed[34];
    memcpy(ext_seed, seed, 32);
    ext_seed[32] = nonce & 0xFF;
    ext_seed[33] = (nonce >> 8) & 0xFF;
    shake128_init(&state);
    shake128_absorb(&state, ext_seed, 34);
    shake128_finalize(&state);

#define DIL_FAST_BUFFER_BLOCKS 5
    uint8_t buf[DIL_FAST_BUFFER_BLOCKS * DIL_STREAM128_BLOCKBYTES];
    shake128_squeezeblocks(buf, DIL_FAST_BUFFER_BLOCKS, &state);
    ctr = rej_uniform(a->coeffs, DIL_N, buf, sizeof(buf));
    while (ctr < DIL_N) {
        uint8_t extra_buf[3*DIL_STREAM128_BLOCKBYTES];
        shake128_squeezeblocks(extra_buf, 3, &state);
        ctr += rej_uniform(a->coeffs + ctr, DIL_N - ctr, extra_buf, sizeof(extra_buf));
    }
}

void poly_uniform_gamma1(poly *a, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
    uint8_t buf[((DIL_POLYZ_PACKEDBYTES_MAX + DIL_STREAM256_BLOCKBYTES - 1)/DIL_STREAM256_BLOCKBYTES)*DIL_STREAM256_BLOCKBYTES];
    stream256_state state;
    stream256_init(&state, seed, nonce);
    size_t outblocks = (conf->polyz_packed + DIL_STREAM256_BLOCKBYTES - 1)/DIL_STREAM256_BLOCKBYTES;
    stream256_squeezeblocks(buf, outblocks, &state);
    polyz_unpack(a, buf, conf);
}

void poly_uniform_eta(poly *a, const uint8_t seed[DIL_CRHBYTES], uint16_t nonce, const dilithium_conf_t *conf) {
    uint8_t buf[2 * DIL_STREAM256_BLOCKBYTES];
    stream256_state state;
    size_t eta_nblocks = (conf->eta == 2) ? 2 : ((227 + DIL_STREAM256_BLOCKBYTES - 1)/DIL_STREAM256_BLOCKBYTES);
    stream256_init(&state, seed, nonce);
    stream256_squeezeblocks(buf, eta_nblocks, &state);
    unsigned int ctr = rej_eta(a->coeffs, DIL_N, buf, eta_nblocks * DIL_STREAM256_BLOCKBYTES, conf);
    while (ctr < DIL_N) {
        stream256_squeezeblocks(buf, 1, &state);
        ctr += rej_eta(a->coeffs + ctr, DIL_N - ctr, buf, DIL_STREAM256_BLOCKBYTES, conf);
    }
}

/* ========================================================================= *
 * Funzioni di Aritmetica Polinomiale e NTT
 * ========================================================================= */

__attribute__((optimize("O3")))
void poly_pointwise_montgomery(poly * c,
                               const poly *__restrict__ a,
                               const poly *__restrict__ b)
{
    const int32_t *ap = a->coeffs;
    const int32_t *bp = b->coeffs;
    int32_t *cp = c->coeffs;
    #pragma GCC unroll 2
    for (unsigned int i = 0; i < DIL_N; i += 2) {
        int64_t t0 = (int64_t)ap[0] * bp[0];
        int64_t t1 = (int64_t)ap[1] * bp[1];
        cp[0] = montgomery_reduce(t0);
        cp[1] = montgomery_reduce(t1);
        ap += 2;
        bp += 2;
        cp += 2;
    }
}

void poly_ntt(poly *a) { ntt(a->coeffs); }
void poly_invntt_tomont(poly *a) { invntt_tomont(a->coeffs); }

__attribute__((optimize("O3")))
void poly_add(poly * __restrict__ c, const poly * __restrict__ a, const poly * __restrict__ b) {
    for (unsigned int i = 0; i < DIL_N; i += 2) {
        c->coeffs[i]   = a->coeffs[i]   + b->coeffs[i];
        c->coeffs[i+1] = a->coeffs[i+1] + b->coeffs[i+1];
    }
}

__attribute__((optimize("O3")))
void poly_sub(poly * c, const poly * __restrict__ a, const poly * __restrict__ b) {
    for (unsigned int i = 0; i < DIL_N; i += 2) {
        c->coeffs[i]   =  a->coeffs[i] -  b->coeffs[i];
        c->coeffs[i+1] =  a->coeffs[i+1] -  b->coeffs[i+1];
    }
}

__attribute__((optimize("O3")))
void poly_caddq(poly *a) {
    int32_t * __restrict__ pa = a->coeffs;

    // Srotolamento x2: Il sweet spot del Cortex-M4 per innescare LDRD/STRD
    for(unsigned int i = 0; i < DIL_N / 2; i++) {
        int32_t x0 = pa[0];
        int32_t x1 = pa[1];
        x0 += (x0 >> 31) & DIL_Q;
        x0 -= DIL_Q;
        x0 += (x0 >> 31) & DIL_Q;
        x1 += (x1 >> 31) & DIL_Q;
        x1 -= DIL_Q;
        x1 += (x1 >> 31) & DIL_Q;
        pa[0] = x0;
        pa[1] = x1;
        pa += 2;
    }
}

void poly_power2round(poly *a1, poly *a0, const poly *a) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        a1->coeffs[i]   = power2round(&a0->coeffs[i],   a->coeffs[i]);
        a1->coeffs[i+1] = power2round(&a0->coeffs[i+1], a->coeffs[i+1]);
    }
}

__attribute__((optimize("O3")))
void poly_reduce(poly *a) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        a->coeffs[i]   = reduce32(a->coeffs[i]);
        a->coeffs[i+1] = reduce32(a->coeffs[i+1]);
    }
}

void poly_decompose(poly *a1, poly *a0, const poly *a, const dilithium_conf_t *conf) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        a1->coeffs[i]   = decompose(&a0->coeffs[i],   a->coeffs[i],   conf->gamma2);
        a1->coeffs[i+1] = decompose(&a0->coeffs[i+1], a->coeffs[i+1], conf->gamma2);
    }
}

unsigned int poly_make_hint(poly * __restrict__ h, const poly * __restrict__ a0, const poly * __restrict__ a1, const dilithium_conf_t *conf) {
    unsigned int s = 0;
    for (unsigned int i = 0; i < DIL_N; i += 8) {
        uint32_t h0 = make_hint(a0->coeffs[i+0], a1->coeffs[i+0], conf->gamma2);
        uint32_t h1 = make_hint(a0->coeffs[i+1], a1->coeffs[i+1], conf->gamma2);
        uint32_t h2 = make_hint(a0->coeffs[i+2], a1->coeffs[i+2], conf->gamma2);
        uint32_t h3 = make_hint(a0->coeffs[i+3], a1->coeffs[i+3], conf->gamma2);
        uint32_t h4 = make_hint(a0->coeffs[i+4], a1->coeffs[i+4], conf->gamma2);
        uint32_t h5 = make_hint(a0->coeffs[i+5], a1->coeffs[i+5], conf->gamma2);
        uint32_t h6 = make_hint(a0->coeffs[i+6], a1->coeffs[i+6], conf->gamma2);
        uint32_t h7 = make_hint(a0->coeffs[i+7], a1->coeffs[i+7], conf->gamma2);

        h->coeffs[i+0]=h0; h->coeffs[i+1]=h1;
        h->coeffs[i+2]=h2; h->coeffs[i+3]=h3;
        h->coeffs[i+4]=h4; h->coeffs[i+5]=h5;
        h->coeffs[i+6]=h6; h->coeffs[i+7]=h7;

        s += h0+h1+h2+h3+h4+h5+h6+h7;
    }
    return s;
}

__attribute__((optimize("O3")))
void poly_shiftl(poly *a) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        int32_t x0 = a->coeffs[i];
        int32_t x1 = a->coeffs[i+1];

        a->coeffs[i]   = x0 << DIL_D;
        a->coeffs[i+1] = x1 << DIL_D;
    }
}

void poly_use_hint(poly *b, const poly *a, const poly *h, const dilithium_conf_t *conf) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        b->coeffs[i]   = use_hint(a->coeffs[i],   h->coeffs[i],   conf->gamma2);
        b->coeffs[i+1] = use_hint(a->coeffs[i+1], h->coeffs[i+1], conf->gamma2);
    }
}
