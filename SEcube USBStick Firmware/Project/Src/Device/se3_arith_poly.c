#include <stdint.h>
#include <string.h>

#include "se3_arith_poly.h"
#include "se3_arith_reduce.h"
#include "se3_algo_shake.h"
#include "se3_algo_dilithium_symmetric.h"
#include "Keccak.h"

/* ========================================================================= *
 * Funzioni di Hashing, Arrotondamento e Hint
 * ========================================================================= */

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

int poly_chknorm(const poly *a, int32_t B) {
    int32_t ret = 0;
    const int32_t limit = B;
    const int32_t *p = a->coeffs;

    for (int i = 0; i < DIL_N / 4; i++) {
        int32_t v0 = p[0];
        int32_t v1 = p[1];
        int32_t v2 = p[2];
        int32_t v3 = p[3];
        p += 4;

        int32_t m0 = v0 >> 31;
        int32_t m1 = v1 >> 31;
        int32_t m2 = v2 >> 31;
        int32_t m3 = v3 >> 31;

        v0 = (v0 ^ m0) - m0;
        v1 = (v1 ^ m1) - m1;
        v2 = (v2 ^ m2) - m2;
        v3 = (v3 ^ m3) - m3;

        ret |= (limit - 1 - v0);
        ret |= (limit - 1 - v1);
        ret |= (limit - 1 - v2);
        ret |= (limit - 1 - v3);
    }

    return (uint32_t)ret >> 31;
}

/* ========================================================================= *
 * Funzioni di Compressione e Decompressione (Packing/Unpacking)
 * ========================================================================= */

void polyt0_pack(uint8_t *r, const poly *a) {
    const int32_t *coeffs = a->coeffs;
    const uint32_t offset = (1U << (DIL_D - 1));
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
    uint32_t w0, w1, w2;

    for(unsigned int i = 0; i < DIL_N; i += 8) {
        t0 = offset - coeffs[i+0];
        t1 = offset - coeffs[i+1];
        t2 = offset - coeffs[i+2];
        t3 = offset - coeffs[i+3];
        t4 = offset - coeffs[i+4];
        t5 = offset - coeffs[i+5];
        t6 = offset - coeffs[i+6];
        t7 = offset - coeffs[i+7];

        w0 = t0 | (t1 << 13) | (t2 << 26);
        w1 = (t2 >> 6) | (t3 << 7) | (t4 << 20);
        w2 = (t4 >> 12) | (t5 << 1) | (t6 << 14) | (t7 << 27);

        memcpy(r + 0, &w0, 4);
        memcpy(r + 4, &w1, 4);
        memcpy(r + 8, &w2, 4);
        r[12] = (uint8_t)(t7 >> 5);
        r += 13;
    }
}

void polyt0_unpack(poly *r, const uint8_t *a) {
    int32_t *coeffs = r->coeffs;
    const int32_t offset = (1 << (DIL_D - 1));
    uint32_t w0, w1, w2, w3;

    for(unsigned int i = 0; i < DIL_N / 8; ++i) {
        memcpy(&w0, a + 0, 4);
        memcpy(&w1, a + 4, 4);
        memcpy(&w2, a + 8, 4);
        w3 = a[12];
        a += 13;

        coeffs[0] = offset - (int32_t)(w0 & 0x1FFF);
        coeffs[1] = offset - (int32_t)((w0 >> 13) & 0x1FFF);
        coeffs[2] = offset - (int32_t)((w0 >> 26) | ((w1 & 0x7) << 6));
        coeffs[3] = offset - (int32_t)((w1 >> 3) & 0x1FFF);
        coeffs[4] = offset - (int32_t)((w1 >> 16) & 0x1FFF);
        coeffs[5] = offset - (int32_t)((w1 >> 29) | ((w2 & 0x3FF) << 3));
        coeffs[6] = offset - (int32_t)((w2 >> 10) & 0x1FFF);
        coeffs[7] = offset - (int32_t)((w2 >> 23) | ((w3 & 0xFF) << 9));
        coeffs += 8;
    }
}

void polyeta_pack(uint8_t *r, const poly *a, const dilithium_conf_t *conf) {
    const int32_t *coeffs = a->coeffs;
    if (conf->eta == 2) {
        for(unsigned int i = 0; i < DIL_N/8; ++i) {
            uint32_t w;
            w  = (uint32_t)(2 - coeffs[8*i+0]);
            w |= (uint32_t)(2 - coeffs[8*i+1]) << 3;
            w |= (uint32_t)(2 - coeffs[8*i+2]) << 6;
            w |= (uint32_t)(2 - coeffs[8*i+3]) << 9;
            w |= (uint32_t)(2 - coeffs[8*i+4]) << 12;
            w |= (uint32_t)(2 - coeffs[8*i+5]) << 15;
            w |= (uint32_t)(2 - coeffs[8*i+6]) << 18;
            w |= (uint32_t)(2 - coeffs[8*i+7]) << 21;
            memcpy(r + 3*i, &w, 3);
        }
    } else if (conf->eta == 4) {
        for(unsigned int i = 0; i < DIL_N/2; ++i) {
            r[i] = (uint8_t)((4 - coeffs[2*i+0]) | ((4 - coeffs[2*i+1]) << 4));
        }
    }
}

void polyeta_unpack(poly *r, const uint8_t *a, const dilithium_conf_t *conf) {
    int32_t *coeffs = r->coeffs;
    if (conf->eta == 2) {
        for(unsigned int i = 0; i < DIL_N/8; ++i) {
            uint32_t w = 0;
            memcpy(&w, a + 3*i, 3);
            coeffs[8*i+0] = 2 - (int32_t)((w >> 0)  & 7);
            coeffs[8*i+1] = 2 - (int32_t)((w >> 3)  & 7);
            coeffs[8*i+2] = 2 - (int32_t)((w >> 6)  & 7);
            coeffs[8*i+3] = 2 - (int32_t)((w >> 9)  & 7);
            coeffs[8*i+4] = 2 - (int32_t)((w >> 12) & 7);
            coeffs[8*i+5] = 2 - (int32_t)((w >> 15) & 7);
            coeffs[8*i+6] = 2 - (int32_t)((w >> 18) & 7);
            coeffs[8*i+7] = 2 - (int32_t)((w >> 21) & 7);
        }
    } else if (conf->eta == 4) {
        for(unsigned int i = 0; i < DIL_N/8; ++i) {
            uint32_t w;
            memcpy(&w, a + 4*i, 4);
            coeffs[8*i+0] = 4 - (int32_t)((w >> 0) & 0x0F);
            coeffs[8*i+1] = 4 - (int32_t)((w >> 4) & 0x0F);
            coeffs[8*i+2] = 4 - (int32_t)((w >> 8) & 0x0F);
            coeffs[8*i+3] = 4 - (int32_t)((w >> 12) & 0x0F);
            coeffs[8*i+4] = 4 - (int32_t)((w >> 16) & 0x0F);
            coeffs[8*i+5] = 4 - (int32_t)((w >> 20) & 0x0F);
            coeffs[8*i+6] = 4 - (int32_t)((w >> 24) & 0x0F);
            coeffs[8*i+7] = 4 - (int32_t)((w >> 28) & 0x0F);
        }
    }
}

void polyt1_pack(uint8_t *r, const poly *a) {
    for(unsigned int i = 0; i < DIL_N/4; ++i) {
        r[5*i+0] = (a->coeffs[4*i+0] >> 0);
        r[5*i+1] = (a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2);
        r[5*i+2] = (a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4);
        r[5*i+3] = (a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6);
        r[5*i+4] = (a->coeffs[4*i+3] >> 2);
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

void polyz_pack(uint8_t *r, const poly *a, const dilithium_conf_t *conf) {
    uint32_t t[4];
    if (conf->gamma1 == (1 << 17)) {
        for(unsigned int i = 0; i < DIL_N/4; ++i) {
            for(int j=0; j<4; j++) t[j] = conf->gamma1 - a->coeffs[4*i+j];
            r[9*i+0] = t[0]; r[9*i+1] = t[0] >> 8; r[9*i+2] = t[0] >> 16 | t[1] << 2;
            r[9*i+3] = t[1] >> 6; r[9*i+4] = t[1] >> 14 | t[2] << 4; r[9*i+5] = t[2] >> 4;
            r[9*i+6] = t[2] >> 12 | t[3] << 6; r[9*i+7] = t[3] >> 2; r[9*i+8] = t[3] >> 10;
        }
    } else if (conf->gamma1 == (1 << 19)) {
        for(unsigned int i = 0; i < DIL_N/2; ++i) {
            t[0] = conf->gamma1 - a->coeffs[2*i+0]; t[1] = conf->gamma1 - a->coeffs[2*i+1];
            r[5*i+0] = t[0]; r[5*i+1] = t[0] >> 8; r[5*i+2] = t[0] >> 16 | t[1] << 4;
            r[5*i+3] = t[1] >> 4; r[5*i+4] = t[1] >> 12;
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

void polyw1_pack(uint8_t * __restrict__ r, const poly * __restrict__ a, const dilithium_conf_t *conf) {
    const int32_t *c   = a->coeffs;
    const int32_t *end = c + DIL_N;

    if (conf->gamma2 == (DIL_Q-1)/88) {
        while (c < end) {
            uint32_t w = (uint32_t)c[0]
                       | ((uint32_t)c[1] <<  6)
                       | ((uint32_t)c[2] << 12)
                       | ((uint32_t)c[3] << 18);
            memcpy(r, &w, 3);
            r += 3; c += 4;
        }
    } else if (conf->gamma2 == (DIL_Q-1)/32) {
        while (c < end) {
            uint16_t w = (uint16_t)((uint32_t)c[0]
                                  | ((uint32_t)c[1] << 4)
                                  | ((uint32_t)c[2] << 8)
                                  | ((uint32_t)c[3] << 12));
            memcpy(r, &w, 2);
            r += 2; c += 4;
        }
    }
}

/* ========================================================================= *
 * Funzioni di Campionamento e Controllo (Rejection Sampling)
 * ========================================================================= */

unsigned int rej_eta(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen, const dilithium_conf_t *conf) {
    unsigned int ctr = 0, pos = 0;
    uint32_t t0, t1, b;

    while(ctr < len && pos < buflen) {
        b = buf[pos++];
        t0 = b & 0x0F;
        t1 = b >> 4;

        if (conf->eta == 2) {
            if(t0 < 15) {
                t0 = t0 - (t0 >= 10 ? 10 : (t0 >= 5 ? 5 : 0));
                a[ctr++] = 2 - (int32_t)t0;
            }
            if(t1 < 15 && ctr < len) {
                t1 = t1 - (t1 >= 10 ? 10 : (t1 >= 5 ? 5 : 0));
                a[ctr++] = 2 - (int32_t)t1;
            }
        } else if (conf->eta == 4) {
            if(t0 <= 8) a[ctr++] = 4 - (int32_t)t0;
            if(t1 <= 8 && ctr < len) a[ctr++] = 4 - (int32_t)t1;
        }
    }
    return ctr;
}

unsigned int rej_uniform(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr = 0, pos = 0;
    uint32_t t;

    while(ctr < len && pos + 3 <= buflen) {
        memcpy(&t, buf + pos, 4);
        pos += 3;
        t &= 0x7FFFFF;

        if(t < DIL_Q) {
            a[ctr++] = (int32_t)t;
        }
    }
    return ctr;
}

void poly_uniform(poly *a, const uint8_t seed[DIL_SEEDBYTES], const uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_BYTES + 4] __attribute__((aligned(8)));
    unsigned int buflen = POLY_UNIFORM_BYTES;
    stream128_state state;

    stream128_init(&state, seed, nonce);
    stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);
    unsigned int ctr = rej_uniform(a->coeffs, DIL_N, buf, buflen);

    while(ctr < DIL_N) {
        unsigned int off = buflen % 3;
        if(off) memcpy(buf, buf + buflen - off, off);
        stream128_squeezeblocks(buf + off, 1, &state);
        buflen = DIL_STREAM128_BLOCKBYTES + off;
        ctr += rej_uniform(a->coeffs + ctr, DIL_N - ctr, buf, buflen);
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
void poly_pointwise_montgomery(poly *__restrict__ c,
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
void poly_sub(poly * __restrict__ c, const poly * __restrict__ a, const poly * __restrict__ b) {
    for (unsigned int i = 0; i < DIL_N; i += 2) {
        c->coeffs[i]   =  a->coeffs[i] -  b->coeffs[i];
        c->coeffs[i+1] =  a->coeffs[i+1] -  b->coeffs[i+1];
    }
}

__attribute__((optimize("O3")))
void poly_caddq(poly *a) {
    for(unsigned int i = 0; i < DIL_N; i += 2) {
        int32_t x0 = a->coeffs[i];
        int32_t x1 = a->coeffs[i+1];
        a->coeffs[i]   = x0 + (DIL_Q & (x0 >> 31));
        a->coeffs[i+1] = x1 + (DIL_Q & (x1 >> 31));
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
