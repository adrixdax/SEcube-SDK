#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "se3_arith_poly.h"

#include "se3_arith_reduce.h"
#include "se3_algo_shake.h"
#include "se3_algo_mldsa_symmetric.h"
#include "Keccak.h"



static inline uint32_t ct_lt(uint32_t a, uint32_t b) {
    return (uint32_t)(-(int32_t)((a - b) >> 31));
}

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
    // Usiamo B - 1 per permettere un controllo rigoroso tramite bit di segno
    int32_t limit = B - 1;
    // Loop singolo: sicuro per la memoria, facilmente vettorizzabile dal compilatore
    for (unsigned int i = 0; i < DIL_N; i++) {
        // 1. Lettura sicura a 32-bit (previene l'Hard Fault da disallineamento)
        int32_t v = a->coeffs[i];
        // 2. Calcolo del valore assoluto senza usare "if" (Constant-Time)
        int32_t mask = v >> 31;
        v = (v ^ mask) - mask;
        // 3. Accumulo dell'errore. Se v > limit, (limit - v) diventa negativo
        // e il suo 31esimo bit (quello del segno) diventa 1.
        ret |= (limit - v);
    }
    // Sposta il bit di segno in prima posizione.
    // Ritorna 1 (Fail) se almeno un coeff era troppo grande, 0 (Success) altrimenti.
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
        r[0] = (uint8_t)(w0);
        r[1] = (uint8_t)(w0 >> 8);
        r[2] = (uint8_t)(w0 >> 16);
        r[3] = (uint8_t)(w0 >> 24);
        r[4] = (uint8_t)(w1);
        r[5] = (uint8_t)(w1 >> 8);
        r[6] = (uint8_t)(w1 >> 16);
        r[7] = (uint8_t)(w1 >> 24);
        r[8]  = (uint8_t)(w2);
        r[9]  = (uint8_t)(w2 >> 8);
        r[10] = (uint8_t)(w2 >> 16);
        r[11] = (uint8_t)(w2 >> 24);
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
    unsigned int i;

    if (conf->eta == 2) {
        // ML-DSA-44: Impacchetta 8 coefficienti in 3 byte
        for(i = 0; i < DIL_N / 8; ++i) {
            uint32_t w;

            // Maschera bit-a-bit (& 7) per bloccare il "bit-bleeding" dei numeri negativi
            w  =  ((uint32_t)(2 - coeffs[8*i+0]) & 7);
            w |= (((uint32_t)(2 - coeffs[8*i+1]) & 7) << 3);
            w |= (((uint32_t)(2 - coeffs[8*i+2]) & 7) << 6);
            w |= (((uint32_t)(2 - coeffs[8*i+3]) & 7) << 9);
            w |= (((uint32_t)(2 - coeffs[8*i+4]) & 7) << 12);
            w |= (((uint32_t)(2 - coeffs[8*i+5]) & 7) << 15);
            w |= (((uint32_t)(2 - coeffs[8*i+6]) & 7) << 18);
            w |= (((uint32_t)(2 - coeffs[8*i+7]) & 7) << 21);

            // Scrittura diretta in memoria (più veloce e sicura del memcpy)
            r[3*i+0] = (uint8_t)(w);
            r[3*i+1] = (uint8_t)(w >> 8);
            r[3*i+2] = (uint8_t)(w >> 16);
        }
    } else if (conf->eta == 4) {
        // ML-DSA-65 / ML-DSA-87: Impacchetta 2 coefficienti in 1 byte
        for(i = 0; i < DIL_N / 2; ++i) {
            // Maschera bit-a-bit (& 15) per bloccare il "bit-bleeding"
            r[i] = (uint8_t)(((4 - coeffs[2*i+0]) & 15) | (((4 - coeffs[2*i+1]) & 15) << 4));
        }
    }
}


void polyeta_unpack(poly *r, const uint8_t *a, const dilithium_conf_t *conf) {
    int32_t *coeffs = r->coeffs;
    if (conf->eta == 2) {
        for(unsigned int i = 0; i < DIL_N/8; ++i) {
            uint32_t w = 0;
            // Caricamento esplicito di 3 byte per evitare sporcizia nel 4° byte
            w  = (uint32_t)a[3*i+0];
            w |= (uint32_t)a[3*i+1] << 8;
            w |= (uint32_t)a[3*i+2] << 16;
            for(int j=0; j<8; ++j) {
                uint8_t extracted = (w >> (3*j)) & 7;
                // ML-DSA-44: i coefficienti sono (eta - valore)
                coeffs[8*i+j] = (int32_t)2 - (int32_t)extracted;

                // Opzionale: Protezione contro dati corrotti
                if (extracted > 4) {
                    fprintf(stderr, "WARNING: eta-value %d is out of range [0,4]\n", extracted);
                }
            }
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

// In se3_arith_poly.c
void polyt1_pack(uint8_t *r, const poly *a) {
    for(unsigned int i = 0; i < DIL_N/4; ++i) {

        uint32_t t0 = (uint32_t)a->coeffs[4*i+0] & 0x3FF;
        uint32_t t1 = (uint32_t)a->coeffs[4*i+1] & 0x3FF;
        uint32_t t2 = (uint32_t)a->coeffs[4*i+2] & 0x3FF;
        uint32_t t3 = (uint32_t)a->coeffs[4*i+3] & 0x3FF;

        r[5*i+0] = (t0 >> 0) & 0xFF;
        r[5*i+1] = ((t0 >> 8) | (t1 << 2)) & 0xFF;
        r[5*i+2] = ((t1 >> 6) | (t2 << 4)) & 0xFF;
        r[5*i+3] = ((t2 >> 4) | (t3 << 6)) & 0xFF;
        r[5*i+4] = (t3 >> 2) & 0xFF;
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
    unsigned int ctr = 0;
    unsigned int pos = 0;

    while (pos + 2 < buflen && ctr < len) {
        uint8_t b0 = buf[pos];
        uint8_t b1 = buf[pos+1];
        uint8_t b2 = buf[pos+2] & 0x7F; // Cleanly zeroes the top bit

        uint32_t t = ((uint32_t)b2 << 16) | ((uint32_t)b1 << 8) | b0;

        if (t < DIL_Q) {
            a[ctr] = t;
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

    // 1. Preparazione del seed (già corretta)
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
    for(unsigned int i = 0; i < DIL_N; i++) {
        int32_t x = a->coeffs[i];
        // 1. Risolve eventuali numeri negativi (es. se s2 era -2)
        x += (x >> 31) & DIL_Q;
        // 2. Tira giù tutto di Q per risolvere gli overflow (es. Q+1 diventa 1)
        x -= DIL_Q;
        // 3. Se il numero era già giusto, il passaggio 2 lo ha reso negativo. Lo riportiamo su.
        x += (x >> 31) & DIL_Q;
        a->coeffs[i] = x;
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
