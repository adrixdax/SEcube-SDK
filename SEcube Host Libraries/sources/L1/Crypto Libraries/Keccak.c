#include "Keccak.h"

static const uint64_t RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Qui va la versione KeccakF1600_StatePermute con AVX2/unrolling che hai postato prima */
void KeccakF1600_StatePermute(uint64_t s[25]) {
    /* ... Implementazione srotolata ... */
}

unsigned int keccak_absorb(uint64_t s[25], unsigned int pos, unsigned int r, const uint8_t *in, size_t inlen) {
    while(inlen > 0) {
        s[pos/8] ^= (uint64_t)in[0] << (8*(pos%8));
        in++; inlen--; pos++;
        if(pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
    }
    return pos;
}

void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p) {
    s[pos/8] ^= (uint64_t)p << (8*(pos%8));
    s[(r-1)/8] ^= 0x8000000000000000ULL;
    KeccakF1600_StatePermute(s);
}

unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25], unsigned int pos, unsigned int r) {
    for(size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(s[pos/8] >> (8*(pos%8)));
        pos++;
        if(pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
    }
    return pos;
}