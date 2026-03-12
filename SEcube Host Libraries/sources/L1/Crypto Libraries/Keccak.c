#include "Keccak.h"

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KeccakF_RotationConstants[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static const int KeccakF_PiLane[25] = {
    10,  7, 11, 17, 18,
     3,  5, 16,  8, 21,
    24,  4, 15, 23, 19,
    13, 12,  2, 20, 14,
    22,  9,  6,  1,  0
};

/* --- Permutazione Core Keccak-f[1600] --- */
void KeccakF1600_StatePermute(uint64_t state[25]) {
    int round, x, y;
    uint64_t tempA[25];
    uint64_t C[5], D[5];

    for (round = 0; round < 24; round++) {
        // Step Theta
        for (x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                state[x + 5 * y] ^= D[x];
            }
        }

        // Step Rho e Pi
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                tempA[KeccakF_PiLane[x + 5 * y]] = ROL64(state[x + 5 * y], KeccakF_RotationConstants[x + 5 * y]);
            }
        }

        // Step Chi
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                state[x + 5 * y] = tempA[x + 5 * y] ^ ((~tempA[((x + 1) % 5) + 5 * y]) & tempA[((x + 2) % 5) + 5 * y]);
            }
        }

        // Step Iota
        state[0] ^= KeccakF_RoundConstants[round];
    }
}

/* --- Funzioni di gestione della spugna (Assorbimento ed Estrazione) --- */
unsigned int keccak_absorb(uint64_t s[25], unsigned int pos, unsigned int r, const uint8_t *in, size_t inlen) {
    while(inlen > 0) {
        if(pos == 0 && inlen >= r) {
            for(unsigned int i = 0; i < r / 8; i++) {
                s[i] ^= load64(in + i * 8);
            }
            KeccakF1600_StatePermute(s);
            in += r;
            inlen -= r;
        } else {
            s[pos / 8] ^= (uint64_t)in[0] << (8 * (pos % 8));
            in++;
            inlen--;
            pos++;
            if(pos == r) {
                KeccakF1600_StatePermute(s);
                pos = 0;
            }
        }
    }
    return pos;
}

void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p) {
    s[pos / 8] ^= (uint64_t)p << (8 * (pos % 8));
    s[(r - 1) / 8] ^= 0x8000000000000000ULL;
    KeccakF1600_StatePermute(s);
}

unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25], unsigned int pos, unsigned int r) {
    for(size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(s[pos / 8] >> (8 * (pos % 8)));
        pos++;
        if(pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
    }
    return pos;
}