/* =========================================================
 * VERSIONE EMBEDDED (Cortex-M4 Target) - OTTIMIZZATA PER DIMENSIONE
 * ========================================================= */
// Inseriamo queste LUT in Flash (usano solo 48 byte totali)
// e ci fanno risparmiare centinaia di byte di istruzioni srotolate.

#include "Keccak.h"

#define NROUNDS 24

static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t keccak_rho_offsets[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};
static const uint8_t keccak_pi_lane[24] = {
    10, 7,  11, 17, 18, 3,  5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2,  20, 14, 22, 9,  6,  1
};

__attribute__((optimize("O3")))
void KeccakF1600_StatePermute(uint64_t state[25])
{
    int round, j;
    uint64_t C[5], D[5];
    uint64_t temp, temp2;

    for (round = 0; round < NROUNDS; round++) {
        // Theta - Mantenuto srotolato in C[5] perché il guadagno
        // in velocità qui giustifica i pochi byte in più.
        C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        D[0] = C[4] ^ ROL64(C[1], 1);
        D[1] = C[0] ^ ROL64(C[2], 1);
        D[2] = C[1] ^ ROL64(C[3], 1);
        D[3] = C[2] ^ ROL64(C[4], 1);
        D[4] = C[3] ^ ROL64(C[0], 1);

        for (j = 0; j < 25; j++) {
            state[j] ^= D[j % 5];
        }

        // Rho & Pi - Ottimizzazione per dimensione (Flash)
        // Abbiamo sostituito 24 righe di codice con un ciclo compatto
        temp = state[1];
        for (int i = 0; i < 24; i++) {
            j = keccak_pi_lane[i];
            temp2 = state[j];
            state[j] = ROL64(temp, keccak_rho_offsets[i]);
            temp = temp2;
        }

        // Chi - Unrolling locale riga per riga
        for (j = 0; j < 25; j += 5) {
            C[0] = state[j+0]; C[1] = state[j+1]; C[2] = state[j+2];
            C[3] = state[j+3]; C[4] = state[j+4];

            state[j+0] ^= (~C[1]) & C[2];
            state[j+1] ^= (~C[2]) & C[3];
            state[j+2] ^= (~C[3]) & C[4];
            state[j+3] ^= (~C[4]) & C[0];
            state[j+4] ^= (~C[0]) & C[1];
        }

        // Iota
        state[0] ^= KeccakF_RoundConstants[round];
    }
}

// --- QUESTE FUNZIONI MANCAVANO NEL TUO FILE KECCAK.C ---

void keccak_absorb_once(uint64_t s[25], unsigned int r, const uint8_t *in, size_t inlen, uint8_t p) {
    size_t i;
    for (i = 0; i < inlen; i += r) {
        size_t block_size = inlen - i;
        if (block_size > r) block_size = r;

        for (size_t j = 0; j < block_size; ++j) {
            ((uint8_t*)s)[j] ^= in[i + j];
        }

        if (block_size == r) {
            KeccakF1600_StatePermute(s);
        }
    }
}

unsigned int keccak_absorb(uint64_t s[25], unsigned int pos, unsigned int r, const uint8_t *in, size_t inlen) {
    size_t i = 0;
    while (i < inlen) {
        size_t len = r - pos;
        if (inlen - i < len) len = inlen - i;
        for (size_t j = 0; j < len; ++j) {
            ((uint8_t*)s)[pos + j] ^= in[i + j];
        }
        pos += len;
        i += len;
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
    }
    return pos;
}

void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p) {
    ((uint8_t*)s)[pos] ^= p;
    ((uint8_t*)s)[r - 1] ^= 0x80;
    KeccakF1600_StatePermute(s);
}

unsigned int keccak_squeeze(uint8_t *out, size_t outlen, uint64_t s[25], unsigned int pos, unsigned int r) {
    size_t i = 0;
    while (i < outlen) {
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
        size_t len = r - pos;
        if (outlen - i < len) len = outlen - i;
        for (size_t j = 0; j < len; ++j) {
            out[i + j] = ((uint8_t*)s)[pos + j];
        }
        pos += len;
        i += len;
    }
    return pos;
}

void keccak_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t s[25], unsigned int r) {
    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (size_t j = 0; j < r; ++j) {
            out[j] = ((uint8_t*)s)[j];
        }
        out += r;
        nblocks--;
    }
}

void keccak_init(keccak_state *state) {
    memset(state, 0, sizeof(keccak_state));
}
