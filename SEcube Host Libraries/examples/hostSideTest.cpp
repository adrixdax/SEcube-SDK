#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cassert>

// Mock macro per CCRAM
#ifndef USE_CCRAM_SECTION
#define USE_CCRAM_SECTION
#endif

extern "C" {
    #include "se3_algo_mldsa.h"
    #include "se3_algo_mldsa_params.h"
    #include "se3_arith_polyvec.h"
    #include "se3_arith_ntt.h"
    #include "se3_arith_packing.h"
}

// VALORI ATTESI DA OPENSSL (SEED 0)
const uint8_t EXPECTED_RHO[32] = {
    0xba, 0x71, 0xf9, 0xf6, 0x4e, 0x11, 0xba, 0xeb, 0x58, 0xfa, 0x9c, 0x6f, 0xbb, 0x6e, 0x14, 0xe6,
    0x1f, 0x18, 0x64, 0x3d, 0xab, 0x49, 0x5b, 0x47, 0x53, 0x9a, 0x91, 0x66, 0xca, 0x01, 0x98, 0x13
};

void print_step(const std::string& msg) {
    std::cout << "\n>>> [TEST] " << msg << std::endl;
}

bool verify_buffer(const std::string& label, const uint8_t* actual, const uint8_t* expected, size_t len) {
    if (memcmp(actual, expected, len) == 0) {
        std::cout << "  [OK] " << label << " coincide!" << std::endl;
        return true;
    } else {
        std::cout << "  [FAIL] " << label << " diverge!" << std::endl;
        std::printf("  Atteso: "); for(int i=0; i<16; i++) std::printf("%02x", expected[i]);
        std::printf("\n  Ricevuto: "); for(int i=0; i<16; i++) std::printf("%02x", actual[i]);
        std::printf("\n");
        return false;
    }
}

int main() {
    const dilithium_conf_t* conf = &SE3_DILITHIUM_L2;
    uint8_t zeta[32] = {0}; // Seme forzato a zero per KAT
    uint8_t rho[32], rhoprime[64], key_seed[32];

    // --- TEST 1: Derivazione Semi ---
    print_step("Fase 1: Derivazione Semi (FIPS 204)");
    mldsa_derive_keygen_seeds(zeta, conf->k, conf->l, rho, rhoprime, key_seed);
    if(!verify_buffer("Rho", rho, EXPECTED_RHO, 32)) return -1;

    // --- TEST 2: Espansione Matrice A ---
    print_step("Fase 2: Espansione Matrice A (NTT Domain)");
    polyvecl mat[4];
    polyvec_matrix_expand(mat, rho, conf);
    // Qui verifichiamo se il primo coefficiente del primo polinomio è nel dominio NTT
    // Se poly_uniform genera coefficienti > Q o non ridotti, fallirà il prodotto.
    std::printf("  A[0][0].coeffs[0]: %d\n", mat[0].vec[0].coeffs[0]);

    // --- TEST 3: Generazione s1 e s2 ---
    print_step("Fase 3: Generazione s1 e s2 (Error Vectors)");
    polyvecl s1, s1hat;
    polyveck s2;
    polyvecl_uniform_eta(&s1, rhoprime, 0, conf);
    polyveck_uniform_eta(&s2, rhoprime, conf->l, conf);
    // Nota: s1 e s2 devono essere piccoli (eta=2 per L2)
    std::printf("  s1[0].coeffs[0] (deve essere tra -2 e 2): %d\n", s1.vec[0].coeffs[0]);

    // --- TEST 4: Trasformata NTT ---
    print_step("Fase 4: Forward NTT su s1");
    s1hat = s1;
    polyvecl_ntt(&s1hat, conf);
    // Se s1hat ha valori enormi, la NTT non sta usando la riduzione di Montgomery correttamente

    // --- TEST 5: Prodotto Matrice-Vettore ---
    print_step("Fase 5: Prodotto Pointwise A * s1");
    polyveck t1;
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat, conf);

    // --- TEST 6: Inverse NTT e Somma Errore ---
    print_step("Fase 6: InvNTT e Somma s2");
    polyveck_invntt_tomont(&t1, conf);
    polyveck_add(&t1, &t1, &s2, conf);

    // PUNTO CRITICO: Correzione dei segni prima del packing
    print_step("Fase 7: Normalizzazione CADDQ (Range [0, Q-1])");
    polyveck_caddq(&t1, conf);

    // --- TEST 7: Power2Round e Packing ---
    print_step("Fase 8: Decomposizione t1/t0 e Packing PK");
    polyveck t0;
    polyveck_power2round(&t1, &t0, &t1, conf);

    uint8_t pk_serialized[1312];
    pack_pk(pk_serialized, rho, &t1, conf);

    // Confronto finale con OpenSSL (offset 32 è l'inizio di t1)
    const uint8_t EXPECTED_T1_START[16] = {
        0x1c, 0x44, 0xf8, 0x26, 0xbb, 0xd5, 0x6e, 0x34, 0xe5, 0x5d, 0xb5, 0xe5, 0xe2, 0xd7, 0x33, 0x48
    };

    verify_buffer("Public Key t1 (Primi 16 byte)", pk_serialized + 32, EXPECTED_T1_START, 16);

    std::cout << "\nTest Completato." << std::endl;
    return 0;
}