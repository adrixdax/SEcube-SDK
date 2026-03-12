/**
******************************************************************************
 * File Name          : se3_arith_ntt.h
 * Description        : Definizioni e prototipi per NTT e I-NTT (Dilithium)
 ******************************************************************************
 */
#include <stdint.h>

/** * Parametri Dilithium (NIST FIPS 204)
 * N_COEFF: Grado del polinomio (256)
 */
#define N_COEFF 256

/**
 * @brief Esegue la Forward NTT in-place.
 * @param p            Polinomio da trasformare (allineato a 8 byte).
 * @param zetas        Tabella radici unità (opzionale, NULL per usare interna).
 * */
void ntt(int32_t *__restrict p);

/**
 * @brief Esegue la Inverse NTT in-place con scaling finale. [cite: 2026-03-11]
 * @param p            Polinomio nel dominio NTT da riportare al dominio normale.
 * Include la moltiplicazione per 256^-1 mod Q. [cite: 2026-03-11]
 */
void invntt_tomont(int32_t *__restrict p);
