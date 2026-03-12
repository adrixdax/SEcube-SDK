/* * =========================================================================
 * CONTROLLO DI SICUREZZA PRE-COMPILATORE
 * Questo header non usa un config.h fisso. Deve essere incluso da un file 
 * sorgente (.c) che ha già definito DILITHIUM_MODE (2, 3 o 5).
 * ========================================================================= 
 */
#ifndef SE3_ALGO_DILITHIUM_PARAMS_H
#define SE3_ALGO_DILITHIUM_PARAMS_H

#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2
#endif

#ifndef DILITHIUM_MODE
    #error "ATTENZIONE: Devi definire DILITHIUM_MODE (2, 3 o 5) prima di includere params.h!"
#endif

/* ========================================================================= *
 * Parametri Matematici Globali (Dilithium)
 * ========================================================================= */
#define DIL_SEEDBYTES 32
#define DIL_CRHBYTES 64
#define DIL_TRBYTES 64
#define DIL_RNDBYTES 32
#define DIL_N 256
#define DIL_Q 8380417
#define DIL_QINV 58728449
#define DIL_D 13
#define DIL_ROOT_OF_UNITY 1753
#define DILITHIUM_MODE 2

/* ========================================================================= *
 * Parametri per le primitive simmetriche (SHAKE128/256)
 * ========================================================================= */
#ifndef STREAM128_BLOCKBYTES
    #define DIL_STREAM128_BLOCKBYTES 168  // Aggiunto DIL_
#endif

#ifndef STREAM256_BLOCKBYTES
    #define DIL_STREAM256_BLOCKBYTES 136  // Aggiunto DIL_
#endif

/* ========================================================================= *
 * Profili di Sicurezza (NIST Security Levels)
 * ========================================================================= */
#if DILITHIUM_MODE == 2
    // Livello 2 (Equivalente AES-128) - Ideale per microcontrollori
    #define DIL_K 4
    #define DIL_L 4
    #define ETA 2
    #define TAU 39
    #define BETA 78
    #define GAMMA1 (1 << 17)
    #define GAMMA2 ((DIL_Q-1)/88)
    #define OMEGA 80
    #define CTILDEBYTES 32
    #define DIL_POLYZ_PACKEDBYTES 576
    #define DIL_POLYW1_PACKEDBYTES 192
    #define DIL_POLYETA_PACKEDBYTES 96

#elif DILITHIUM_MODE == 3
    // Livello 3 (Equivalente AES-192)
    #define DIL_K 6
    #define DIL_L 5
    #define ETA 4
    #define TAU 49
    #define BETA 196
    #define GAMMA1 (1 << 19)
    #define GAMMA2 ((Q-1)/32)
    #define OMEGA 55
    #define CTILDEBYTES 48
    #define DIL_POLYZ_PACKEDBYTES 640
    #define DIL_POLYW1_PACKEDBYTES 128
    #define DIL_POLYETA_PACKEDBYTES 128

#elif DILITHIUM_MODE == 5
    // Livello 5 (Equivalente AES-256) - Massimo consumo di RAM
    #define DIL_K 8
    #define DIL_L 7
    #define ETA 2
    #define TAU 60
    #define BETA 120
    #define GAMMA1 (1 << 19)
    #define GAMMA2 ((Q-1)/32)
    #define OMEGA 75
    #define CTILDEBYTES 64
    #define DIL_POLYZ_PACKEDBYTES 640
    #define DIL_POLYW1_PACKEDBYTES 128
    #define DIL_POLYETA_PACKEDBYTES 96
#else
    #error "DILITHIUM_MODE supportati: 2, 3 o 5."
#endif

/* ========================================================================= *
 * Costanti per il Campionamento (Rejection Sampling)
 * ========================================================================= */
/* Usiamo 5 blocchi per SHAKE128 come standard di sicurezza/efficienza */
#define POLY_UNIFORM_NBLOCKS 5
#define POLY_UNIFORM_BYTES (POLY_UNIFORM_NBLOCKS * DIL_STREAM128_BLOCKBYTES)
/* Per Gamma1 usiamo SHAKE256. Il numero di blocchi dipende dalla variante. */
#if GAMMA1 == (1 << 17)
    #define POLY_GAMMA1_NBLOCKS 5
#elif GAMMA1 == (1 << 19)
    #define POLY_GAMMA1_NBLOCKS 6
#endif
#define POLY_GAMMA1_BYTES (POLY_GAMMA1_NBLOCKS * DIL_STREAM256_BLOCKBYTES)
/* ========================================================================= *
 * Dimensioni fisse per l'imballaggio (Packing) dei polinomi
 * ========================================================================= */
#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

/* ========================================================================= *
 * Dimensioni finali delle Chiavi e della Firma (In Byte)
 * ========================================================================= */
#define CRYPTO_PUBLICKEYBYTES (DIL_SEEDBYTES + DIL_K*POLYT1_PACKEDBYTES)

#define CRYPTO_SECRETKEYBYTES (2*DIL_SEEDBYTES \
                               + DIL_TRBYTES \
                               + DIL_L*DIL_POLYETA_PACKEDBYTES \
                               + DIL_K*DIL_POLYETA_PACKEDBYTES \
                               + DIL_K*POLYT0_PACKEDBYTES)

#define CRYPTO_BYTES (CTILDEBYTES + DIL_L*DIL_POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
