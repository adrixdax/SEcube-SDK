#include "se3_arith_ntt.h"
#include <stdint.h>

#include "se3_algo_mldsa_params.h"

// IL VERO EROE DEL FIX: 4294967296 - 58728449
#define ML_DSA_Q_NEG_INV 4236238847U

/* Tabella a 32 bit per risparmiare 1KB di CCRAM/ROM */
static const uint32_t zetas_montgomery[256] = {
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
    189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
    5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782
};

/* --- Operazioni Matematiche Sicure (0 <= res < Q) --- */

static inline uint32_t reduce_montgomery(uint64_t a) {
    uint64_t t = (uint32_t)a * ML_DSA_Q_NEG_INV;
    uint64_t b = a + t * DIL_Q;
    uint32_t c = (uint32_t)(b >> 32);
    return (c >= DIL_Q) ? (c - DIL_Q) : c;
}

static inline uint32_t mod_add(uint32_t a, uint32_t b) {
    int32_t c = a + b - DIL_Q;
return c + ((c >> 31) & DIL_Q);
}

static inline uint32_t mod_sub(uint32_t a, uint32_t b) {
int32_t c = a - b;
return c + ((c >> 31) & DIL_Q);}

/* --- NTT e INTT --- */

void ntt(int32_t p[DIL_N]) {
    int i, j, k, step;
    int offset = DIL_N;

    for (i = 0; i < DIL_N; i++) {
        int32_t a = p[i];
        int32_t t = (a + (1 << 22)) >> 23;
        a = a - t * DIL_Q;
        a += (a >> 31) & DIL_Q;
        p[i] = a;
    }

    for (step = 1; step < DIL_N; step <<= 1) {
        k = 0;
        offset >>= 1;
        for (i = 0; i < step; i++) {
            const int32_t z_step_root = zetas_montgomery[step + i];
            int32_t * __restrict__ pj = &p[k];
            int32_t * __restrict__ pj_off = &p[k + offset];
            for (j = k; j < k + offset; j++) {
                int32_t w_even = *pj;
                int32_t t_odd = reduce_montgomery((int64_t)z_step_root * (*pj_off));
                *pj++     = mod_add(w_even, t_odd);
                *pj_off++ = mod_sub(w_even, t_odd);
            }
            k += 2 * offset;
        }
    }
}

void invntt(int32_t p[DIL_N]) {
    int i, j, k, offset;
    int step = DIL_N;
    static const int32_t inverse_degree = 8347681;

    // =========================================================================
    // 1. SANITIZZAZIONE CONSTANT-TIME
    // Niente '%', niente 'if'. Usa Barrett e CADDQ con i puntatori.
    // =========================================================================
    int32_t * __restrict__ pp = p;
    for (i = 0; i < DIL_N; i++) {
        int32_t a = *pp;
        int32_t t = (a + (1 << 22)) >> 23;
        a = a - t * DIL_Q;
        *pp++ = a + ((a >> 31) & DIL_Q);
    }

    // =========================================================================
    // 2. CICLO BUTTERFLY (INTT - Gentleman-Sande)
    // Sfrutta i puntatori per LDR/STR veloci e le funzioni inline sicure
    // =========================================================================
    for (offset = 1; offset < DIL_N; offset <<= 1) {
        step >>= 1;
        k = 0;
        for (i = 0; i < step; i++) {
            const int32_t step_root = DIL_Q - zetas_montgomery[step + (step - 1 - i)];
            int32_t * __restrict__ pj = &p[k];
            int32_t * __restrict__ pj_off = &p[k + offset];
            for (j = k; j < k + offset; j++) {
                int32_t even = *pj;
                int32_t odd = *pj_off;
                *pj++ = mod_add(even, odd);
                int32_t sub = mod_sub(even, odd);
                *pj_off++ = reduce_montgomery((int64_t)step_root * sub);
            }
            k += 2 * offset;
        }
    }
    pp = p; // Resettiamo il puntatore all'inizio dell'array
    for (i = 0; i < DIL_N / 2; i++) {
        int32_t v0 = pp[0];
        int32_t v1 = pp[1];
        v0 = reduce_montgomery((int64_t)v0 * inverse_degree);
        v1 = reduce_montgomery((int64_t)v1 * inverse_degree);
        pp[0] = v0 + ((v0 >> 31) & DIL_Q);
        pp[1] = v1 + ((v1 >> 31) & DIL_Q);
        pp += 2;
    }
}

void invntt_tomont(int32_t p[DIL_N]) {
    int i, j, k, offset;
    int step = DIL_N;
    static const int32_t inverse_degree_montgomery = 41978;

    // =========================================================================
    // 1. SANITIZZAZIONE CONSTANT-TIME
    // Via le divisioni hardware (%) e i branch (if)
    // =========================================================================
    int32_t * __restrict__ pp = p;
    for (i = 0; i < DIL_N; i++) {
        int32_t a = *pp;
        int32_t t = (a + (1 << 22)) >> 23;
        a = a - t * DIL_Q;
        *pp++ = a + ((a >> 31) & DIL_Q);
    }
    for (offset = 1; offset < DIL_N; offset <<= 1) {
        step >>= 1;
        k = 0;
        for (i = 0; i < step; i++) {
            const int32_t step_root = DIL_Q - zetas_montgomery[step + (step - 1 - i)];
            int32_t * __restrict__ pj = &p[k];
            int32_t * __restrict__ pj_off = &p[k + offset];
            for (j = k; j < k + offset; j++) {
                int32_t even = *pj;
                int32_t odd = *pj_off;
                *pj++ = mod_add(even, odd);
                int32_t sub = mod_sub(even, odd);
                *pj_off++ = reduce_montgomery((int64_t)step_root * sub);
            }
            k += 2 * offset;
        }
    }
    pp = p;
    for (i = 0; i < DIL_N / 2; i++) {
        int32_t v0 = pp[0];
        int32_t v1 = pp[1];
        pp[0] = reduce_montgomery((int64_t)v0 * inverse_degree_montgomery);
        pp[1] = reduce_montgomery((int64_t)v1 * inverse_degree_montgomery);
        pp += 2;
    }
}