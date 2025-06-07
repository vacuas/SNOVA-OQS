// SPDX-License-Identifier: MIT

/**
 * Plain C Optimized implementation for q=16. Compiler uses AVX2 instructions if available.
 *
 * Copyright (c) 2025 SNOVA TEAM
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "symmetric.h"
#include "snova.h"

#if SNOVA_q != 16
#error "SNOVA_q != 16"
#endif

#define v_SNOVA SNOVA_v
#define o_SNOVA SNOVA_o
#define l_SNOVA SNOVA_l

#define FIXED_ABQ (l_SNOVA < 4)

#define seed_length_public 16
#define seed_length_private 32
#define seed_length (seed_length_public + seed_length_private)

#define n_SNOVA (v_SNOVA + o_SNOVA)
#define m_SNOVA (o_SNOVA)
#define lsq_SNOVA (l_SNOVA * l_SNOVA)
#define alpha_SNOVA (l_SNOVA * l_SNOVA + l_SNOVA)

#define GF16s_hash (o_SNOVA * lsq_SNOVA)
#define GF16s_signature (n_SNOVA * lsq_SNOVA)
#define bytes_hash ((GF16s_hash + 1) >> 1)

#define rank (l_SNOVA)
#define sq_rank (rank * rank)  // matrix size

#define bytes_signature ((GF16s_signature + 1) >> 1)
#define bytes_salt 16
#define bytes_sig_with_salt (bytes_signature + bytes_salt)

#define GF16s_prng_public                                                                          \
    (sq_rank * (2 * (m_SNOVA * alpha_SNOVA) + m_SNOVA * (n_SNOVA * n_SNOVA - m_SNOVA * m_SNOVA)) + \
     rank * 2 * m_SNOVA * alpha_SNOVA)
//                                                     A B ^^^              P11 P12 P21 ^^^                                Q1 Q2
//                                                     ^^^ ps. Q1 matrix prng is rank, not sq_rank.
#define bytes_prng_public ((GF16s_prng_public + 1) >> 1)

#define GF16s_prng_private (v_SNOVA * o_SNOVA * rank)
//                            T12 matrix prng is rank, not sq_rank.
#define bytes_prng_private ((GF16s_prng_private + 1) >> 1)

#define bytes_pk (seed_length_public + ((m_SNOVA * o_SNOVA * o_SNOVA * lsq_SNOVA + 1) >> 1))
#define bytes_expend_pk (seed_length_public + ((m_SNOVA * (n_SNOVA * n_SNOVA + 4 * alpha_SNOVA) * sq_rank) + 1) / 2)
//                                                 P11 P12 P21 P22 ^^^     A B Q1 Q2 ^^^

#define bytes_sk                                                                                                      \
    (((sq_rank * (4 * m_SNOVA * alpha_SNOVA + m_SNOVA * (v_SNOVA * v_SNOVA + v_SNOVA * o_SNOVA + o_SNOVA * v_SNOVA) + \
                  v_SNOVA * o_SNOVA) +                                                                                \
       1) >>                                                                                                          \
      1) +                                                                                                            \
     seed_length_public + seed_length_private)
//                                         ABQ ^^^                   F11 F12 F21 ^^^ T12 ^^^

#define Keccak_HashInstance shake_t
#define Keccak_HashInitialize_SHAKE256(x) shake256_init(x)
#define Keccak_HashInitialize_SHAKE128(x) shake128_init(x)
#define Keccak_HashUpdate(a, b, c) shake_absorb(a, b, (c) / 8)
#define Keccak_HashFinal(a, b) shake_finalize(a)
#define Keccak_HashSqueeze(a, b, c) shake_squeeze(b, (c) / 8, a)

#define mt(p, q) mt4b[((p) << 4) ^ (q)]
#define inv(gf16) inv4b[(gf16)]
#define gf16_get_add(a, b) ((a) ^ (b))
#define gf16_get_mul(a, b) (mt((a), (b)))

extern uint8_t mt4b[256];
extern uint8_t inv4b[16];

typedef uint8_t gf16_t;

#define get_gf16m(gf16m, x, y) (gf16m[(((x) * rank) + (y))])
#define set_gf16m(gf16m, x, y, value) (gf16m[(((x) * rank) + (y))] = value)

typedef gf16_t gf16m_t[sq_rank];

int ct_is_negative(int val);
uint32_t ct_xgf16_is_not_zero(uint32_t val);
uint32_t ct_gf16_is_not_zero(uint8_t val);

void snova_set_zero(void *ptr, size_t size);
#define SNOVA_CLEAR(x) snova_set_zero(x, sizeof(x));

#define SNOVA_CLEAR_BYTE(x, byte) snova_set_zero(x, byte);

void convert_bytes_to_GF16s(const uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s);
void convert_GF16s_to_bytes(uint8_t *byte_array, const uint8_t *gf16_array, int num_of_GF16s);
void convert_bytes_to_GF16s_cut_in_half(const uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s);
void convert_GF16s_to_bytes_merger_in_half(uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s);

typedef gf16m_t P11_t[m_SNOVA][v_SNOVA][v_SNOVA];
typedef gf16m_t P12_t[m_SNOVA][v_SNOVA][o_SNOVA];
typedef gf16m_t P21_t[m_SNOVA][o_SNOVA][v_SNOVA];
typedef gf16m_t Aalpha_t[m_SNOVA][alpha_SNOVA];
typedef gf16m_t Balpha_t[m_SNOVA][alpha_SNOVA];
typedef gf16m_t Qalpha1_t[m_SNOVA][alpha_SNOVA];
typedef gf16m_t Qalpha2_t[m_SNOVA][alpha_SNOVA];

typedef struct {
	P11_t P11;
	P12_t P12;
	P21_t P21;
	Aalpha_t Aalpha;
	Balpha_t Balpha;
	Qalpha1_t Qalpha1;
	Qalpha2_t Qalpha2;
} map_group1;

typedef gf16m_t T12_t[v_SNOVA][o_SNOVA];
typedef gf16m_t F11_t[m_SNOVA][v_SNOVA][v_SNOVA];
typedef gf16m_t F12_t[m_SNOVA][v_SNOVA][o_SNOVA];
typedef gf16m_t F21_t[m_SNOVA][o_SNOVA][v_SNOVA];

typedef struct {
	F11_t F11;
	F12_t F12;
	F21_t F21;
} map_group2;

typedef struct {
	Aalpha_t Aalpha;
	Balpha_t Balpha;
	Qalpha1_t Qalpha1;
	Qalpha2_t Qalpha2;
	T12_t T12;
	F11_t F11;
	F12_t F12;
	F21_t F21;
	uint8_t pt_public_key_seed[seed_length_public];
	uint8_t pt_private_key_seed[seed_length_private];
} sk_gf16;

typedef gf16m_t P22_t[m_SNOVA][o_SNOVA][o_SNOVA];
typedef uint8_t P22_byte_t[(m_SNOVA * o_SNOVA * o_SNOVA * lsq_SNOVA + 1) >> 1];  // byte

typedef struct {
	uint8_t pt_public_key_seed[seed_length_public];
	P22_byte_t P22;
} public_key;

typedef struct {
	uint8_t pt_public_key_seed[seed_length_public];
	P22_t P22;
	map_group1 map1;
} public_key_expand;

typedef struct {
	uint8_t pt_public_key_seed[seed_length_public];
	uint8_t P22_map1[((sizeof(P22_t) + sizeof(map_group1)) + 1) / 2];
} public_key_expand_pack;

typedef struct {
	map_group1 map1;
	T12_t T12;
	map_group2 map2;
	public_key pk;
} snova_key_elems;

/**
 * init gf16 tables
 */
static void init_gf16_tables(void) {
	static int gf16_tables_is_init = 0;
	if (gf16_tables_is_init) {
		return;
	}
	gf16_tables_is_init = 1;
	uint8_t F_star[15] = {1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9};  // Z2[x]/(x^4+x+1)
	for (int i = 0; i < 16; ++i) {
		mt(0, i) = mt(i, 0) = 0;
	}

	for (int i = 0; i < 15; ++i)
		for (int j = 0; j < 15; ++j) {
			mt(F_star[i], F_star[j]) = F_star[(i + j) % 15];
		}
	{
		int g = F_star[1], g_inv = F_star[14], gn = 1, gn_inv = 1;
		inv4b[0] = 0;
		inv4b[1] = 1;
		for (int index = 0; index < 14; index++) {
			inv4b[(gn = mt(gn, g))] = (gn_inv = mt(gn_inv, g_inv));
		}
	}
}

// POD -> entry[a][b] * (entry[c][d] * entry[e][f] + entry[g][h] * entry[i][j])
#define POD(entry, a, b, c, d, e, f, g, h, i, j)                                                                    \
    gf16_get_mul(get_gf16m(entry, a, b), gf16_get_add(gf16_get_mul(get_gf16m(entry, c, d), get_gf16m(entry, e, f)), \
                                                      gf16_get_mul(get_gf16m(entry, g, h), get_gf16m(entry, i, j))))

/**
 * Zeroing the GF16 Matrix a.
 */
static inline void gf16m_set_zero(gf16m_t a) {
	memset(a, 0, sq_rank);
}

/**
 * Adding GF16 Matrices. c = a + b
 */
static inline void gf16m_add(const gf16m_t a, const gf16m_t b, gf16m_t c) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(c, i, j, gf16_get_add(get_gf16m(a, i, j), get_gf16m(b, i, j)));
		}
	}
}

/**
 * Multiplying GF16 Matrices. c = a * b
 */
static inline void gf16m_mul(const gf16m_t a, const gf16m_t b, gf16m_t c) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(c, i, j, gf16_get_mul(get_gf16m(a, i, 0), get_gf16m(b, 0, j)));
			for (int k = 1; k < rank; ++k) {
				set_gf16m(c, i, j, gf16_get_add(get_gf16m(c, i, j), gf16_get_mul(get_gf16m(a, i, k), get_gf16m(b, k, j))));
			}
		}
	}
}

/**
 * Scaling the GF16 Matrix. c = Scaling "a" by a factor of "k"
 */
static inline void gf16m_scale(const gf16m_t a, gf16_t k, gf16m_t c) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(c, i, j, gf16_get_mul(get_gf16m(a, i, j), k));
		}
	}
}

/**
 * Transposing the GF16 Matrix. ap = aT
 */
static inline void gf16m_transpose(const gf16m_t a, gf16m_t ap) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(ap, i, j, get_gf16m(a, j, i));
		}
	}
}

/**
 * Cloning the GF16 Matrix target = source
 */
static inline void gf16m_clone(gf16m_t target, const gf16m_t source) {
	memcpy(target, source, sq_rank);
}

/**
 * be_aI
 */
static inline void be_aI(gf16m_t target, gf16_t a) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(target, i, j, (i == j) ? a : 0);
		}
	}
}

/**
 * be_the_S
 */
static inline void be_the_S(gf16m_t target) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(target, i, j, (8 - (i + j)));
		}
	}
#if rank == 5
	set_gf16m(target, 4, 4, 9);
#endif
}

/**
 * Helper for rank5 gf16m_det5
 */
static inline gf16_t gf16m_det3(gf16m_t entry, int i0, int i1, int i2, int j0, int j1, int j2) {
	return gf16_get_add(
	           gf16_get_add(gf16_get_mul(get_gf16m(entry, j0, i0),
	                                     gf16_get_add(gf16_get_mul(get_gf16m(entry, j1, i1), get_gf16m(entry, j2, i2)),
	                                             gf16_get_mul(get_gf16m(entry, j1, i2), get_gf16m(entry, j2, i1)))),
	                        gf16_get_mul(get_gf16m(entry, j0, i1),
	                                     gf16_get_add(gf16_get_mul(get_gf16m(entry, j1, i0), get_gf16m(entry, j2, i2)),
	                                             gf16_get_mul(get_gf16m(entry, j1, i2), get_gf16m(entry, j2, i0))))),
	           gf16_get_mul(get_gf16m(entry, j0, i2), gf16_get_add(gf16_get_mul(get_gf16m(entry, j1, i0), get_gf16m(entry, j2, i1)),
	                        gf16_get_mul(get_gf16m(entry, j1, i1), get_gf16m(entry, j2, i0)))));
}

static inline gf16_t gf16m_det5(gf16m_t entry) {
	uint8_t a012 = gf16m_det3(entry, 0, 1, 2, 0, 1, 2);
	uint8_t b012 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 3), get_gf16m(entry, 4, 4)),
	                            gf16_get_mul(get_gf16m(entry, 3, 4), get_gf16m(entry, 4, 3)));

	uint8_t a013 = gf16m_det3(entry, 0, 1, 3, 0, 1, 2);
	uint8_t b013 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 2), get_gf16m(entry, 4, 4)),
	                            gf16_get_mul(get_gf16m(entry, 3, 4), get_gf16m(entry, 4, 2)));

	uint8_t a014 = gf16m_det3(entry, 0, 1, 4, 0, 1, 2);
	uint8_t b014 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 2), get_gf16m(entry, 4, 3)),
	                            gf16_get_mul(get_gf16m(entry, 3, 3), get_gf16m(entry, 4, 2)));

	uint8_t a023 = gf16m_det3(entry, 0, 2, 3, 0, 1, 2);
	uint8_t b023 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 1), get_gf16m(entry, 4, 4)),
	                            gf16_get_mul(get_gf16m(entry, 3, 4), get_gf16m(entry, 4, 1)));

	uint8_t a024 = gf16m_det3(entry, 0, 2, 4, 0, 1, 2);
	uint8_t b024 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 1), get_gf16m(entry, 4, 3)),
	                            gf16_get_mul(get_gf16m(entry, 3, 3), get_gf16m(entry, 4, 1)));

	uint8_t a034 = gf16m_det3(entry, 0, 3, 4, 0, 1, 2);
	uint8_t b034 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 1), get_gf16m(entry, 4, 2)),
	                            gf16_get_mul(get_gf16m(entry, 3, 2), get_gf16m(entry, 4, 1)));

	uint8_t a123 = gf16m_det3(entry, 1, 2, 3, 0, 1, 2);
	uint8_t b123 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 0), get_gf16m(entry, 4, 4)),
	                            gf16_get_mul(get_gf16m(entry, 3, 4), get_gf16m(entry, 4, 0)));

	uint8_t a124 = gf16m_det3(entry, 1, 2, 4, 0, 1, 2);
	uint8_t b124 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 0), get_gf16m(entry, 4, 3)),
	                            gf16_get_mul(get_gf16m(entry, 3, 3), get_gf16m(entry, 4, 0)));

	uint8_t a134 = gf16m_det3(entry, 1, 3, 4, 0, 1, 2);
	uint8_t b134 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 0), get_gf16m(entry, 4, 2)),
	                            gf16_get_mul(get_gf16m(entry, 3, 2), get_gf16m(entry, 4, 0)));

	uint8_t a234 = gf16m_det3(entry, 2, 3, 4, 0, 1, 2);
	uint8_t b234 = gf16_get_add(gf16_get_mul(get_gf16m(entry, 3, 0), get_gf16m(entry, 4, 1)),
	                            gf16_get_mul(get_gf16m(entry, 3, 1), get_gf16m(entry, 4, 0)));

	return gf16_get_mul(a012, b012) ^ gf16_get_mul(a013, b013) ^ gf16_get_mul(a014, b014) ^ gf16_get_mul(a023, b023) ^
	       gf16_get_mul(a024, b024) ^ gf16_get_mul(a034, b034) ^ gf16_get_mul(a123, b123) ^ gf16_get_mul(a124, b124) ^
	       gf16_get_mul(a134, b134) ^ gf16_get_mul(a234, b234);
}

/**
 * gf16m_det
 */
static inline gf16_t gf16m_det(gf16m_t entry) {
#if rank == 2
	return gf16_get_add(gf16_get_mul(get_gf16m(entry, 0, 0), get_gf16m(entry, 1, 1)),
	                    gf16_get_mul(get_gf16m(entry, 0, 1), get_gf16m(entry, 1, 0)));
	// (entry[0][0] * entry[1][1] + entry[0][1] * entry[1][0]);
#elif rank == 3
	return gf16_get_add(
	           gf16_get_add(
	               gf16_get_mul(get_gf16m(entry, 0, 0), gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 1), get_gf16m(entry, 2, 2)),
	                            gf16_get_mul(get_gf16m(entry, 1, 2), get_gf16m(entry, 2, 1)))),
	               // AAAAA(entry, 0, 0, 1, 1, 2, 2, 1, 2, 2, 1),
	               gf16_get_mul(get_gf16m(entry, 0, 1), gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 0), get_gf16m(entry, 2, 2)),
	                            gf16_get_mul(get_gf16m(entry, 1, 2), get_gf16m(entry, 2, 0))))),
	           gf16_get_mul(get_gf16m(entry, 0, 2), gf16_get_add(gf16_get_mul(get_gf16m(entry, 1, 0), get_gf16m(entry, 2, 1)),
	                        gf16_get_mul(get_gf16m(entry, 1, 1), get_gf16m(entry, 2, 0)))));

#elif rank == 4

	gf16_t d0 = gf16_get_mul(get_gf16m(entry, 0, 0), gf16_get_add(gf16_get_add(POD(entry, 1, 1, 2, 2, 3, 3, 2, 3, 3, 2),
	                         POD(entry, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1)),
	                         POD(entry, 1, 3, 2, 1, 3, 2, 2, 2, 3, 1)));

	gf16_t d1 = gf16_get_mul(get_gf16m(entry, 0, 1), gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 2, 3, 3, 2, 3, 3, 2),
	                         POD(entry, 1, 2, 2, 0, 3, 3, 2, 3, 3, 0)),
	                         POD(entry, 1, 3, 2, 0, 3, 2, 2, 2, 3, 0)));

	gf16_t d2 = gf16_get_mul(get_gf16m(entry, 0, 2), gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 1, 3, 3, 2, 3, 3, 1),
	                         POD(entry, 1, 1, 2, 0, 3, 3, 2, 3, 3, 0)),
	                         POD(entry, 1, 3, 2, 0, 3, 1, 2, 1, 3, 0)));

	gf16_t d3 = gf16_get_mul(get_gf16m(entry, 0, 3), gf16_get_add(gf16_get_add(POD(entry, 1, 0, 2, 1, 3, 2, 2, 2, 3, 1),
	                         POD(entry, 1, 1, 2, 0, 3, 2, 2, 2, 3, 0)),
	                         POD(entry, 1, 2, 2, 0, 3, 1, 2, 1, 3, 0)));

	return gf16_get_add(gf16_get_add(gf16_get_add(d0, d1), d2), d3);

#elif rank == 5
	return gf16m_det5(entry);
#else
// rank > 5 is not supported
#error
#endif
}

/**
 * be_aS
 */
static inline void be_aS(gf16m_t target, gf16_t a) {
	for (int i = 0; i < rank; ++i) {
		for (int j = 0; j < rank; ++j) {
			set_gf16m(target, i, j, gf16_get_mul((8 - (i + j)), a));
		}
	}
#if rank == 5
	set_gf16m(target, 4, 4, gf16_get_mul(9, a));
#endif
}

/**
 * be_invertible_by_add_aS
 */
static inline void be_invertible_by_add_aS(gf16m_t source) {
	gf16m_t temp;
	if (gf16m_det(source) == 0) {
		for (uint8_t a = 1; a < 16; ++a) {
			be_aS(temp, a);
			gf16m_add(temp, source, source);
			if (gf16m_det(source) != 0) {
				return;
			}
		}
	}
}

#define i_prime_inv(mi, alpha) ((o_SNOVA * alpha_SNOVA - alpha + mi) % o_SNOVA)

#if FIXED_ABQ
uint8_t fixed_abq[4 * m_SNOVA * alpha_SNOVA * lsq_SNOVA] = {0};
#endif

static gf16m_t S[l_SNOVA] = {0};
static uint32_t xS[l_SNOVA][lsq_SNOVA] = {0};
static int S_is_init = 0;
// GF[x]/(x^4+x+1) reduction
static inline uint32_t gf16_reduce(uint32_t idx) {
	uint32_t res, upper;

	res = idx & 0x49249249;  // Octal 0o11111111111
	upper = idx >> 12;
	res = res ^ upper ^ (upper << 3);
	upper = res >> 12;
	res = res ^ upper ^ (upper << 3);
	upper = res >> 12;
	res = res ^ upper ^ (upper << 3);

	return res & 0x249;
}

// Conversion 4 bit -> 32 bit representation
static inline uint32_t gf16_from_nibble(uint8_t idx) {
	uint32_t middle = idx | idx << 4;
	return (middle & 0x41) | ((middle << 2) & 0x208);
}

// Conversion 32 bit -> 4 bit representation
static inline uint8_t gf16_to_nibble(uint32_t idx) {
	uint32_t res = gf16_reduce(idx);
	res = res | (res >> 4);
	return (res & 0x5) | ((res >> 2) & 0xa);
}

// Conversion 32 bit -> 4 bit representation
static inline uint8_t xgf16_to_nibble(uint32_t res) {
	res = res | (res >> 4);
	return (res & 0x5) | ((res >> 2) & 0xa);
}

// Constant time GF16 inverse
// x^16 - x = 0 implies x^14 = x^-1
static inline uint32_t gf16_inv(uint32_t val) {
	val = gf16_reduce(val);
	uint32_t res2 = gf16_reduce(val * val);
	uint32_t res4 = gf16_reduce(res2 * res2);
	uint32_t res8 = gf16_reduce(res4 * res4);

	return gf16_reduce(res2 * ((res4 * res8) & 0x49249249));
}

/**
 * Generate elements of F16[S]
 */
static void gen_S_array(void) {
	if (S_is_init) {
		return;
	}

	S_is_init = 1;
	be_aI(S[0], 1);
	be_the_S(S[1]);
	for (int index = 2; index < l_SNOVA; index++) {
		gf16m_mul(S[index - 1], S[1], S[index]);
	}

	for (int index = 0; index < l_SNOVA; index++)
		for (int ij = 0; ij < lsq_SNOVA; ij++) {
			xS[index][ij] = gf16_from_nibble(S[index][ij]);
		}
}

/**
 * pk expand from seed
 *
 * Using AES-CTR encryption as a hash function
 * AES ciphertext padded with zeros.
 * The iv is also padded with zeros.
 * Using input value as the AES key.
 * The ciphertext obtained from AES encryption serves as the output of the hash
 * function.
 * @param pt_public_key_seed - Pointer to the hash input. (Fixed length of 16)
 * @param out_pk - Pointer to the hash output. (Fixed length of
 * bytes_prng_public)
 */
static void pk_expand(const uint8_t *pt_public_key_seed, uint8_t *out_pk) {
	snova_pk_expander_t instance;
	snova_pk_expander_init(&instance, pt_public_key_seed, SEED_LENGTH_PUBLIC);
	snova_pk_expander(out_pk, bytes_prng_public, &instance);
}

/**
 * @param c - output
 * @param pt_matrix - input
 */
static void gen_a_FqS(gf16_t *c, gf16m_t pt_matrix) {
	gf16m_t temp;
	be_aI(pt_matrix, c[0]);
	for (int i = 1; i < rank - 1; ++i) {
		gf16m_scale(S[i], c[i], temp);
		gf16m_add(pt_matrix, temp, pt_matrix);
	}
	gf16m_scale(S[rank - 1], (c[rank - 1] != 0) ? c[rank - 1] : 16 - (c[0] + (c[0] == 0)), temp);
	gf16m_add(pt_matrix, temp, pt_matrix);
	SNOVA_CLEAR(temp);
}

// Constant time version of gen_a_FqS
static void gen_a_FqS_ct(gf16_t *c, gf16m_t pt_matrix) {
	uint32_t xTemp[lsq_SNOVA] = {0};
	uint32_t cX = gf16_from_nibble(c[0]);

	for (int ij = 0; ij < l_SNOVA; ij++) {
		xTemp[ij * l_SNOVA + ij] = cX;
	}

	for (int i1 = 1; i1 < l_SNOVA - 1; i1++) {
		cX = gf16_from_nibble(c[i1]);
		for (int ij = 0; ij < lsq_SNOVA; ij++) {
			xTemp[ij] ^= cX * xS[i1][ij];
		}
	}

	uint8_t zero = ct_gf16_is_not_zero(c[rank - 1]);
	uint8_t val = zero * c[rank - 1] + (1 - zero) * (15 + ct_gf16_is_not_zero(c[0]) - c[0]);

	cX = gf16_from_nibble(val);
	for (int ij = 0; ij < lsq_SNOVA; ij++) {
		xTemp[ij] ^= cX * xS[l_SNOVA - 1][ij];
	}

	for (int ij = 0; ij < lsq_SNOVA; ij++) {
		pt_matrix[ij] = gf16_to_nibble(xTemp[ij]);
	}

	SNOVA_CLEAR(xTemp);
}

/**
 * Generate the linear map T12
 * @param T12 - output
 * @param seed - input
 */
static void gen_seeds_and_T12(T12_t T12, const uint8_t *seed) {
	gf16_t *pt_array;
	uint8_t prng_output_private[bytes_prng_private];
	gf16_t GF16_prng_output_private[GF16s_prng_private];

	shake256(prng_output_private, bytes_prng_private, seed, seed_length_private);
	convert_bytes_to_GF16s(prng_output_private, GF16_prng_output_private, GF16s_prng_private);

	pt_array = GF16_prng_output_private;
	for (int j = 0; j < v_SNOVA; ++j) {
		for (int k = 0; k < o_SNOVA; ++k) {
			gen_a_FqS_ct(pt_array, T12[j][k]);
			pt_array += rank;
		}
	}

	// Clear Secret!
	SNOVA_CLEAR(prng_output_private);
	SNOVA_CLEAR(GF16_prng_output_private);
}

/**
 * Generate the random part of public key
 * @param map - P11 P12 P21 Aalpha Balpha Qalpha1 Qalpha2
 * @param pt_public_key_seed - input
 */

static void gen_A_B_Q_P(map_group1 *map, const uint8_t *pt_public_key_seed) {
	uint8_t prng_output_public[bytes_prng_public];
	uint8_t Q_temp[(sizeof(Qalpha1_t) + sizeof(Qalpha2_t)) / l_SNOVA];
	// ----- pt temp -----
	pk_expand(pt_public_key_seed, prng_output_public);
#if FIXED_ABQ
	convert_bytes_to_GF16s(prng_output_public, (uint8_t *)map, GF16s_prng_public - sizeof(Q_temp));
	memcpy(map->Aalpha, fixed_abq, 4 * m_SNOVA * alpha_SNOVA * lsq_SNOVA);
#else
	convert_bytes_to_GF16s(prng_output_public, (uint8_t *)map, GF16s_prng_public - sizeof(Q_temp));
	convert_bytes_to_GF16s(prng_output_public + sizeof(prng_output_public) - ((sizeof(Q_temp) + 1) >> 1), Q_temp,
	                       sizeof(Q_temp));

	for (int pi = 0; pi < m_SNOVA; ++pi) {
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			be_invertible_by_add_aS(map->Aalpha[pi][alpha]);
		}
	}
	for (int pi = 0; pi < m_SNOVA; ++pi) {
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			be_invertible_by_add_aS(map->Balpha[pi][alpha]);
		}
	}

	gf16_t *pt_array = Q_temp;
	for (int pi = 0; pi < m_SNOVA; ++pi) {
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			gen_a_FqS(pt_array, map->Qalpha1[pi][alpha]);
			pt_array += l_SNOVA;
		}
	}
	for (int pi = 0; pi < m_SNOVA; ++pi) {
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			gen_a_FqS(pt_array, map->Qalpha2[pi][alpha]);
			pt_array += l_SNOVA;
		}
	}
#endif
}

/**
 * P22 byte to GF16
 * @param P22_gf16s - output
 * @param P22_bytes - input
 */
static void input_P22(uint8_t *P22_gf16s, const uint8_t *P22_bytes) {
	convert_bytes_to_GF16s(P22_bytes, P22_gf16s, m_SNOVA * o_SNOVA * o_SNOVA * lsq_SNOVA);
}

/**
 * Pack expanded private key. esk = (key_elems, pt_private_key_seed).
 * @param esk - pointer to output expanded private key.
 * @param key_elems - pointer to input snova key elements.
 * @param pt_private_key_seed - pointer to input private key seed.
 */
static void sk_pack(uint8_t *esk, snova_key_elems *key_elems, const uint8_t *pt_private_key_seed) {
	uint8_t *sk_gf16_ptr = (uint8_t *)(key_elems->map1.Aalpha);
	convert_GF16s_to_bytes_merger_in_half(esk, sk_gf16_ptr, (bytes_sk - (seed_length_public + seed_length_private)) * 2);
	memcpy(esk + (bytes_sk - (seed_length_public + seed_length_private)), key_elems->pk.pt_public_key_seed, seed_length_public);
	memcpy(esk + (bytes_sk - seed_length_private), pt_private_key_seed, seed_length_private);
}

/**
 * Unpack expanded secret key. skupk = (esk).
 * @param skupk - pointer to output private key (unpack).
 * @param esk - pointer to input expanded private key.
 */
static void sk_unpack(sk_gf16 *skupk, const uint8_t *esk) {
	convert_bytes_to_GF16s_cut_in_half(esk, (uint8_t *)skupk, (bytes_sk - (seed_length_public + seed_length_private)) * 2);
	memcpy(skupk->pt_public_key_seed, esk + (bytes_sk - (seed_length_public + seed_length_private)),
	       seed_length_public + seed_length_private);
}

/**
 * Pack public key. pk = (key_elems).
 */
static void pk_pack(uint8_t *pk, snova_key_elems *key_elems) {
	memcpy(pk, &key_elems->pk, bytes_pk);
}

/**
 * Unpack expend public key.
 */
static void pkx_unpack(public_key_expand *pkx_unpck, public_key_expand_pack *pkx_pck) {
	convert_bytes_to_GF16s((uint8_t *)(pkx_pck) + seed_length_public, (uint8_t *)(pkx_unpck) + seed_length_public,
	                       sizeof(P22_t) + sizeof(map_group1));
	memcpy(pkx_unpck->pt_public_key_seed, pkx_pck->pt_public_key_seed, seed_length_public);
}

/**
 * Pack expend public key.
 */
static void pkx_pack(public_key_expand_pack *pkx_pck, public_key_expand *pkx_unpck) {
	convert_GF16s_to_bytes((uint8_t *)(pkx_pck) + seed_length_public, (uint8_t *)(pkx_unpck) + seed_length_public,
	                       sizeof(P22_t) + sizeof(map_group1));
	memcpy(pkx_pck->pt_public_key_seed, pkx_unpck->pt_public_key_seed, seed_length_public);
}

/**
 * expand public key
 * @param pkx - output
 * @param pk - input
 */
static void expand_public_core(public_key_expand *pkx, const uint8_t *pk) {
	public_key *pk_stru = (public_key *)pk;
	memcpy(pkx->pt_public_key_seed, pk_stru->pt_public_key_seed, sizeof(pk_stru->pt_public_key_seed));
	// generate PRNG part of public key
	gen_A_B_Q_P(&(pkx->map1), pk_stru->pt_public_key_seed);
	// read  P22
	input_P22((uint8_t *)pkx->P22, (uint8_t *)pk_stru->P22);
}

/**
 * expand public key
 * @param pkx - output
 * @param pk - input
 */
static void expand_public_pack_core(uint8_t *pkx_pck, const uint8_t *pk) {
	public_key_expand pkx_unpack;
	public_key *pk_stru = (public_key *)pk;
	memcpy(pkx_unpack.pt_public_key_seed, pk_stru->pt_public_key_seed, sizeof(pk_stru->pt_public_key_seed));
	// generate PRNG part of public key
	gen_A_B_Q_P(&(pkx_unpack.map1), pk_stru->pt_public_key_seed);
	// read  P22
	input_P22((uint8_t *)pkx_unpack.P22, (uint8_t *)pk_stru->P22);
	// pack gf16 -> bytes
	pkx_pack((public_key_expand_pack *)pkx_pck, &pkx_unpack);
}

/**
 * createHashOut
 */
static void createSignedHash(const uint8_t *digest, uint64_t bytes_digest, const uint8_t *pt_public_key_seed,
                             const uint8_t *array_salt, uint8_t *signed_hash_out) {
	Keccak_HashInstance hashInstance;
	Keccak_HashInitialize_SHAKE256(&hashInstance);
	Keccak_HashUpdate(&hashInstance, pt_public_key_seed, 8 * seed_length_public);
	Keccak_HashUpdate(&hashInstance, digest, 8 * bytes_digest);
	Keccak_HashUpdate(&hashInstance, array_salt, 8 * bytes_salt);
	Keccak_HashFinal(&hashInstance, NULL);
	Keccak_HashSqueeze(&hashInstance, signed_hash_out, 8 * bytes_hash);
}

alignas(32) uint8_t mt4b[256] = {0};
alignas(32) uint8_t inv4b[16] = {0};

int ct_is_negative(int val) {
	return ((val >> 31) & 1);
}

// Constant time version of: (val != 0)
uint32_t ct_gf16_is_not_zero(uint8_t val) {
	return (val | (val >> 1) | (val >> 2) | (val >> 3)) & 1;
}

uint32_t ct_xgf16_is_not_zero(uint32_t val) {
	return (val | (val >> 3) | (val >> 6) | (val >> 9)) & 1;
}

void snova_set_zero(void *ptr, size_t size) {
	memset(ptr, 0, size);
}

/**
 * Convert one byte of data to GF16 representation (using only half of the
 * byte). Example: <bytes 12 34 56 78 9a bc> -> <bytes 02 01 04 03 05 ..... 0c
 * 0b>
 * @param byte_array - input (bytes)
 * @param gf16_array - output (GF16)
 * @param num_of_GF16s - GF16 amount
 */
void convert_bytes_to_GF16s(const uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s) {
	int i;
	int pairs = num_of_GF16s >> 1;

	// Convert each byte into two GF16 values
	for (i = 0; i < pairs; ++i) {
		gf16_array[i * 2] = byte_array[i] & 0x0F;
		gf16_array[i * 2 + 1] = (byte_array[i] >> 4) & 0x0F;
	}

	// Handle the last GF16 value if num_of_GF16s is odd
	if (num_of_GF16s % 2 == 1) {
		gf16_array[num_of_GF16s - 1] = byte_array[pairs] & 0x0F;
	}
}

/**
 * Convert two GF16 values to one byte.
 * Example:
 *  <bytes 02 01 04 03 05 ..... 0c 0b> -> <bytes 12 34 56 78 9a bc>
 * @param byte_array - output (bytes)
 * @param gf16_array - input (GF16)
 * @param num_of_GF16s - GF16 amount
 */
void convert_GF16s_to_bytes(uint8_t *byte_array, const uint8_t *gf16_array, int num_of_GF16s) {
	int i;
	int pairs = num_of_GF16s >> 1;

	// Convert pairs of GF16 values into one byte
	for (i = 0; i < pairs; ++i) {
		byte_array[i] = gf16_array[i * 2] | (gf16_array[i * 2 + 1] << 4);
	}

	// Handle the last GF16 value if num_of_GF16s is odd
	if (num_of_GF16s % 2 == 1) {
		byte_array[pairs] = gf16_array[num_of_GF16s - 1];
	}
}

/**
 * Convert one byte of data to GF16 representation (using only half of the
 * byte). cut_in_half Example: <bytes 12 34 56 78 9a bc> -> <bytes 02 04 06 08
 * 0a 0c 01 03 05 07 09 0b>
 * @param byte_array - input (bytes)
 * @param gf16_array - output (GF16)
 * @param num_of_GF16s - GF16 amount
 */
void convert_bytes_to_GF16s_cut_in_half(const uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s) {
	int half_GF16s = (num_of_GF16s + 1) >> 1;
	int i;

	// Extract the lower 4 bits of each byte to the first half of gf16_array
	for (i = 0; i < half_GF16s; ++i) {
		gf16_array[i] = byte_array[i] & 0x0F;
	}

	// Extract the upper 4 bits of each byte to the second half of gf16_array
	for (i = 0; i < (num_of_GF16s >> 1); ++i) {
		gf16_array[i + half_GF16s] = byte_array[i] >> 4;
	}
}

/**
 * Convert two GF16 values to one byte.
 * Example:
 *  <bytes 02 04 06 08 0a 0c 01 03 05 07 09 0b> -> <bytes 12 34 56 78 9a bc>
 * @param byte_array - output (bytes)
 * @param gf16_array - input (GF16)
 * @param num_of_GF16s - GF16 amount
 */
void convert_GF16s_to_bytes_merger_in_half(uint8_t *byte_array, uint8_t *gf16_array, int num_of_GF16s) {
	int half_GF16s = (num_of_GF16s + 1) >> 1;
	int i;

	// Combine pairs of GF16 values into one byte
	for (i = 0; i < (num_of_GF16s >> 1); ++i) {
		byte_array[i] = gf16_array[i] | (gf16_array[i + half_GF16s] << 4);
	}

	// If num_of_GF16s is odd, handle the last GF16 value separately
	if (num_of_GF16s & 1) {
		byte_array[i] = gf16_array[i];
	}
}

#define gen_F gen_F_opt
#define gen_P22 gen_P22_opt
#define sign_digest_core sign_digest_core_opt
#define verify_core verify_signture_opt
#define verify_pkx_core verify_signture_pkx_opt

static void snova_plasma_init(void) {
	static int first_plasma_time = 1;
	if (first_plasma_time) {
		first_plasma_time = 0;
	}
}

/**
 * Generate private key (F part)
 */
void gen_F_opt(map_group2 *map2, map_group1 *map1, T12_t T12) {
	uint32_t xF11[m_SNOVA * lsq_SNOVA] = {0};
	uint32_t xT12[v_SNOVA * o_SNOVA * lsq_SNOVA] = {0};
	uint32_t xtemp0[m_SNOVA * o_SNOVA * l_SNOVA * l_SNOVA];
	uint32_t xtemp1[m_SNOVA * o_SNOVA * l_SNOVA * l_SNOVA];

	memcpy(map2->F11, map1->P11, m_SNOVA * v_SNOVA * v_SNOVA * lsq_SNOVA);
	memcpy(map2->F12, map1->P12, m_SNOVA * v_SNOVA * o_SNOVA * lsq_SNOVA);
	memcpy(map2->F21, map1->P21, m_SNOVA * o_SNOVA * v_SNOVA * lsq_SNOVA);

	// F12

	for (int dj = 0; dj < v_SNOVA; ++dj)
		for (int dk = 0; dk < o_SNOVA; ++dk)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					xT12[((dj * l_SNOVA + i1) * o_SNOVA + dk) * l_SNOVA + j1] =
					    gf16_from_nibble(T12[dj][dk][i1 * l_SNOVA + j1]);
				}

	for (int di = 0; di < v_SNOVA; di++) {
		// uint32_t xtemp[m_SNOVA * o_SNOVA * l_SNOVA * l_SNOVA] = {0};
		SNOVA_CLEAR(xtemp0);
		for (int dk = 0; dk < v_SNOVA; dk++) {
			for (int mi = 0; mi < m_SNOVA; mi++)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						xF11[j1 * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1] =
						    gf16_from_nibble(map1->P11[mi][di][dk][i1 * l_SNOVA + j1]);

			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int mi = 0; mi < m_SNOVA; ++mi)
						for (int i1 = 0; i1 < l_SNOVA; ++i1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xtemp0[(dj * l_SNOVA + j1) * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1] ^=
								    xF11[k1 * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1] *
								    xT12[(dk * l_SNOVA + k1) * o_SNOVA * l_SNOVA + (dj * l_SNOVA + j1)];
		}

		for (int mi = 0; mi < m_SNOVA; ++mi)
			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						map2->F12[mi][di][dj][i1 * l_SNOVA + j1] ^=
						    gf16_to_nibble(xtemp0[(dj * l_SNOVA + j1) * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1]);
	}

	// Repeat F21

	for (int dj = 0; dj < v_SNOVA; ++dj)
		for (int dk = 0; dk < o_SNOVA; ++dk)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					xT12[((dj * l_SNOVA + j1) * o_SNOVA + dk) * l_SNOVA + i1] =
					    gf16_from_nibble(T12[dj][dk][i1 * l_SNOVA + j1]);
				}

	for (int di = 0; di < v_SNOVA; di++) {
		// uint32_t xtemp[m_SNOVA * o_SNOVA * l_SNOVA * l_SNOVA] = {0};
		SNOVA_CLEAR(xtemp1);
		for (int dk = 0; dk < v_SNOVA; dk++) {
			for (int mi = 0; mi < m_SNOVA; mi++)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						xF11[i1 * m_SNOVA * l_SNOVA + mi * l_SNOVA + j1] =
						    gf16_from_nibble(map1->P11[mi][dk][di][i1 * l_SNOVA + j1]);

			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int mi = 0; mi < m_SNOVA; ++mi)
						for (int i1 = 0; i1 < l_SNOVA; ++i1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xtemp1[(dj * l_SNOVA + j1) * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1] ^=
								    xF11[k1 * m_SNOVA * l_SNOVA + mi * l_SNOVA + i1] *
								    xT12[(dk * l_SNOVA + k1) * o_SNOVA * l_SNOVA + (dj * l_SNOVA + j1)];
		}

		for (int mi = 0; mi < m_SNOVA; ++mi)
			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						map2->F21[mi][dj][di][i1 * l_SNOVA + j1] ^=
						    gf16_to_nibble(xtemp1[(dj * l_SNOVA + i1) * m_SNOVA * l_SNOVA + mi * l_SNOVA + j1]);
	}

	SNOVA_CLEAR(xF11);
	SNOVA_CLEAR(xT12);
}

/**
 * Generate public key (P22 part)
 * @param outP22 - output
 * @param T12 - input
 * @param P21 - input
 * @param F12 - input
 */
void gen_P22_opt(P22_byte_t outP22, T12_t T12, P21_t P21, F12_t F12) {
	uint32_t xT12[v_SNOVA * o_SNOVA * lsq_SNOVA];
	uint32_t xF12[v_SNOVA * o_SNOVA * lsq_SNOVA];
	uint32_t xP21[o_SNOVA * v_SNOVA * lsq_SNOVA];
	P22_t P22 = {0};

	for (int di = 0; di < v_SNOVA; ++di)
		for (int dj = 0; dj < o_SNOVA; ++dj)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					xT12[(di * o_SNOVA + dj) * lsq_SNOVA + i1 * l_SNOVA + j1] =
					    gf16_from_nibble(T12[di][dj][i1 * l_SNOVA + j1]);

	for (int mi = 0; mi < m_SNOVA; ++mi) {
		uint32_t xP22[o_SNOVA * o_SNOVA * lsq_SNOVA] = {0};

		for (int di = 0; di < v_SNOVA; ++di)
			for (int dk = 0; dk < o_SNOVA; ++dk)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						xF12[(di * o_SNOVA + dk) * lsq_SNOVA + i1 * l_SNOVA + j1] =
						    gf16_from_nibble(F12[mi][di][dk][i1 * l_SNOVA + j1]);

		for (int di = 0; di < v_SNOVA; ++di)
			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						xP21[(dj * v_SNOVA + di) * lsq_SNOVA + i1 * l_SNOVA + j1] =
						    gf16_from_nibble(P21[mi][dj][di][i1 * l_SNOVA + j1]);

		for (int di = 0; di < v_SNOVA; ++di)
			for (int dj = 0; dj < o_SNOVA; ++dj)
				for (int dk = 0; dk < o_SNOVA; ++dk)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xP22[(dj * o_SNOVA + dk) * lsq_SNOVA + i1 * l_SNOVA + j1] ^=
								    xF12[(di * o_SNOVA + dk) * lsq_SNOVA + k1 * l_SNOVA + j1] *
								    xT12[(di * o_SNOVA + dj) * lsq_SNOVA + i1 * l_SNOVA + k1];

		for (int dj = 0; dj < o_SNOVA; ++dj)
			for (int di = 0; di < v_SNOVA; ++di)
				for (int dk = 0; dk < o_SNOVA; ++dk)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xP22[(dj * o_SNOVA + dk) * lsq_SNOVA + i1 * l_SNOVA + j1] ^=
								    xP21[(dj * v_SNOVA + di) * lsq_SNOVA + i1 * l_SNOVA + k1] *
								    xT12[(di * o_SNOVA + dk) * lsq_SNOVA + k1 * l_SNOVA + j1];

		for (int dj = 0; dj < o_SNOVA; ++dj)
			for (int dk = 0; dk < o_SNOVA; ++dk)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						P22[mi][dj][dk][i1 * l_SNOVA + j1] =
						    gf16_to_nibble(xP22[((dj * o_SNOVA + dk) * l_SNOVA + i1) * l_SNOVA + j1]);
	}

	convert_GF16s_to_bytes(outP22, (uint8_t *)P22, m_SNOVA * o_SNOVA * o_SNOVA * lsq_SNOVA);
}

/**
 * Computes signature
 */
int sign_digest_core_opt(uint8_t *pt_signature, const uint8_t *digest, uint64_t bytes_digest, const uint8_t *array_salt,
                         Aalpha_t Aalpha, Balpha_t Balpha, Qalpha1_t Qalpha1, Qalpha2_t Qalpha2, T12_t T12, F11_t F11,
                         F12_t F12, F21_t F21, const uint8_t pt_public_key_seed[seed_length_public],
                         const uint8_t pt_private_key_seed[seed_length_private]) {
	uint8_t vinegar_gf16[n_SNOVA][lsq_SNOVA] = {0};
	uint32_t xVinegar_gf16[n_SNOVA][lsq_SNOVA] = {0};
	uint32_t temp_xgf16 = 0;

	uint32_t xSolution[m_SNOVA * lsq_SNOVA] = {0};

	uint8_t hash_in_GF16[m_SNOVA * lsq_SNOVA];
	uint8_t signature_in_GF16Matrix[n_SNOVA][lsq_SNOVA];
	uint8_t signed_hash[bytes_hash];

	int flag_redo = 1;
	uint8_t num_sign = 0;

	memset(pt_signature, 0, (bytes_signature + bytes_salt));

	createSignedHash(digest, bytes_digest, pt_public_key_seed, array_salt, signed_hash);
	convert_bytes_to_GF16s(signed_hash, hash_in_GF16, GF16s_hash);

	// Try to find a solution

	uint32_t xT12[v_SNOVA][o_SNOVA][lsq_SNOVA] = {0};
	uint32_t xGauss[m_SNOVA * lsq_SNOVA][m_SNOVA * lsq_SNOVA + 1] = {0};

	for (int dj = 0; dj < v_SNOVA; ++dj)
		for (int dk = 0; dk < o_SNOVA; ++dk)
			for (int idx = 0; idx < lsq_SNOVA; ++idx) {
				xT12[dj][dk][idx] = gf16_from_nibble(T12[dj][dk][idx]);
			}

	uint32_t xAalpha[m_SNOVA][alpha_SNOVA * lsq_SNOVA] = {0};
	uint32_t xBalpha[m_SNOVA][alpha_SNOVA * lsq_SNOVA] = {0};
	uint32_t xQalpha1[m_SNOVA][alpha_SNOVA * lsq_SNOVA] = {0};
	uint32_t xQalpha2[m_SNOVA][alpha_SNOVA * lsq_SNOVA] = {0};

	for (int mi = 0; mi < m_SNOVA; ++mi)
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			int pj_prime = i_prime(mi, alpha);
			for (int idx = 0; idx < lsq_SNOVA; ++idx) {
				xQalpha1[pj_prime][alpha * lsq_SNOVA + idx] = gf16_from_nibble(Qalpha1[mi][alpha][idx]);
				xQalpha2[pj_prime][alpha * lsq_SNOVA + idx] = gf16_from_nibble(Qalpha2[mi][alpha][idx]);
				xAalpha[pj_prime][alpha * lsq_SNOVA + idx] = gf16_from_nibble(Aalpha[mi][alpha][idx]);
				xBalpha[pj_prime][alpha * lsq_SNOVA + idx] = gf16_from_nibble(Balpha[mi][alpha][idx]);
			}
		}

	do {
		// Prepare

		uint32_t xF11[v_SNOVA * l_SNOVA] = {0};
		uint32_t xF12[v_SNOVA * l_SNOVA] = {0};
		uint32_t xF21[v_SNOVA * l_SNOVA] = {0};

		uint8_t vinegar_in_byte[(v_SNOVA * lsq_SNOVA + 1) >> 1] = {0};

		uint32_t xLeft[alpha_SNOVA * v_SNOVA * l_SNOVA * l_SNOVA] = {0};
		uint32_t xRight[alpha_SNOVA * v_SNOVA * l_SNOVA * l_SNOVA] = {0};
		uint32_t xFvv_in_GF16Matrix[m_SNOVA][l_SNOVA][l_SNOVA] = {0};

		uint32_t xtemp_int[o_SNOVA * alpha_SNOVA * l_SNOVA * l_SNOVA];
		uint32_t xTemp[m_SNOVA][o_SNOVA][l_SNOVA][l_SNOVA][l_SNOVA][l_SNOVA] = {0};
		uint32_t xTemp_lr[o_SNOVA][alpha_SNOVA][lsq_SNOVA];

		num_sign++;
		if (num_sign == 255) {
			// Probability of getting here is about 2^{-1020}
			memset(pt_signature, 0, bytes_sig_with_salt);
			return -1;
		}
		flag_redo = 0;

		// generate the vinegar value
		Keccak_HashInstance hashInstance;
		Keccak_HashInitialize_SHAKE256(&hashInstance);
		Keccak_HashUpdate(&hashInstance, pt_private_key_seed, 8 * seed_length_private);
		Keccak_HashUpdate(&hashInstance, digest, 8 * bytes_digest);
		Keccak_HashUpdate(&hashInstance, array_salt, 8 * bytes_salt);
		Keccak_HashUpdate(&hashInstance, &num_sign, 8);
		Keccak_HashFinal(&hashInstance, NULL);
		Keccak_HashSqueeze(&hashInstance, vinegar_in_byte, 8 * ((v_SNOVA * lsq_SNOVA + 1) >> 1));

		convert_bytes_to_GF16s(vinegar_in_byte, (uint8_t *)vinegar_gf16, v_SNOVA * lsq_SNOVA);
		for (int jdx = 0; jdx < v_SNOVA; ++jdx)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					xVinegar_gf16[jdx][i1 * l_SNOVA + j1] = gf16_from_nibble(vinegar_gf16[jdx][i1 * l_SNOVA + j1]);
				}

		// evaluate the vinegar part of central map
		// 4 * V * L^5

		for (int mi = 0; mi < m_SNOVA; ++mi) {
			uint32_t xTemp_Q[alpha_SNOVA][v_SNOVA][lsq_SNOVA] = {0};

			memset(xtemp_int, 0, sizeof(xtemp_int));
			memset(xTemp_lr, 0, sizeof(xTemp_lr));

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xTemp_Q[alpha][jdx][i1 * l_SNOVA + j1] ^=
								    xVinegar_gf16[jdx][k1 * l_SNOVA + i1] * xQalpha1[mi][alpha * lsq_SNOVA + k1 * l_SNOVA + j1];

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1) {
							xTemp_Q[alpha][jdx][i1 * l_SNOVA + j1] &= 0x49249249;
						}

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xLeft[alpha * l_SNOVA * v_SNOVA * l_SNOVA + i1 * v_SNOVA * l_SNOVA + jdx * l_SNOVA + j1] ^=
								    xAalpha[mi][alpha * lsq_SNOVA + i1 * l_SNOVA + k1] * xTemp_Q[alpha][jdx][k1 * l_SNOVA + j1];

			for (int idx = 0; idx < v_SNOVA * alpha_SNOVA * lsq_SNOVA; ++idx) {
				xLeft[idx] = gf16_reduce(xLeft[idx]);
			}

			// Same for right
			memset(xTemp_Q, 0, sizeof(xTemp_Q));

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xTemp_Q[alpha][jdx][i1 * l_SNOVA + j1] ^=
								    xQalpha2[mi][alpha * lsq_SNOVA + i1 * l_SNOVA + k1] * xVinegar_gf16[jdx][k1 * l_SNOVA + j1];

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1) {
							xTemp_Q[alpha][jdx][i1 * l_SNOVA + j1] &= 0x49249249;
						}

			for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
				for (int jdx = 0; jdx < v_SNOVA; ++jdx)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xRight[alpha * l_SNOVA * v_SNOVA * l_SNOVA + j1 * v_SNOVA * l_SNOVA + jdx * l_SNOVA + i1] ^=
								    xTemp_Q[alpha][jdx][i1 * l_SNOVA + k1] * xBalpha[mi][alpha * lsq_SNOVA + k1 * l_SNOVA + j1];

			for (int idx = 0; idx < v_SNOVA * alpha_SNOVA * lsq_SNOVA; ++idx) {
				xRight[idx] = gf16_reduce(xRight[idx]);
			}

			// Main multiplication

			// V^2 * O * L^5

			for (int kdx = 0; kdx < v_SNOVA; kdx++)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					uint32_t xtemp3[alpha_SNOVA * l_SNOVA] = {0};

					for (int jdx = 0; jdx < v_SNOVA; jdx++)
						for (int k1 = 0; k1 < l_SNOVA; ++k1) {
							xF11[jdx * l_SNOVA + k1] = gf16_from_nibble(F11[mi][jdx][kdx][k1 * l_SNOVA + j1]);
						}

					for (int alpha_i1 = 0; alpha_i1 < alpha_SNOVA * l_SNOVA; ++alpha_i1)
						for (int jdx_k1 = 0; jdx_k1 < v_SNOVA * l_SNOVA; ++jdx_k1) {
							xtemp3[alpha_i1] ^= xLeft[alpha_i1 * v_SNOVA * l_SNOVA + jdx_k1] * xF11[jdx_k1];
						}

					for (int idx = 0; idx < alpha_SNOVA * l_SNOVA; ++idx) {
						xtemp3[idx] &= 0x49249249;
					}

					for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
						for (int i1 = 0; i1 < l_SNOVA; ++i1)
							for (int j2 = 0; j2 < l_SNOVA; ++j2) {
								int mj = i_prime_inv(mi, alpha);
								xFvv_in_GF16Matrix[mj][i1][j2] ^=
								    xtemp3[alpha * l_SNOVA + i1] *
								    xRight[(alpha * l_SNOVA + j2) * v_SNOVA * l_SNOVA + kdx * l_SNOVA + j1];
							}
				}

			// compute the coefficients of Xo and put into Gauss matrix and compute
			// the coefficients of Xo^t and add into Gauss matrix
			//

			for (int kdx = 0; kdx < o_SNOVA; kdx++)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					for (int jdx = 0; jdx < v_SNOVA; jdx++)
						for (int k1 = 0; k1 < l_SNOVA; ++k1) {
							xF12[jdx * l_SNOVA + k1] = gf16_from_nibble(F12[mi][jdx][kdx][k1 * l_SNOVA + j1]);
						}

					for (int alpha_i1 = 0; alpha_i1 < alpha_SNOVA * l_SNOVA; ++alpha_i1)
						for (int jdk_k1 = 0; jdk_k1 < v_SNOVA * l_SNOVA; ++jdk_k1)
							xtemp_int[alpha_i1 * o_SNOVA * l_SNOVA + (0 * o_SNOVA + kdx) * l_SNOVA + j1] ^=
							    xLeft[alpha_i1 * v_SNOVA * l_SNOVA + jdk_k1] * xF12[jdk_k1];
				}

			for (int idx = 0; idx < alpha_SNOVA * l_SNOVA * o_SNOVA * l_SNOVA; ++idx) {
				xtemp_int[idx] = gf16_reduce(xtemp_int[idx]);
			}

			// Calculate Temp -> Gauss matrix
			// O^2 * L^5

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xTemp_lr[kdx][alpha][i1 * l_SNOVA + j1] ^=
								    xtemp_int[alpha * l_SNOVA * o_SNOVA * l_SNOVA + i1 * o_SNOVA * l_SNOVA +
								              0 * o_SNOVA * l_SNOVA + kdx * l_SNOVA + k1] *
								    xQalpha2[mi][alpha * lsq_SNOVA + k1 * l_SNOVA + j1];

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1) {
							xTemp_lr[kdx][alpha][i1 * l_SNOVA + j1] &= 0x49249249;
						}

			// Outer product
			// O^2 * L^6

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
					int mj = i_prime_inv(mi, alpha);
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int i2 = 0; i2 < l_SNOVA; ++i2)
								for (int j2 = 0; j2 < l_SNOVA; ++j2)
									xTemp[mj][kdx][i1][j2][i2][j1] ^= xTemp_lr[kdx][alpha][i1 * l_SNOVA + i2] *
									                                  xBalpha[mi][alpha * lsq_SNOVA + j2 * l_SNOVA + j1];
				}

			// Same for Right
			// O^2 * L^5
			memset(xtemp_int, 0, sizeof(xtemp_int));
			memset(xTemp_lr, 0, sizeof(xTemp_lr));

			for (int kdx = 0; kdx < o_SNOVA; kdx++)
				for (int i1 = 0; i1 < l_SNOVA; ++i1) {
					for (int jdx = 0; jdx < v_SNOVA; jdx++)
						for (int k1 = 0; k1 < l_SNOVA; ++k1) {
							xF21[jdx * l_SNOVA + k1] = gf16_from_nibble(F21[mi][kdx][jdx][i1 * l_SNOVA + k1]);
						}

					for (int alpha_j1 = 0; alpha_j1 < alpha_SNOVA * l_SNOVA; ++alpha_j1)
						for (int jdk_k1 = 0; jdk_k1 < v_SNOVA * l_SNOVA; ++jdk_k1)
							xtemp_int[alpha_j1 * o_SNOVA * l_SNOVA + (0 * o_SNOVA + kdx) * l_SNOVA + i1] ^=
							    xRight[alpha_j1 * v_SNOVA * l_SNOVA + jdk_k1] * xF21[jdk_k1];
				}

			for (int idx = 0; idx < alpha_SNOVA * l_SNOVA * o_SNOVA * l_SNOVA; ++idx) {
				xtemp_int[idx] = gf16_reduce(xtemp_int[idx]);
			}

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int k1 = 0; k1 < l_SNOVA; ++k1)
								xTemp_lr[kdx][alpha][i1 * l_SNOVA + j1] ^=
								    xtemp_int[alpha * l_SNOVA * o_SNOVA * l_SNOVA + j1 * o_SNOVA * l_SNOVA +
								              0 * o_SNOVA * l_SNOVA + kdx * l_SNOVA + k1] *
								    xQalpha1[mi][alpha * lsq_SNOVA + i1 * l_SNOVA + k1];

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1) {
							xTemp_lr[kdx][alpha][i1 * l_SNOVA + j1] &= 0x49249249;
						}

			// Outer product
			// O^2 * L^6

			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
					int mj = i_prime_inv(mi, alpha);
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int j1 = 0; j1 < l_SNOVA; ++j1)
							for (int i2 = 0; i2 < l_SNOVA; ++i2)
								for (int j2 = 0; j2 < l_SNOVA; ++j2)
									xTemp[mj][kdx][i1][j2][i2][j1] ^= xAalpha[mi][alpha * lsq_SNOVA + i1 * l_SNOVA + j2] *
									                                  xTemp_lr[kdx][alpha][i2 * l_SNOVA + j1];
				}

			SNOVA_CLEAR(xLeft)
			SNOVA_CLEAR(xRight)
		}

		// Compose Gauss matrix
		// put hash value in the last column of Gauss matrix
		for (int index = 0; index < (m_SNOVA * lsq_SNOVA); index++) {
			xGauss[index][m_SNOVA * lsq_SNOVA] = gf16_from_nibble(hash_in_GF16[index]);
		}

		// Reorder xTemp
		for (int mi = 0; mi < m_SNOVA; ++mi)
			for (int kdx = 0; kdx < o_SNOVA; ++kdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						for (int i2 = 0; i2 < l_SNOVA; ++i2)
							for (int j2 = 0; j2 < l_SNOVA; ++j2) {
								xGauss[mi * lsq_SNOVA + i1 * l_SNOVA + j1][kdx * lsq_SNOVA + i2 * l_SNOVA + j2] =
								    gf16_reduce(xTemp[mi][kdx][i1][j2][i2][j1]);
							}

		// last column of Gauss matrix
		for (int mi = 0; mi < m_SNOVA; mi++)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1) {
					xGauss[mi * lsq_SNOVA + i1 * l_SNOVA + j1][m_SNOVA * lsq_SNOVA] ^=
					    gf16_reduce(xFvv_in_GF16Matrix[mi][i1][j1]);
				}

		// Gauss elimination in constant time
		for (int mi2 = 0; mi2 < m_SNOVA * lsq_SNOVA; ++mi2) {
			int swap = ct_xgf16_is_not_zero(xGauss[mi2][mi2]) - 1;
			for (int j2 = mi2 + 1; j2 < m_SNOVA * lsq_SNOVA; ++j2) {
				for (int k2 = mi2; k2 < m_SNOVA * lsq_SNOVA + 1; ++k2) {
					xGauss[mi2][k2] ^= xGauss[j2][k2] & swap;
				}
				swap = ct_xgf16_is_not_zero(xGauss[mi2][mi2]) - 1;
			}
			flag_redo |= swap;

			temp_xgf16 = gf16_inv(xGauss[mi2][mi2]);
			for (int k2 = mi2; k2 < m_SNOVA * lsq_SNOVA + 1; ++k2) {
				xGauss[mi2][k2] = gf16_reduce(xGauss[mi2][k2] * temp_xgf16);
			}

			for (int j2 = mi2 + 1; j2 < m_SNOVA * lsq_SNOVA; ++j2) {
				// Constant time version
				temp_xgf16 = ct_xgf16_is_not_zero(xGauss[j2][mi2]) * xGauss[j2][mi2];
				for (int k2 = mi2; k2 < m_SNOVA * lsq_SNOVA + 1; ++k2) {
					xGauss[j2][k2] = gf16_reduce(xGauss[j2][k2] ^ (xGauss[mi2][k2] * temp_xgf16));
				}
			}
		}

		// Cleanup
		if (!flag_redo) {
			SNOVA_CLEAR(xF11)
			SNOVA_CLEAR(xF12)
			SNOVA_CLEAR(xF21)
			SNOVA_CLEAR(vinegar_in_byte)
			SNOVA_CLEAR(xFvv_in_GF16Matrix)
			SNOVA_CLEAR(xtemp_int)
			SNOVA_CLEAR(xTemp)
			SNOVA_CLEAR(xTemp_lr)
		}
	} while (flag_redo);

	temp_xgf16 = 0;
	for (int mi2 = m_SNOVA * lsq_SNOVA - 1; mi2 >= 0; --mi2) {
		for (int k2 = mi2 + 1; k2 < m_SNOVA * lsq_SNOVA; ++k2) {
			temp_xgf16 ^= xGauss[mi2][k2] * xSolution[k2];
		}

		xSolution[mi2] = xGauss[mi2][m_SNOVA * lsq_SNOVA] ^ gf16_reduce(temp_xgf16);
		temp_xgf16 = 0;
	}

	for (int index = 0; index < o_SNOVA; ++index)
		for (int i1 = 0; i1 < l_SNOVA; ++i1)
			for (int j1 = 0; j1 < l_SNOVA; ++j1) {
				vinegar_gf16[index + v_SNOVA][i1 * l_SNOVA + j1] =
				    gf16_to_nibble(xSolution[index * lsq_SNOVA + i1 * l_SNOVA + j1]);
			}

	// Establish Signature

	uint32_t xSig[lsq_SNOVA] = {0};
	for (int dj = 0; dj < v_SNOVA; ++dj) {
		for (int dk = 0; dk < o_SNOVA; ++dk)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int k1 = 0; k1 < l_SNOVA; ++k1) {
						xSig[i1 * l_SNOVA + j1] ^=
						    xT12[dj][dk][i1 * l_SNOVA + k1] * xSolution[dk * lsq_SNOVA + k1 * l_SNOVA + j1];
					}

		for (int idx = 0; idx < lsq_SNOVA; ++idx) {
			signature_in_GF16Matrix[dj][idx] = vinegar_gf16[dj][idx] ^ gf16_to_nibble(xSig[idx]);
		}

		SNOVA_CLEAR(xSig)
	}

	for (int index = 0; index < o_SNOVA; ++index)
		for (int idx = 0; idx < lsq_SNOVA; ++idx) {
			signature_in_GF16Matrix[v_SNOVA + index][idx] = vinegar_gf16[v_SNOVA + index][idx];
		}

	// output signature
	convert_GF16s_to_bytes(pt_signature, (gf16_t *)signature_in_GF16Matrix, n_SNOVA * lsq_SNOVA);
	for (int i1 = 0; i1 < bytes_salt; ++i1) {
		pt_signature[bytes_signature + i1] = array_salt[i1];
	}

	// Cleanup
	SNOVA_CLEAR(vinegar_gf16)
	SNOVA_CLEAR(xVinegar_gf16)
	SNOVA_CLEAR(xSolution)
	SNOVA_CLEAR(hash_in_GF16)
	SNOVA_CLEAR(signature_in_GF16Matrix)
	SNOVA_CLEAR(signed_hash)
	SNOVA_CLEAR(xT12)
	SNOVA_CLEAR(xGauss)

	return 0;
}

/**
 * Verifies signature
 */
int verify_signture_opt_core(const uint8_t *pt_digest, uint64_t bytes_digest, const uint8_t *pt_signature,
                             const public_key_expand *pkx) {
	uint8_t hash_in_bytes[bytes_hash];
	uint8_t signed_hash[bytes_hash];
	const uint8_t *pt_salt = pt_signature + bytes_signature;

	gf16m_t signature_in_GF16Matrix[n_SNOVA];
	uint32_t Xsignature_in_GF16Matrix[n_SNOVA][lsq_SNOVA];

	Keccak_HashInstance hashInstance;
	Keccak_HashInitialize_SHAKE256(&hashInstance);
	Keccak_HashUpdate(&hashInstance, pkx->pt_public_key_seed, 8 * seed_length_public);
	Keccak_HashUpdate(&hashInstance, pt_digest, 8 * bytes_digest);
	Keccak_HashUpdate(&hashInstance, pt_salt, 8 * bytes_salt);
	Keccak_HashFinal(&hashInstance, NULL);
	Keccak_HashSqueeze(&hashInstance, signed_hash, 8 * bytes_hash);

#if (o_SNOVA * l_SNOVA) & 0x1 == 1
	signed_hash[bytes_hash - 1] &= 0x0f;
#endif

	convert_bytes_to_GF16s(pt_signature, (gf16_t *)signature_in_GF16Matrix, GF16s_signature);
	// generate PRNG part of public key

	for (int jdx = 0; jdx < n_SNOVA; ++jdx)
		for (int i1 = 0; i1 < l_SNOVA; ++i1)
			for (int j1 = 0; j1 < l_SNOVA; ++j1) {
				Xsignature_in_GF16Matrix[jdx][i1 * l_SNOVA + j1] =
				    gf16_from_nibble(signature_in_GF16Matrix[jdx][i1 * l_SNOVA + j1]);
			}

	uint32_t res[m_SNOVA][lsq_SNOVA] = {0};

	// evaluate signature GF16Matrix array
	for (int mi = 0; mi < m_SNOVA; ++mi) {
		uint32_t xLeft[alpha_SNOVA][n_SNOVA][lsq_SNOVA] = {0};
		uint32_t xRight[alpha_SNOVA][n_SNOVA][lsq_SNOVA] = {0};

		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			uint32_t xAalpha[lsq_SNOVA];
			uint32_t xBalpha[lsq_SNOVA];
			uint32_t xQalpha1[lsq_SNOVA];
			uint32_t xQalpha2[lsq_SNOVA];

			int mi_prime = i_prime_inv(mi, alpha);
			for (int idx = 0; idx < lsq_SNOVA; ++idx) {
				xAalpha[idx] = gf16_from_nibble(pkx->map1.Aalpha[mi_prime][alpha][idx]);
				xBalpha[idx] = gf16_from_nibble(pkx->map1.Balpha[mi_prime][alpha][idx]);
				xQalpha1[idx] = gf16_from_nibble(pkx->map1.Qalpha1[mi_prime][alpha][idx]);
				xQalpha2[idx] = gf16_from_nibble(pkx->map1.Qalpha2[mi_prime][alpha][idx]);
			}

			uint32_t xTemp_Q[n_SNOVA][lsq_SNOVA];
			memset(xTemp_Q, 0, sizeof(xTemp_Q));

			// Left
			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							xTemp_Q[jdx][i1 * l_SNOVA + j1] ^=
							    Xsignature_in_GF16Matrix[jdx][k1 * l_SNOVA + i1] * xQalpha1[k1 * l_SNOVA + j1];

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1) {
						xTemp_Q[jdx][i1 * l_SNOVA + j1] &= 0x49249249;
					}

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							xLeft[alpha][jdx][i1 * l_SNOVA + j1] ^=
							    xAalpha[i1 * l_SNOVA + k1] * xTemp_Q[jdx][k1 * l_SNOVA + j1];

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int idx = 0; idx < lsq_SNOVA; ++idx) {
					xLeft[alpha][jdx][idx] = gf16_reduce(xLeft[alpha][jdx][idx]);
				}

			// Right
			memset(xTemp_Q, 0, sizeof(xTemp_Q));

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							xTemp_Q[jdx][i1 * l_SNOVA + j1] ^=
							    xQalpha2[i1 * l_SNOVA + k1] * Xsignature_in_GF16Matrix[jdx][k1 * l_SNOVA + j1];

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1) {
						xTemp_Q[jdx][i1 * l_SNOVA + j1] &= 0x49249249;
					}

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int i1 = 0; i1 < l_SNOVA; ++i1)
					for (int j1 = 0; j1 < l_SNOVA; ++j1)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							xRight[alpha][jdx][i1 * l_SNOVA + j1] ^=
							    xTemp_Q[jdx][i1 * l_SNOVA + k1] * xBalpha[k1 * l_SNOVA + j1];

			for (int jdx = 0; jdx < n_SNOVA; ++jdx)
				for (int idx = 0; idx < lsq_SNOVA; ++idx) {
					xRight[alpha][jdx][idx] = gf16_reduce(xRight[alpha][jdx][idx]);
				}
		}

#if l_SNOVA != 4

		// Main loop

		uint32_t Intermediate[alpha_SNOVA][lsq_SNOVA][n_SNOVA] = {0};

		for (int dj = 0; dj < n_SNOVA; ++dj) {
			uint32_t xPublic[lsq_SNOVA][n_SNOVA];

			if (dj < v_SNOVA) {
				for (int dk = 0; dk < v_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[idx][dk] = gf16_from_nibble(pkx->map1.P11[mi][dj][dk][idx]);
					}

				for (int dk = v_SNOVA; dk < n_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[idx][dk] = gf16_from_nibble(pkx->map1.P12[mi][dj][dk - v_SNOVA][idx]);
					}
			} else {
				for (int dk = 0; dk < v_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[idx][dk] = gf16_from_nibble(pkx->map1.P21[mi][dj - v_SNOVA][dk][idx]);
					}

				for (int dk = v_SNOVA; dk < n_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[idx][dk] = gf16_from_nibble(pkx->P22[mi][dj - v_SNOVA][dk - v_SNOVA][idx]);
					}
			}

			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							for (int dk = 0; dk < n_SNOVA; ++dk)
								Intermediate[alpha][i1 * l_SNOVA + j1][dk] ^=
								    xLeft[alpha][dj][i1 * l_SNOVA + k1] * xPublic[k1 * l_SNOVA + j1][dk];
		}

		// Reduce for next multiplication
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int dk = 0; dk < n_SNOVA; ++dk) {
						Intermediate[alpha][i1 * l_SNOVA + j1][dk] &= 0x49249249;
					}

		// Second loop
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			int mj = i_prime_inv(mi, alpha);
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int k1 = 0; k1 < l_SNOVA; ++k1)
						for (int dk = 0; dk < n_SNOVA; ++dk)
							res[mj][i1 * l_SNOVA + j1] ^=
							    Intermediate[alpha][i1 * l_SNOVA + k1][dk] * xRight[alpha][dk][k1 * l_SNOVA + j1];
		}

#else

		// Prepare for main loop

		uint32_t xPublic[n_SNOVA][lsq_SNOVA][n_SNOVA];
		for (int dj = 0; dj < n_SNOVA; ++dj) {
			if (dj < v_SNOVA) {
				for (int dk = 0; dk < v_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[dj][idx][dk] = gf16_from_nibble(pkx->map1.P11[mi][dj][dk][idx]);
					}

				for (int dk = v_SNOVA; dk < n_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[dj][idx][dk] = gf16_from_nibble(pkx->map1.P12[mi][dj][dk - v_SNOVA][idx]);
					}
			} else {
				for (int dk = 0; dk < v_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[dj][idx][dk] = gf16_from_nibble(pkx->map1.P21[mi][dj - v_SNOVA][dk][idx]);
					}

				for (int dk = v_SNOVA; dk < n_SNOVA; dk++)
					for (size_t idx = 0; idx < lsq_SNOVA; idx++) {
						xPublic[dj][idx][dk] = gf16_from_nibble(pkx->P22[mi][dj - v_SNOVA][dk - v_SNOVA][idx]);
					}
			}
		}

		// Main loop
		uint32_t Intermediate[alpha_SNOVA * lsq_SNOVA * n_SNOVA] = {0};

		for (int dj = 0; dj < n_SNOVA; ++dj)
			for (int dk = 0; dk < n_SNOVA; ++dk)
				for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
					for (int i1 = 0; i1 < l_SNOVA; ++i1)
						for (int k1 = 0; k1 < l_SNOVA; ++k1)
							for (int j1 = 0; j1 < l_SNOVA; ++j1)
								Intermediate[dk * alpha_SNOVA * lsq_SNOVA + alpha * lsq_SNOVA + i1 * l_SNOVA + j1] ^=
								    xLeft[alpha][dj][i1 * l_SNOVA + k1] * xPublic[dj][k1 * l_SNOVA + j1][dk];

		// Reduce for next multiplication
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha)
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int dk = 0; dk < n_SNOVA; ++dk) {
						Intermediate[dk * alpha_SNOVA * lsq_SNOVA + alpha * lsq_SNOVA + i1 * l_SNOVA + j1] &= 0x49249249;
					}

		// Second loop
		for (int alpha = 0; alpha < alpha_SNOVA; ++alpha) {
			int mj = i_prime_inv(mi, alpha);
			for (int i1 = 0; i1 < l_SNOVA; ++i1)
				for (int j1 = 0; j1 < l_SNOVA; ++j1)
					for (int k1 = 0; k1 < l_SNOVA; ++k1)
						for (int dk = 0; dk < n_SNOVA; ++dk)
							res[mj][i1 * l_SNOVA + k1] ^=
							    Intermediate[dk * alpha_SNOVA * lsq_SNOVA + alpha * lsq_SNOVA + i1 * l_SNOVA + j1] *
							    xRight[alpha][dk][j1 * l_SNOVA + k1];
		}
#endif
	}

	// Finish up
	for (int mi = 0; mi < m_SNOVA; ++mi)
		for (int i1 = 0; i1 < l_SNOVA; ++i1)
			for (int j1 = 0; j1 < l_SNOVA; ++j1) {
				((gf16_t *)signature_in_GF16Matrix)[mi * lsq_SNOVA + i1 * l_SNOVA + j1] =
				    gf16_to_nibble(res[mi][i1 * l_SNOVA + j1]);
			}

	convert_GF16s_to_bytes(hash_in_bytes, (gf16_t *)signature_in_GF16Matrix, m_SNOVA * lsq_SNOVA);

	int result = 0;
	for (int idx = 0; idx < bytes_hash; ++idx)
		if (hash_in_bytes[idx] != signed_hash[idx]) {
			result = -1;
			break;
		}

	return result;
}

int verify_signture_opt(const uint8_t *pt_digest, uint64_t bytes_digest, const uint8_t *pt_signature, const uint8_t *pk) {
	public_key_expand pkx;
	expand_public_core(&pkx, pk);
	return verify_signture_opt_core(pt_digest, bytes_digest, pt_signature, &pkx);
}

int verify_signture_pkx_opt(const uint8_t *pt_digest, uint64_t bytes_digest, const uint8_t *pt_signature,
                            const uint8_t *pkx_pck) {
	public_key_expand pkx_unpck;
	pkx_unpack(&pkx_unpck, (public_key_expand_pack *)pkx_pck);
	return verify_signture_opt_core(pt_digest, bytes_digest, pt_signature, &pkx_unpck);
}

#if FIXED_ABQ
static void gen_ABQ(const char *abq_seed) {
	uint8_t rng_out[m_SNOVA * alpha_SNOVA * (lsq_SNOVA + l_SNOVA)];
	uint8_t q12[2 * m_SNOVA * alpha_SNOVA * l_SNOVA];

	shake256(rng_out, m_SNOVA * alpha_SNOVA * (lsq_SNOVA + l_SNOVA), (uint8_t *)abq_seed, strlen(abq_seed));

	convert_bytes_to_GF16s(rng_out, fixed_abq, 2 * m_SNOVA * alpha_SNOVA * lsq_SNOVA);
	convert_bytes_to_GF16s(&rng_out[alpha_SNOVA * lsq_SNOVA], q12, 2 * m_SNOVA * alpha_SNOVA * l_SNOVA);

	for (int pi = 0; pi < m_SNOVA; ++pi) {
		for (int index = 0; index < alpha_SNOVA; ++index) {
			// be_invertible_by_add_aS(map->Aalpha[index]);
			be_invertible_by_add_aS(&fixed_abq[(pi * alpha_SNOVA + index) * lsq_SNOVA]);
		}
		for (int index = 0; index < alpha_SNOVA; ++index) {
			// be_invertible_by_add_aS(map->Balpha[index]);
			be_invertible_by_add_aS(&fixed_abq[((m_SNOVA + pi) * alpha_SNOVA + index) * lsq_SNOVA]);
		}
		for (int index = 0; index < alpha_SNOVA; ++index) {
			// gen_a_FqS(pt_array, map->Qalpha1[index]);
			gen_a_FqS(&q12[(pi * alpha_SNOVA + index) * l_SNOVA],
			          &fixed_abq[((2 * m_SNOVA + pi) * alpha_SNOVA + index) * lsq_SNOVA]);
		}
		for (int index = 0; index < alpha_SNOVA; ++index) {
			// gen_a_FqS(pt_array, map->Qalpha2[index]);
			gen_a_FqS(&q12[((m_SNOVA + pi) * alpha_SNOVA + index) * l_SNOVA],
			          &fixed_abq[((3 * m_SNOVA + pi) * alpha_SNOVA + index) * lsq_SNOVA]);
		}
	}
}
#endif

/**
 * SNOVA init
 */
static void snova_init(void) {
	static int first_time = 1;
	if (first_time) {
		first_time = 0;
		init_gf16_tables();
		gen_S_array();

#if FIXED_ABQ
		gen_ABQ("SNOVA_ABQ");
#endif

		snova_plasma_init();
	}
}

/**
 * generate snova key elements.
 * @param key_elems - pointer to output snova key elements.
 * @param pk_seed - pointer to input public key seed.
 * @param sk_seed - pointer to input private key elements.
 */
static void generate_keys_core(snova_key_elems *key_elems, const uint8_t *pk_seed, const uint8_t *sk_seed) {
	gen_seeds_and_T12(key_elems->T12, sk_seed);
	memcpy(key_elems->pk.pt_public_key_seed, pk_seed, seed_length_public);
	gen_A_B_Q_P(&(key_elems->map1), pk_seed);
	gen_F(&(key_elems->map2), &(key_elems->map1), key_elems->T12);
	gen_P22(key_elems->pk.P22, key_elems->T12, key_elems->map1.P21, key_elems->map2.F12);
}

int expand_secret(uint8_t *esk, const uint8_t *sk) {
	const uint8_t *pk_seed = sk;
	const uint8_t *sk_seed = sk + seed_length_public;
	snova_key_elems key_elems;

	generate_keys_core(&key_elems, pk_seed, sk_seed);
	sk_pack(esk, &key_elems, sk_seed);

	// Clear Secret!
	snova_set_zero(&key_elems, sizeof(key_elems));

	return 0;
}

/**
 * Generates public and private key. where private key is the seed of private
 * key.
 * @param pk - pointer to output public key.
 * @param ssk - pointer to output private key.
 * @param pkseed - pointer to input public key seed.
 * @param skseed - pointer to input private key seed.
 */
int generate_keys_ssk(uint8_t *pk, uint8_t *ssk, const uint8_t *pkseed, const uint8_t *skseed) {
	snova_init();
	snova_key_elems key_elems;
	generate_keys_core(&key_elems, pkseed, skseed);
	pk_pack(pk, &key_elems);
	memcpy(ssk, pkseed, seed_length_public);
	memcpy(ssk + seed_length_public, skseed, seed_length_private);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&key_elems, sizeof(key_elems));
	return 0;
}

/**
 * Generates public and private key. where private key is the expanded version.
 * @param pk - pointer to output public key.
 * @param esk - pointer to output private key. (expanded)
 * @param pkseed - pointer to input public key seed.
 * @param skseed - pointer to input private key seed.
 */
int generate_keys_esk(uint8_t *pk, uint8_t *esk, const uint8_t *pkseed, const uint8_t *skseed) {
	snova_init();
	snova_key_elems key_elems;
	generate_keys_core(&key_elems, pkseed, skseed);
	pk_pack(pk, &key_elems);
	sk_pack(esk, &key_elems, skseed);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&key_elems, sizeof(key_elems));
	return 0;
}

/**
 * Generates public key. where private key is the seed of private
 * @param pk - pointer to output public key.
 * @param ssk - pointer to output private key.
 */
int generate_pk_with_ssk(uint8_t *pk, const uint8_t *ssk) {
	snova_init();
	const uint8_t *pkseed = ssk;
	const uint8_t *skseed = ssk + seed_length_public;
	snova_key_elems key_elems;

	generate_keys_core(&key_elems, pkseed, skseed);
	pk_pack(pk, &key_elems);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&key_elems, sizeof(key_elems));
	return 0;
}

/**
 * Generates public key. where private key is the expanded version.
 * @param pk - pointer to output public key.
 * @param @param esk - pointer to output private key. (expanded)
 */
int generate_pk_with_esk(uint8_t *pk, const uint8_t *esk) {
	snova_init();

	T12_t T12;
	uint8_t public_key_seed[seed_length_public];

	{
		// Limit scope of sk_upk
		sk_gf16 sk_upk;
		sk_unpack(&sk_upk, esk);
		memcpy(public_key_seed, sk_upk.pt_public_key_seed, seed_length_public);
		memcpy(T12, sk_upk.T12, sizeof(T12_t));
	}

	snova_key_elems key_elems;
	memcpy(key_elems.pk.pt_public_key_seed, public_key_seed, seed_length_public);
	gen_A_B_Q_P(&(key_elems.map1), public_key_seed);
	gen_F(&(key_elems.map2), &(key_elems.map1), T12);
	gen_P22(key_elems.pk.P22, T12, key_elems.map1.P21, key_elems.map2.F12);
	pk_pack(pk, &key_elems);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&key_elems, sizeof(key_elems));
	return 0;
}

/**
 * Expand ssk. Release map1 after use to reduce stack usage.
 */
void sign_expand_ssk(sk_gf16 *sk_upk, const uint8_t *ssk) {
	map_group1 map1;
	T12_t T12;

	gen_A_B_Q_P(&(map1), ssk);
	gen_seeds_and_T12(T12, ssk + seed_length_public);
	gen_F((map_group2 *)sk_upk->F11, &map1, T12);

	memcpy(sk_upk->Aalpha, map1.Aalpha, sizeof(Aalpha_t));
	memcpy(sk_upk->Balpha, map1.Balpha, sizeof(Balpha_t));
	memcpy(sk_upk->Qalpha1, map1.Qalpha1, sizeof(Qalpha1_t));
	memcpy(sk_upk->Qalpha2, map1.Qalpha2, sizeof(Qalpha2_t));
	memcpy(sk_upk->T12, T12, sizeof(T12_t));
	memcpy(sk_upk->pt_public_key_seed, ssk, seed_length_public);
	memcpy(sk_upk->pt_private_key_seed, ssk + seed_length_public, seed_length_private);
}

/**
 * Compute the signature using ssk (private key seed). some preparatory work
 * before using sign_digest_core()
 * @param pt_signature - pointer to output signature.
 * @param digest - pointer to input digest.
 * @param array_salt - pointer to input salt.
 * @param ssk - pointer to input private key (seed).
 */
int sign_digest_ssk(uint8_t *pt_signature, const uint8_t *digest, uint64_t bytes_digest, uint8_t *array_salt,
                    const uint8_t *ssk) {
	snova_init();
	sk_gf16 sk_upk;
	sign_expand_ssk(&sk_upk, ssk);
	int res = sign_digest_core(pt_signature, digest, bytes_digest, array_salt, sk_upk.Aalpha, sk_upk.Balpha, sk_upk.Qalpha1,
	                           sk_upk.Qalpha2, sk_upk.T12, sk_upk.F11, sk_upk.F12, sk_upk.F21, sk_upk.pt_public_key_seed,
	                           sk_upk.pt_private_key_seed);
	// Clear Secret!
	SNOVA_CLEAR_BYTE(&sk_upk, sizeof(sk_upk));
	return res;
}

/**
 * Compute the signature using esk (). some preparatory work before using
 * sign_digest_core()
 * @param pt_signature - pointer to output signature.
 * @param digest - pointer to input digest.
 * @param array_salt - pointer to input salt.
 * @param esk - pointer to input private key (expanded).
 */
int sign_digest_esk(uint8_t *pt_signature, const uint8_t *digest, uint64_t bytes_digest, uint8_t *array_salt,
                    const uint8_t *esk) {
	snova_init();
	sk_gf16 sk_upk;
	sk_unpack(&sk_upk, esk);
	int res = sign_digest_core(pt_signature, digest, bytes_digest, array_salt, sk_upk.Aalpha, sk_upk.Balpha, sk_upk.Qalpha1,
	                           sk_upk.Qalpha2, sk_upk.T12, sk_upk.F11, sk_upk.F12, sk_upk.F21, sk_upk.pt_public_key_seed,
	                           sk_upk.pt_private_key_seed);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&sk_upk, sizeof(sk_upk));
	return res;
}

/**
 * Verifies signature.
 * @param pt_digest - pointer to input digest.
 * @param pt_signature - pointer to output signature.
 * @param pk - pointer to output public key.
 * @returns - 0 if signature could be verified correctly and -1 otherwise
 */
int verify_signture(const uint8_t *pt_digest, uint64_t bytes_digest, const uint8_t *pt_signature, const uint8_t *pk) {
	snova_init();
	return verify_core(pt_digest, bytes_digest, pt_signature, pk);
}

/**
 * Verifies signature.
 * @param pt_digest - pointer to input digest.
 * @param pt_signature - pointer to output signature.
 * @param pkx - pointer to output public key expend.
 * @returns - 0 if signature could be verified correctly and -1 otherwise
 */
int verify_signture_pkx(const uint8_t *pt_digest, uint64_t bytes_digest, const uint8_t *pt_signature, const uint8_t *pkx) {
	snova_init();
	return verify_pkx_core(pt_digest, bytes_digest, pt_signature, pkx);
}

int expand_public_pack(uint8_t *pkx, const uint8_t *pk) {
	snova_init();
	expand_public_pack_core(pkx, pk);
	return 0;
}

/**
 * Generates public and private key. where private key is the seed of private
 * key.
 * @param pk - pointer to output public key.
 * @param ssk - pointer to output private key.
 * @param pkseed - pointer to input public key seed.
 * @param skseed - pointer to input private key seed.
 */
int SNOVA_NAMESPACE(genkeys)(uint8_t *pk, uint8_t *ssk, const uint8_t *seed) {
	const uint8_t *pkseed = seed;
	const uint8_t *skseed = seed + seed_length_public;

	snova_init();
	snova_key_elems key_elems;
	generate_keys_core(&key_elems, pkseed, skseed);
	pk_pack(pk, &key_elems);
	memcpy(ssk, pkseed, seed_length_public);
	memcpy(ssk + seed_length_public, skseed, seed_length_private);

	// Clear Secret!
	SNOVA_CLEAR_BYTE(&key_elems, sizeof(key_elems));
	return 0;
}

/**
 * Compute the signature using ssk (private key seed). some preparatory work
 * before using sign_digest_core()
 * @param pt_signature - pointer to output signature.
 * @param digest - pointer to input digest.
 * @param array_salt - pointer to input salt.
 * @param ssk - pointer to input private key (seed).
 */
int SNOVA_NAMESPACE(sign)(uint8_t *pt_signature, const uint8_t *digest, size_t bytes_digest, const uint8_t *array_salt,
                          const uint8_t *ssk) {
	snova_init();
	sk_gf16 sk_upk;

	sign_expand_ssk(&sk_upk, ssk);
	int res = sign_digest_core(pt_signature, digest, bytes_digest, array_salt, sk_upk.Aalpha, sk_upk.Balpha, sk_upk.Qalpha1,
	                           sk_upk.Qalpha2, sk_upk.T12, sk_upk.F11, sk_upk.F12, sk_upk.F21, sk_upk.pt_public_key_seed,
	                           sk_upk.pt_private_key_seed);
	// Clear Secret!
	SNOVA_CLEAR_BYTE(&sk_upk, sizeof(sk_upk));
	return res;
}

/**
 * Verifies signature.
 * @param pt_digest - pointer to input digest.
 * @param pt_signature - pointer to output signature.
 * @param pk - pointer to output public key.
 * @returns - 0 if signature could be verified correctly and -1 otherwise
 */
int SNOVA_NAMESPACE(verify)(const uint8_t *pt_digest, size_t bytes_digest, const uint8_t *pt_signature, const uint8_t *pk) {
	snova_init();
	return verify_core(pt_digest, bytes_digest, pt_signature, pk);
}
