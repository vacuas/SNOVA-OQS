// SPDX-License-Identifier: MIT

/**
 * Reference implementation
 *
 * Copyright (c) 2025 SNOVA TEAM
 */

#include <stdint.h>
#include <string.h>

#include "symmetric.h"
#include "snova.h"

typedef uint8_t gf_t;

gf_t gf_multtab[SNOVA_q * SNOVA_q] = {0};
gf_t gf_invtab[SNOVA_q] = {0};
gf_t gf_addtab[SNOVA_q * SNOVA_q] = {0};
gf_t gf_S[SNOVA_l * SNOVA_l2] = {0};

static inline gf_t gf_mult(const gf_t a, const gf_t b) {
	return gf_multtab[a * SNOVA_q + b];
}

static inline gf_t gf_inv(const gf_t a) {
	return gf_invtab[a];
}

static inline gf_t gf_add(const gf_t a, const gf_t b) {
	return gf_addtab[a * SNOVA_q + b];
}

static inline void gf_set_add(gf_t *a, const gf_t b) {
	*a = gf_addtab[*a * SNOVA_q + b];
}

static inline gf_t gf_sub(const gf_t a, const gf_t b) {
#if SNOVA_q != 16
	return gf_addtab[a * SNOVA_q + (SNOVA_q - b) % SNOVA_q];
#else
	return gf_addtab[a * SNOVA_q + b];
#endif
}

static inline void gf_mat_mul(gf_t *a, const gf_t *b, const gf_t *c) {
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_t sum = 0;
			for (int k1 = 0; k1 < SNOVA_l; k1++) {
				gf_set_add(&sum, gf_mult(b[i1 * SNOVA_l + k1], c[k1 * SNOVA_l + j1]));
			}
			a[i1 * SNOVA_l + j1] = sum;
		}
}

static inline void gf_mat_mul_add(gf_t *a, const gf_t *b, const gf_t *c) {
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_t sum = 0;
			for (int k1 = 0; k1 < SNOVA_l; k1++) {
				gf_set_add(&sum, gf_mult(b[i1 * SNOVA_l + k1], c[k1 * SNOVA_l + j1]));
			}
			gf_set_add(&a[i1 * SNOVA_l + j1], sum);
		}
}

static inline gf_t gf_mat_det(gf_t *a) {
	gf_t det = 0;
#if SNOVA_l == 2
	det = gf_sub(gf_mult(a[0], a[3]), gf_mult(a[1], a[2]));
#elif SNOVA_l == 3
	det = gf_mult(a[0], gf_sub(gf_mult(a[4], a[8]), gf_mult(a[5], a[7])));
	gf_set_add(&det, gf_mult(a[1], gf_sub(gf_mult(a[5], a[6]), gf_mult(a[3], a[8]))));
	gf_set_add(&det, gf_mult(a[2], gf_sub(gf_mult(a[3], a[7]), gf_mult(a[4], a[6]))));
#elif SNOVA_l == 4
	gf_t det_l;
	gf_t det_r;
#define DET_L(x, y) det_l = gf_sub(gf_mult(a[x], a[4 + y]), gf_mult(a[y], a[4 + x]))
#define DET_R(x, y) det_r = gf_sub(gf_mult(a[8 + x], a[12 + y]), gf_mult(a[8 + y], a[12 + x]))
#define DET22(x1, y1, x2, y2) \
    DET_L(x1, y1);            \
    DET_R(x2, y2);            \
    gf_set_add(&det, gf_mult(det_l, det_r))
	DET22(0, 1, 2, 3);
	DET22(0, 2, 3, 1);
	DET22(0, 3, 1, 2);
	DET22(1, 2, 0, 3);
	DET22(1, 3, 2, 0);
	DET22(2, 3, 0, 1);
#undef DET_R
#undef DET22
#undef DET_L
#elif SNOVA_l == 5
	gf_t det_l;
	gf_t det_r;
#define DET_L(x, y) det_l = gf_sub(gf_mult(a[x], a[5 + y]), gf_mult(a[y], a[5 + x]))
#define DET_R2(x, y, z) gf_mult(gf_sub(gf_mult(a[10 + x], a[15 + y]), gf_mult(a[10 + y], a[15 + x])), a[20 + z])
#define DET_R3(x, y, z) det_r = gf_add(DET_R2(x, y, z), gf_add(DET_R2(y, z, x), DET_R2(z, x, y)))
#define DET23(x1, y1, x2, y2, z2) \
    DET_L(x1, y1);                \
    DET_R3(x2, y2, z2);           \
    gf_set_add(&det, gf_mult(det_l, det_r))
	DET23(0, 1, 2, 3, 4);
	DET23(0, 2, 3, 1, 4);
	DET23(0, 3, 1, 2, 4);
	DET23(0, 4, 1, 3, 2);
	DET23(1, 2, 0, 3, 4);
	DET23(1, 3, 2, 0, 4);
	DET23(1, 4, 2, 3, 0);
	DET23(2, 3, 0, 1, 4);
	DET23(2, 4, 0, 3, 1);
	DET23(3, 4, 2, 0, 1);
#undef DET_R2
#undef DET_R3
#undef DET23
#undef DET_L
#else
#error "Unsupported rank"
#endif
	return det;
}

static void init_gf_tables(void) {
#if SNOVA_q == 16
	// GF(16)
	uint8_t F_star[15] = {1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9};  // Z2[x]/(x^4+x+1)
	for (int i1 = 0; i1 < 16; i1++) {
		gf_multtab[i1] = 0;
		gf_multtab[i1 * SNOVA_q] = 0;
	}
	for (int i1 = 0; i1 < SNOVA_q - 1; i1++)
		for (int j1 = 0; j1 < SNOVA_q - 1; j1++) {
			gf_multtab[F_star[i1] * SNOVA_q + F_star[j1]] = F_star[(i1 + j1) % (SNOVA_q - 1)];
		}

	for (int i1 = 0; i1 < SNOVA_q; i1++)
		for (int j1 = 0; j1 < SNOVA_q; j1++) {
			gf_addtab[i1 * SNOVA_q + j1] = (i1 ^ j1);
		}
#else
	// GF(prime)
	for (int i1 = 0; i1 < SNOVA_q; i1++)
		for (int j1 = 0; j1 < SNOVA_q; j1++) {
			gf_multtab[i1 * SNOVA_q + j1] = (i1 * j1) % SNOVA_q;
			gf_addtab[i1 * SNOVA_q + j1] = (i1 + j1) % SNOVA_q;
		}
#endif
	// Use that x^q = x and therefore x^(q-2) = x^-1
	for (int i1 = 0; i1 < SNOVA_q; i1++) {
		gf_t val = i1;
		for (int j1 = 3; j1 < SNOVA_q; j1++) {
			val = gf_mult(val, i1);
		}
		gf_invtab[i1] = val;
	}
}

// Set the irreducible S matrix
static void set_S(gf_t *gf_S1) {
#if SNOVA_q == 16
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_S1[i1 * SNOVA_l + j1] = 8 - (i1 + j1);
		}
#if SNOVA_l == 5
	gf_S1[SNOVA_l2 - 1] = 9;
#endif

#elif SNOVA_q == 11
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_S1[i1 * SNOVA_l + j1] = (0 + i1 + j1) & 3;
		}
	gf_S1[SNOVA_l2 - 1] = 6;

#elif SNOVA_q == 13
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_S1[i1 * SNOVA_l + j1] = (3 + i1 + j1) & 6;
		}
	gf_S1[SNOVA_l2 - 1] = 10;

#elif SNOVA_q == 17
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_S1[i1 * SNOVA_l + j1] = (2 + i1 + j1) & 5;
		}
	gf_S1[SNOVA_l2 - 1] = 4;

#elif SNOVA_q == 31
	for (int i1 = 0; i1 < SNOVA_l; i1++)
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_S1[i1 * SNOVA_l + j1] = (2 + i1 + j1) & 5;
		}
	gf_S1[SNOVA_l2 - 1] = 8;

#else

#error "Parameters not supported"
#endif
}

static void gen_S_array(void) {
	memset(gf_S, 0, sizeof(gf_S));

	for (int i1 = 0; i1 < SNOVA_l; i1++) {
		gf_S[i1 * SNOVA_l + i1] = 1;
	}

	set_S(&gf_S[1 * SNOVA_l2]);

	for (int i1 = 2; i1 < SNOVA_l; i1++) {
		gf_mat_mul(&gf_S[i1 * SNOVA_l2], &gf_S[1 * SNOVA_l2], &gf_S[(i1 - 1) * SNOVA_l2]);
	}
}

static int first_time = 1;

static void snova_init(void) {
	first_time = 0;
	init_gf_tables();
	gen_S_array();
}

/**
 * Utilities
 */
static void convert_bytes_to_GF(gf_t *gf_array, const uint8_t *byte_array, size_t num) {
	for (size_t idx = 0; idx < num; idx++) {
#if SNOVA_q > 16
		gf_array[idx] = byte_array[idx] % SNOVA_q;
#else
		if (idx & 1) {
			gf_array[idx] = (byte_array[idx / 2] >> 4) % SNOVA_q;
		} else {
			gf_array[idx] = (byte_array[idx / 2] & 0xf) % SNOVA_q;
		}
#endif
	}
}

// Used to compress PK (genkey) and SIG(sign)
static void compress_gf(uint8_t *byte_array, const gf_t *gf_array, size_t num) {
#if SNOVA_q == 11

	size_t idx = 0;
	size_t out_idx = 0;
	size_t num_bytes = BYTES_GF(num);

	do {
		uint64_t val = 0;
		uint64_t fact = 1;

		int i1 = 0;
		while (i1 < 16 && idx < num) {
			val += fact * (gf_array[idx] % SNOVA_q);
			idx++;
			i1++;
			fact *= SNOVA_q;
		}

		i1 = (i1 + 1) / 2;
		int j1 = 0;
		while (j1 < 7 && out_idx < num_bytes) {
			byte_array[out_idx] = val & 0xff;
			out_idx++;
			val = val >> 8;
			j1++;
		}
	} while (idx < num);

#elif SNOVA_q > 16
	for (size_t idx = 0; idx < num; idx++) {
		byte_array[idx] = gf_array[idx] % SNOVA_q;
	}
#else
	for (size_t idx = 0; idx < num / 2; idx++) {
		byte_array[idx] = (gf_array[2 * idx] % SNOVA_q) ^ ((gf_array[2 * idx + 1] % SNOVA_q) << 4);
		if (num & 1) {
			byte_array[num / 2] = gf_array[num - 1] % SNOVA_q;
		}
	}
#endif
}

// Used to expand PK(verify) and SIG(verify)
static int expand_gf(gf_t *gf_array, const uint8_t *byte_array, size_t num) {
#if SNOVA_q == 11

	size_t num_bytes = BYTES_GF(num);
	size_t idx = 0;
	size_t out_idx = 0;
	uint64_t val;

	do {
		val = 0;

		int i1 = 0;
		while (i1 < 7 && idx < num_bytes) {
			val = val ^ ((uint64_t)(byte_array[idx]) << (8 * i1));
			idx++;
			i1++;
		}

		int j1 = 0;
		while (j1 < 16 && out_idx < num) {
			gf_array[out_idx] = val % SNOVA_q;
			val = val / SNOVA_q;
			out_idx++;
			j1++;
		}
	} while (out_idx < num);

	if (val) {
		return -1;
	}

#else
	convert_bytes_to_GF(gf_array, byte_array, num);
#endif
	return 0;
}

static void hash_combined(uint8_t *hash_out, const uint8_t *digest, size_t len_digest, const uint8_t *pk_seed,
                          const uint8_t *salt) {
	shake_t state;
	shake256_init(&state);
	shake_absorb(&state, pk_seed, SEED_LENGTH_PUBLIC);
	shake_absorb(&state, digest, len_digest);
	shake_absorb(&state, salt, BYTES_SALT);
	shake_finalize(&state);
	shake_squeeze(hash_out, BYTES_HASH, &state);
}

/**
 * Improve q and calculate Q matrix
 */
static inline void gen_a_FqS(gf_t *Qm, gf_t *q) {
	if (!q[SNOVA_l - 1]) {
		q[SNOVA_l - 1] = SNOVA_q - (q[0] + (q[0] == 0));
	}

	for (int i1 = 0; i1 < SNOVA_l2; i1++) {
		gf_t sum = 0;
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			gf_set_add(&sum, gf_mult(q[j1], gf_S[j1 * SNOVA_l2 + i1]));
		}
		Qm[i1] = sum;
	}
}

/**
 * Expand T12 matrix and coefficients. Shared by genkey and sign
 */
static void expand_T12(gf_t *T12, const uint8_t *seed) {
	gf_t T12coef[SNOVA_o * SNOVA_v * SNOVA_l];

#if SNOVA_q != 16
	shake256(T12coef, sizeof(T12coef), seed, SEED_LENGTH_PRIVATE);
	for (size_t idx = 0; idx < SNOVA_o * SNOVA_v * SNOVA_l; idx++) {
		T12coef[idx] = T12coef[idx] % SNOVA_q;
	}
#else
	uint8_t T12bytes[(SNOVA_o * SNOVA_v * SNOVA_l) / 2];
	shake256(T12bytes, sizeof(T12bytes), seed, SEED_LENGTH_PRIVATE);
	convert_bytes_to_GF(T12coef, T12bytes, SNOVA_o * SNOVA_v * SNOVA_l);
#endif

	for (size_t idx = 0; idx < SNOVA_o * SNOVA_v; idx++) {
		gen_a_FqS(&T12[idx * SNOVA_l2], &T12coef[idx * SNOVA_l]);
	}
}

/**
 * Ensure that a matrix is invertible by adding multiples of S
 */
static inline void be_invertible_by_add_aS(gf_t *mat, const gf_t *orig) {
	memcpy(mat, orig, SNOVA_l2);
	if (gf_mat_det(mat) == 0) {
		for (gf_t f1 = 1; f1 < SNOVA_q; f1++) {
			for (int i1 = 0; i1 < SNOVA_l2; i1++) {
				gf_set_add(&mat[i1], gf_mult(f1, gf_S[SNOVA_l2 + i1]));
			}
			if (gf_mat_det(mat) != 0) {
				break;
			}
		}
	}
}

/**
 * Use last part of the P matrix to establish ABQ
 */
static void gen_ABQ(gf_t *A, gf_t *Am, gf_t *Bm, gf_t *Q1m, gf_t *Q2m) {
	gf_t *B = A + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *q1 = B + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *q2 = q1 + SNOVA_m * SNOVA_alpha * SNOVA_l;

	for (size_t idx = 0; idx < SNOVA_m * SNOVA_alpha; idx++) {
		be_invertible_by_add_aS(&Am[idx * SNOVA_l2], &A[idx * SNOVA_l2]);
		be_invertible_by_add_aS(&Bm[idx * SNOVA_l2], &B[idx * SNOVA_l2]);
		gen_a_FqS(&Q1m[idx * SNOVA_l2], &q1[idx * SNOVA_l]);
		gen_a_FqS(&Q2m[idx * SNOVA_l2], &q2[idx * SNOVA_l]);
	}
}

/**
 * Reference version of genkey.
 */
int SNOVA_NAMESPACE(genkeys)(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
	if (first_time) {
		snova_init();
	}

	/**
	 * Gen T12 matrix
	 */
	gf_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];
	gf_t P22[SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2] = {0};

	expand_T12(T12, seed + SEED_LENGTH_PUBLIC);

	/**
	 * Gen Public matrix but not ABQ
	 */
	gf_t P_matrix[NUM_GEN_PUB_GF];
	gf_t *P11 = P_matrix;
	gf_t *P12 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_n * SNOVA_l2;

	snova_pk_expander_t instance;
	snova_pk_expander_init(&instance, seed, SEED_LENGTH_PUBLIC);

	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	/**
	 * Calculate F12 matrix, use P11
	 */

	gf_t F12[SNOVA_m * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};

	for (int i1 = 0; i1 < SNOVA_m; i1++) {
		for (int j1 = 0; j1 < SNOVA_v; j1++) {
			// Squeeze P11[0..SNOVA_v * SNOVA_l2]
			for (int idx = 0; idx < SNOVA_v; idx++) {
				for (int k1 = 0; k1 < SNOVA_o; k1++) {
					// Multiply public and secret
					gf_mat_mul_add(&F12[((i1 * SNOVA_v + j1) * SNOVA_o + k1) * SNOVA_l2],
					               &P11[((i1 * SNOVA_v + j1) * SNOVA_v + idx) * SNOVA_l2],
					               &T12[(idx * SNOVA_o + k1) * SNOVA_l2]);
				}
			}
		}
	}

	// Use P12
	for (int i1 = 0; i1 < SNOVA_m * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		gf_set_add(&F12[i1], P12[i1]);
	}

	for (int i1 = 0; i1 < SNOVA_m; i1++) {
		for (int idx = 0; idx < SNOVA_v; idx++) {
			for (int k1 = 0; k1 < SNOVA_o; k1++) {
				for (int j1 = 0; j1 < SNOVA_o; j1++) {
					// Multiply two secrets
					gf_mat_mul_add(&P22[((i1 * SNOVA_o + j1) * SNOVA_o + k1) * SNOVA_l2], &T12[(idx * SNOVA_o + j1) * SNOVA_l2],
					               &F12[((i1 * SNOVA_v + idx) * SNOVA_o + k1) * SNOVA_l2]);
				}
			}
		}
	}

	/**
	 * Calculate P22. Uses P21
	 */
	for (int i1 = 0; i1 < SNOVA_m; i1++) {
		for (int j1 = 0; j1 < SNOVA_o; j1++) {
			for (int idx = 0; idx < SNOVA_v; idx++) {
				for (int k1 = 0; k1 < SNOVA_o; k1++) {
					// Multiply public and secret
					gf_mat_mul_add(&P22[((i1 * SNOVA_o + j1) * SNOVA_o + k1) * SNOVA_l2],
					               &P21[((i1 * SNOVA_o + j1) * SNOVA_v + idx) * SNOVA_l2],
					               &T12[(idx * SNOVA_o + k1) * SNOVA_l2]);
				}
			}
		}
	}

#if SNOVA_q != 16
	// Negate P22
	for (int i1 = 0; i1 < SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2; i1++) {
		P22[i1] = (SNOVA_q - P22[i1]) % SNOVA_q;
	}
#endif

	/**
	 * Output public and secret keys
	 */
	memcpy(pk, seed, SEED_LENGTH_PUBLIC);
	compress_gf(pk + SEED_LENGTH_PUBLIC, P22, SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2);
	memcpy(sk, seed, SEED_LENGTH);

	return 0;
}

/**
 * Reference version of Sign. Deterministic using the salt provided
 */
int SNOVA_NAMESPACE(sign)(uint8_t *sig, const uint8_t *digest, size_t len_digest, const uint8_t *salt, const uint8_t *sk) {
	if (first_time) {
		snova_init();
	}

	const uint8_t *seed = sk;

	gf_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];
	expand_T12(T12, seed + SEED_LENGTH_PUBLIC);

	gf_t P_matrix[NUM_GEN_PUB_GF];
	gf_t *P11 = P_matrix;
	gf_t *P12 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_n * SNOVA_l2;

	snova_pk_expander_t instance;
	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];

	snova_pk_expander_init(&instance, seed, SEED_LENGTH_PUBLIC);
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	/**
	 * Calculate F12, F21
	 */
	gf_t F12[SNOVA_m * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};
	gf_t F21[SNOVA_m * SNOVA_o * SNOVA_v * SNOVA_l2] = {0};

	for (int i1 = 0; i1 < SNOVA_m; i1++) {
		for (int j1 = 0; j1 < SNOVA_v; j1++) {
			for (int j2 = 0; j2 < SNOVA_v; j2++) {
				for (int k1 = 0; k1 < SNOVA_o; k1++) {
					// Multiply public and secret
					gf_mat_mul_add(&F12[((i1 * SNOVA_v + j1) * SNOVA_o + k1) * SNOVA_l2],
					               &P11[((i1 * SNOVA_v + j1) * SNOVA_v + j2) * SNOVA_l2], &T12[(j2 * SNOVA_o + k1) * SNOVA_l2]);
					gf_mat_mul_add(&F21[((i1 * SNOVA_o + k1) * SNOVA_v + j1) * SNOVA_l2], &T12[(j2 * SNOVA_o + k1) * SNOVA_l2],
					               &P11[((i1 * SNOVA_v + j2) * SNOVA_v + j1) * SNOVA_l2]);
				}
			}
		}
	}

	for (int i1 = 0; i1 < SNOVA_m * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		gf_set_add(&F12[i1], P12[i1]);
	}

	for (int i1 = 0; i1 < SNOVA_m * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		gf_set_add(&F21[i1], P21[i1]);
	}

	// Generate ABQ
	gf_t Am[4 * SNOVA_m * SNOVA_alpha * SNOVA_l2];
	gf_t *Bm = Am + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *Q1 = Bm + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *Q2 = Q1 + SNOVA_m * SNOVA_alpha * SNOVA_l2;

	gen_ABQ(P_matrix + (SNOVA_m * (SNOVA_n * SNOVA_n - SNOVA_o * SNOVA_o)) * SNOVA_l2, Am, Bm, Q1, Q2);

	// Calculate message has of size l^2o
	gf_t hash_in_GF16[GF16_HASH];

	uint8_t sign_hashb[BYTES_HASH];
	hash_combined(sign_hashb, digest, len_digest, sk, salt);
	convert_bytes_to_GF(hash_in_GF16, sign_hashb, GF16_HASH);

	// Find a solution for T.X
	gf_t gauss[SNOVA_m * SNOVA_l2][SNOVA_o * SNOVA_l2 + 1];
	gf_t signature_in_GF[SNOVA_n * SNOVA_l2] = {0};
	int flag_redo = 1;
	uint8_t num_sign = 0;

	do {
		memset(gauss, 0, sizeof(gauss));
		num_sign++;
		if (num_sign == 255) {
			// Probability of getting here is about q^{-255}
			memset(sig, 0, BYTES_SIGNATURE);
			return -1;
		}
		flag_redo = 0;

		// generate the vinegar value
		uint8_t vinegar_in_byte[NUM_GEN_SEC_BYTES];
		shake_t v_instance;

		shake256_init(&v_instance);
		shake_absorb(&v_instance, sk + SEED_LENGTH_PUBLIC, SEED_LENGTH_PRIVATE);
		shake_absorb(&v_instance, digest, len_digest);
		shake_absorb(&v_instance, salt, BYTES_SALT);
		shake_absorb(&v_instance, &num_sign, 1);
		shake_finalize(&v_instance);
		shake_squeeze(vinegar_in_byte, NUM_GEN_SEC_BYTES, &v_instance);

		convert_bytes_to_GF(signature_in_GF, vinegar_in_byte, SNOVA_v * SNOVA_l2);

		gf_t Left[SNOVA_m * SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};
		gf_t Right[SNOVA_m * SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};

		// evaluate the vinegar part of central map
		for (int mi = 0; mi < SNOVA_m; mi++) {
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
				for (int idx = 0; idx < SNOVA_v; ++idx) {
					gf_t gf16m_temp1[SNOVA_l2];

					// Left. Transpose multiply explicit
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++) {
							gf_t sum = 0;
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								gf_set_add(&sum, gf_mult(signature_in_GF[idx * SNOVA_l2 + k1 * SNOVA_l + i1],
								                         Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1]));
							}
							gf16m_temp1[i1 * SNOVA_l + j1] = sum;
						}
					gf_mat_mul_add(&Left[((mi * SNOVA_alpha + alpha) * SNOVA_v + idx) * SNOVA_l2],
					               &Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2], gf16m_temp1);

					// Same for right
					gf_mat_mul(gf16m_temp1, &Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2], &signature_in_GF[idx * SNOVA_l2]);
					gf_mat_mul_add(&Right[((mi * SNOVA_alpha + alpha) * SNOVA_v + idx) * SNOVA_l2], gf16m_temp1,
					               &Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2]);
				}
			}
		}

		// Calculate Fvv
		gf_t Fvv_in_GF16Matrix[SNOVA_m * SNOVA_l2] = {0};

		for (int mi = 0; mi < SNOVA_m; mi++) {
			for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
				gf_t gf16m_temp1[SNOVA_l2];
				int mi_prime = i_prime(mi, alpha);
				for (int j1 = 0; j1 < SNOVA_v; j1++) {
					for (int k1 = 0; k1 < SNOVA_v; k1++) {
						gf_mat_mul(gf16m_temp1, &Left[((mi * SNOVA_alpha + alpha) * SNOVA_v + j1) * SNOVA_l2],
						           &P11[((mi_prime * SNOVA_v + j1) * SNOVA_v + k1) * SNOVA_l2]);
						gf_mat_mul_add(&Fvv_in_GF16Matrix[mi * SNOVA_l2], gf16m_temp1,
						               &Right[((mi * SNOVA_alpha + alpha) * SNOVA_v + k1) * SNOVA_l2]);
					}
				}
			}
		}

		// Set the last column of gauss matrix
		for (int mi = 0; mi < SNOVA_m; mi++) {
			for (int i1 = 0; i1 < SNOVA_l2; i1++) {
				gauss[mi * SNOVA_l2 + i1][SNOVA_o * SNOVA_l2] =
				    gf_sub(hash_in_GF16[mi * SNOVA_l2 + i1], Fvv_in_GF16Matrix[mi * SNOVA_l2 + i1]);
			}
		}

		// compute the coefficients of Xo and put into gauss matrix and compute
		// the coefficients of Xo^t and add into gauss matrix
		for (int mi = 0; mi < SNOVA_m; mi++) {
			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
					gf_t gf16m_temp0[SNOVA_l2];
					gf_t Left_X_tmp[SNOVA_l2];
					gf_t Right_X_tmp[SNOVA_l2];
					int mi_prime = i_prime(mi, alpha);

					for (int j = 0; j < SNOVA_v; ++j) {
						gf_mat_mul(gf16m_temp0, &Left[((mi * SNOVA_alpha + alpha) * SNOVA_v + j) * SNOVA_l2],
						           &F12[((mi_prime * SNOVA_v + j) * SNOVA_o + idx) * SNOVA_l2]);
						gf_mat_mul(Left_X_tmp, gf16m_temp0, &Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2]);

						for (int ti1 = 0; ti1 < SNOVA_l; ti1++)
							for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
								for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
									for (int tj2 = 0; tj2 < SNOVA_l; tj2++) {
										int ti = ti1 * SNOVA_l + ti2;
										int tj = tj1 * SNOVA_l + tj2;
										gf_set_add(&gauss[mi * SNOVA_l2 + ti][idx * SNOVA_l2 + tj],
										           gf_mult(Left_X_tmp[ti1 * SNOVA_l + tj1],
										                   Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + tj2 * SNOVA_l + ti2]));
									}
					}

					for (int j = 0; j < SNOVA_v; ++j) {
						gf_mat_mul(gf16m_temp0, &Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2],
						           &F21[((mi_prime * SNOVA_o + idx) * SNOVA_v + j) * SNOVA_l2]);
						gf_mat_mul(Right_X_tmp, gf16m_temp0, &Right[((mi * SNOVA_alpha + alpha) * SNOVA_v + j) * SNOVA_l2]);

						for (int ti1 = 0; ti1 < SNOVA_l; ti1++)
							for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
								for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
									for (int tj2 = 0; tj2 < SNOVA_l; tj2++) {
										int ti = ti1 * SNOVA_l + ti2;
										int tj = tj1 * SNOVA_l + tj2;
										gf_set_add(&gauss[mi * SNOVA_l2 + ti][idx * SNOVA_l2 + tj],
										           gf_mult(Right_X_tmp[tj1 * SNOVA_l + ti2],
										                   Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + ti1 * SNOVA_l + tj2]));
									}
					}
				}
			}
		}

		// Gaussian elimination
		for (int i = 0; i < SNOVA_m * SNOVA_l2; ++i) {
			if (gauss[i][i] == 0) {
				for (int j = i + 1; j < SNOVA_m * SNOVA_l2; ++j) {
					if (gauss[j][i] != 0) {
						for (int k = i; k < SNOVA_m * SNOVA_l2 + 1; ++k) {
							gf_t t_GF16 = gauss[i][k];
							gauss[i][k] = gauss[j][k];
							gauss[j][k] = t_GF16;
						}
						break;
					}
				}
			}
			if (gauss[i][i] == 0) {
				flag_redo = 1;
				break;
			}

			gf_t t_GF16 = gf_inv(gauss[i][i]);
			for (int k = i; k < SNOVA_m * SNOVA_l2 + 1; ++k) {
				gauss[i][k] = gf_mult(gauss[i][k], t_GF16);
			}

			for (int j = i + 1; j < SNOVA_m * SNOVA_l2; ++j) {
				if (gauss[j][i] != 0) {
					gf_t gji = gauss[j][i];
					for (int k = i; k < SNOVA_m * SNOVA_l2 + 1; ++k) {
						gauss[j][k] = gf_sub(gauss[j][k], gf_mult(gauss[i][k], gji));
					}
				}
			}
		}
	} while (flag_redo);

	// Last step of Gaussian elimination
	gf_t solution[SNOVA_m * SNOVA_l2] = {0};

	for (int i = SNOVA_m * SNOVA_l2 - 1; i >= 0; --i) {
		gf_t sum = 0;
		for (int k = i + 1; k < SNOVA_m * SNOVA_l2; ++k) {
			gf_set_add(&sum, gf_mult(gauss[i][k], solution[k]));
		}
		solution[i] = gf_sub(gauss[i][SNOVA_m * SNOVA_l2], sum);
	}

	// Establish signature using T12
	for (int index = 0; index < SNOVA_v; ++index) {
		for (int mi = 0; mi < SNOVA_m; ++mi) {
			gf_mat_mul_add(&signature_in_GF[index * SNOVA_l2], &T12[(index * SNOVA_m + mi) * SNOVA_l2], &solution[mi * SNOVA_l2]);
		}
	}
	memcpy(signature_in_GF + SNOVA_v * SNOVA_l2, solution, SNOVA_m * SNOVA_l2);

	compress_gf(sig, signature_in_GF, SNOVA_n * SNOVA_l2);
	memcpy(sig + BYTES_SIGNATURE - BYTES_SALT, salt, BYTES_SALT);

	return 0;
}

/**
 * Reference version of verify.
 */
int SNOVA_NAMESPACE(verify)(const uint8_t *digest, size_t len_digest, const uint8_t *sig, const uint8_t *pk) {
	if (first_time) {
		snova_init();
	}

	/**
	 * Create P matrix
	 */
	gf_t P_matrix[NUM_GEN_PUB_GF];
	gf_t *P11 = P_matrix;
	gf_t *P12 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_m * SNOVA_v * SNOVA_n * SNOVA_l2;
	gf_t P22[SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2];

	if (expand_gf(P22, pk + SEED_LENGTH_PUBLIC, SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2)) {
		return -1;
	}

	snova_pk_expander_t instance;
	snova_pk_expander_init(&instance, pk, SEED_LENGTH_PUBLIC);

	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	gf_t P[SNOVA_m * SNOVA_n * SNOVA_n * SNOVA_l2] = {0};

	for (int mi = 0; mi < SNOVA_m; ++mi) {
		for (int idx = 0; idx < SNOVA_l2; idx++) {
			for (int ni = 0; ni < SNOVA_v; ++ni) {
				for (int nj = 0; nj < SNOVA_v; ++nj) {
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P11[((mi * SNOVA_v + ni) * SNOVA_v + nj) * SNOVA_l2 + idx];
				}

				for (int nj = SNOVA_v; nj < SNOVA_n; ++nj) {
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P12[((mi * SNOVA_v + ni) * SNOVA_o + (nj - SNOVA_v)) * SNOVA_l2 + idx];
				}
			}
			for (int ni = SNOVA_v; ni < SNOVA_n; ++ni) {
				for (int nj = 0; nj < SNOVA_v; ++nj) {
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P21[((mi * SNOVA_o + (ni - SNOVA_v)) * SNOVA_v + nj) * SNOVA_l2 + idx];
				}

				for (int nj = SNOVA_v; nj < SNOVA_n; ++nj) {
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P22[((mi * SNOVA_o + (ni - SNOVA_v)) * SNOVA_o + nj - SNOVA_v) * SNOVA_l2 + idx];
				}
			}
		}
	}

	/**
	 * Create ABQ matrices
	 */
	gf_t Am[4 * SNOVA_m * SNOVA_alpha * SNOVA_l2];
	gf_t *Bm = Am + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *Q1 = Bm + SNOVA_m * SNOVA_alpha * SNOVA_l2;
	gf_t *Q2 = Q1 + SNOVA_m * SNOVA_alpha * SNOVA_l2;

	gen_ABQ(P_matrix + (SNOVA_m * (SNOVA_n * SNOVA_n - SNOVA_o * SNOVA_o)) * SNOVA_l2, Am, Bm, Q1, Q2);

	gf_t signature_in_GF[NUMGF_SIGNATURE];
	if (expand_gf(signature_in_GF, sig, NUMGF_SIGNATURE)) {
		return -1;
	}

	/**
	 * Create Left and Right matrices
	 */
	gf_t Left[SNOVA_m * SNOVA_alpha * SNOVA_n * SNOVA_l2] = {0};
	gf_t Right[SNOVA_m * SNOVA_alpha * SNOVA_n * SNOVA_l2] = {0};

	for (int mi = 0; mi < SNOVA_m; mi++) {
		for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
			for (int idx = 0; idx < SNOVA_n; ++idx) {
				gf_t gf16m_temp1[SNOVA_l2];

				// Left. Transpose multiply explicit
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++) {
						gf_t sum = 0;
						for (int k1 = 0; k1 < SNOVA_l; k1++) {
							gf_set_add(&sum, gf_mult(signature_in_GF[idx * SNOVA_l2 + k1 * SNOVA_l + i1],
							                         Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1]));
						}
						gf16m_temp1[i1 * SNOVA_l + j1] = sum;
					}
				gf_mat_mul_add(&Left[((mi * SNOVA_alpha + alpha) * SNOVA_n + idx) * SNOVA_l2],
				               &Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2], gf16m_temp1);

				// Same for right
				gf_mat_mul(gf16m_temp1, &Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2], &signature_in_GF[idx * SNOVA_l2]);
				gf_mat_mul_add(&Right[((mi * SNOVA_alpha + alpha) * SNOVA_n + idx) * SNOVA_l2], gf16m_temp1,
				               &Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2]);
			}
		}
	}

	/**
	 * Evaluate central map
	 */
	gf_t hash_in_GF[SNOVA_m * SNOVA_l2] = {0};

	for (int mi = 0; mi < SNOVA_m; ++mi) {
		for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
			int mi_prime = i_prime(mi, alpha);

			for (int ni = 0; ni < SNOVA_n; ++ni) {
				gf_t sum_t0[SNOVA_l2] = {0};
				for (int nj = 0; nj < SNOVA_n; ++nj) {
					gf_mat_mul_add(sum_t0, &P[((mi_prime * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2],
					               &Right[((mi * SNOVA_alpha + alpha) * SNOVA_n + nj) * SNOVA_l2]);
				}
				gf_mat_mul_add(&hash_in_GF[mi * SNOVA_l2], &Left[((mi * SNOVA_alpha + alpha) * SNOVA_n + ni) * SNOVA_l2],
				               sum_t0);
			}
		}
	}

	/**
	 * Check hashes
	 */
	uint8_t signed_bytes[BYTES_HASH];
	uint8_t signed_gf[GF16_HASH] = {0};
	const uint8_t *salt = sig + BYTES_SIGNATURE - BYTES_SALT;
	hash_combined(signed_bytes, digest, len_digest, pk, salt);
	convert_bytes_to_GF(signed_gf, signed_bytes, GF16_HASH);

	int result = 0;
	for (int i = 0; i < GF16_HASH; ++i) {
		if (hash_in_GF[i] != signed_gf[i]) {
			result = -1;
			break;
		}
	}

	return result;
}
