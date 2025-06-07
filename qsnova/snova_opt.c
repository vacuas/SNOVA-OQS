// SPDX-License-Identifier: MIT

/**
 * Plain C Optimized implementation. Compiler uses AVX2 instructions if available.
 *
 * Copyright (c) 2025 SNOVA TEAM
 */

#include <stdint.h>
#include <string.h>

#include "symmetric.h"
#include "snova.h"

typedef uint8_t gf_t;

gf_t gf_invtab[SNOVA_q] = {0};
gf_t gf_S[SNOVA_l * SNOVA_l2] = {0};

static inline gf_t gf_mult(const gf_t a, const gf_t b) {
	return (a * b) % SNOVA_q;
}

static inline gf_t gf_inv(const gf_t a) {
	return gf_invtab[a];
}

static inline gf_t gf_add(const gf_t a, const gf_t b) {
	return (a + b) % SNOVA_q;
}

static inline void gf_set_add(gf_t *a, const gf_t b) {
	*a = (*a + b) % SNOVA_q;
}

static inline gf_t gf_sub(const gf_t a, const gf_t b) {
	return (SNOVA_q + a - b) % SNOVA_q;
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
#if SNOVA_q == 11
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

	for (int si = 2; si < SNOVA_l; si++) {
		for (int i1 = 0; i1 < SNOVA_l; i1++)
			for (int j1 = 0; j1 < SNOVA_l; j1++) {
				uint32_t sum = 0;
				for (int k1 = 0; k1 < SNOVA_l; k1++) {
					sum += gf_S[SNOVA_l2 + i1 * SNOVA_l + k1] * gf_S[(si - 1) * SNOVA_l2 + k1 * SNOVA_l + j1];
				}
				gf_S[si * SNOVA_l2 + i1 * SNOVA_l + j1] = sum % SNOVA_q;
			}
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
#if SNOVA_q > 16
	for (size_t idx = 0; idx < num; idx++) {
		gf_array[idx] = byte_array[idx] % SNOVA_q;
	}
#else
	for (size_t idx = 0; idx < num / 2; idx++) {
		gf_array[2 * idx] = (byte_array[idx] & 0xf) % SNOVA_q;
		gf_array[2 * idx + 1] = (byte_array[idx] >> 4) % SNOVA_q;
	}
	if (num & 1) {
		gf_array[num - 1] = (byte_array[num / 2] & 0xf) % SNOVA_q;
	}
#endif
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

// Create hash. Shared by sign and verify
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
		uint16_t sum = 0;
		for (int j1 = 0; j1 < SNOVA_l; j1++) {
			sum += q[j1] * gf_S[j1 * SNOVA_l2 + i1];
		}
		Qm[i1] = sum % SNOVA_q;
	}
}

/**
 * Expand T12 matrix and coefficients. Shared by genkey and sign
 */
static void expand_T12(gf_t *T12, const uint8_t *seed) {
	gf_t T12coef[SNOVA_o * SNOVA_v * SNOVA_l];

	shake256(T12coef, sizeof(T12coef), seed, SEED_LENGTH_PRIVATE);
	for (size_t idx = 0; idx < SNOVA_o * SNOVA_v * SNOVA_l; idx++) {
		T12coef[idx] = T12coef[idx] % SNOVA_q;
	}

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
				mat[i1] = (mat[i1] + (f1 * gf_S[SNOVA_l2 + i1])) % SNOVA_q;
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
	gf_t *B = A + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q1 = B + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q2 = q1 + SNOVA_o * SNOVA_alpha * SNOVA_l;

	for (size_t idx = 0; idx < SNOVA_o * SNOVA_alpha; idx++) {
		be_invertible_by_add_aS(&Am[idx * SNOVA_l2], &A[idx * SNOVA_l2]);
		be_invertible_by_add_aS(&Bm[idx * SNOVA_l2], &B[idx * SNOVA_l2]);
		gen_a_FqS(&Q1m[idx * SNOVA_l2], &q1[idx * SNOVA_l]);
		gen_a_FqS(&Q2m[idx * SNOVA_l2], &q2[idx * SNOVA_l]);
	}
}

/**
 * Use last part of the P matrix to establish AB. Also fix q.
 */
static void gen_q_AB(gf_t *A, gf_t *Am, gf_t *Bm) {
	gf_t *B = A + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q1 = B + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q2 = q1 + SNOVA_o * SNOVA_alpha * SNOVA_l;

	for (size_t idx = 0; idx < SNOVA_o * SNOVA_alpha; idx++) {
		be_invertible_by_add_aS(&Am[idx * SNOVA_l2], &A[idx * SNOVA_l2]);
		be_invertible_by_add_aS(&Bm[idx * SNOVA_l2], &B[idx * SNOVA_l2]);

		if (!q1[idx * SNOVA_l + SNOVA_l - 1]) {
			q1[idx * SNOVA_l + SNOVA_l - 1] = SNOVA_q - (q1[idx * SNOVA_l] + (q1[idx * SNOVA_l] == 0));
		}
		if (!q2[idx * SNOVA_l + SNOVA_l - 1]) {
			q2[idx * SNOVA_l + SNOVA_l - 1] = SNOVA_q - (q2[idx * SNOVA_l] + (q2[idx * SNOVA_l] == 0));
		}
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
	uint32_t P22[SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2] = {0};

	expand_T12(T12, seed + SEED_LENGTH_PUBLIC);

	/**
	 * Gen Public matrix but not ABQ
	 */
	gf_t P_matrix[NUM_GEN_PUB_GF];
	gf_t *P11 = P_matrix;
	gf_t *P12 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_n * SNOVA_l2;

	snova_pk_expander_t instance;
	snova_pk_expander_init(&instance, seed, SEED_LENGTH_PUBLIC);

	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	/**
	 * Calculate F12 matrix, use P11
	 */
	uint16_t F12[SNOVA_o * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};

	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_v; dj++)
			for (int dk = 0; dk < SNOVA_o; dk++)
				for (int idx = 0; idx < SNOVA_v; idx++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								F12[((di * SNOVA_v + dj) * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    P11[((di * SNOVA_v + dj) * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    T12[(idx * SNOVA_o + dk) * SNOVA_l2 + k1 * SNOVA_l + j1];

	// Use P12
	for (int i1 = 0; i1 < SNOVA_o * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		F12[i1] += P12[i1];
	}

	for (int di = 0; di < SNOVA_o; di++)
		for (int idx = 0; idx < SNOVA_v; idx++)
			for (int dk = 0; dk < SNOVA_o; dk++)
				for (int dj = 0; dj < SNOVA_o; dj++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								P22[((di * SNOVA_o + dj) * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    T12[(idx * SNOVA_o + dj) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    F12[((di * SNOVA_v + idx) * SNOVA_o + dk) * SNOVA_l2 + k1 * SNOVA_l + j1];

	/**
	 * Calculate P22. Uses P21
	 */
	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_o; dj++)
			for (int idx = 0; idx < SNOVA_v; idx++)
				for (int dk = 0; dk < SNOVA_o; dk++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								P22[((di * SNOVA_o + dj) * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    P21[((di * SNOVA_o + dj) * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    T12[(idx * SNOVA_o + dk) * SNOVA_l2 + k1 * SNOVA_l + j1];

	// Negate P22
	gf_t P22gf[SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2] = {0};
	for (int i1 = 0; i1 < SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2; i1++) {
		P22gf[i1] = (SNOVA_q - (P22[i1] % SNOVA_q)) % SNOVA_q;
	}

	/**
	 * Output public and secret keys
	 */
	memcpy(pk, seed, SEED_LENGTH_PUBLIC);
	compress_gf(pk + SEED_LENGTH_PUBLIC, P22gf, SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2);
	memcpy(sk, seed, SEED_LENGTH);

	return 0;
}

/**
 * Optimized version of Sign. Deterministic using the salt provided
 */
int SNOVA_NAMESPACE(sign)(uint8_t *sig, const uint8_t *digest, size_t len_digest, const uint8_t *salt, const uint8_t *sk) {
	if (first_time) {
		snova_init();
	}

	const uint8_t *seed = sk;
	gf_t T12gf[SNOVA_o * SNOVA_v * SNOVA_l2];
	expand_T12(T12gf, seed + SEED_LENGTH_PUBLIC);

	uint16_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];
	for (int i1 = 0; i1 < SNOVA_o * SNOVA_v * SNOVA_l2; i1++) {
		T12[i1] = T12gf[i1];
	}

	gf_t P_matrix[NUM_GEN_PUB_GF];
	gf_t *P11 = P_matrix;
	gf_t *P12 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_n * SNOVA_l2;

	snova_pk_expander_t instance;
	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];

	snova_pk_expander_init(&instance, seed, SEED_LENGTH_PUBLIC);
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	/**
	 * Calculate F12, F21
	 */
	uint16_t F12[SNOVA_o * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};
	uint16_t F21[SNOVA_o * SNOVA_o * SNOVA_v * SNOVA_l2] = {0};

	uint16_t F12_16[SNOVA_o * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};
	uint16_t F21_16[SNOVA_o * SNOVA_o * SNOVA_v * SNOVA_l2] = {0};

	// Transpose for more efficient vectorization
	uint16_t T12t[SNOVA_o * SNOVA_v * SNOVA_l2];
	for (int di = 0; di < SNOVA_o; di++)
		for (int dj2 = 0; dj2 < SNOVA_v; dj2++)
			for (int dk = 0; dk < SNOVA_o; dk++)
				for (int j1 = 0; j1 < SNOVA_l; j1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						T12t[(dj2 * SNOVA_o + dk) * SNOVA_l2 + j1 * SNOVA_l + k1] =
						    T12[(dj2 * SNOVA_o + dk) * SNOVA_l2 + k1 * SNOVA_l + j1];

	uint16_t P11t[SNOVA_o * SNOVA_v * SNOVA_v * SNOVA_l2];
	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_v; dj++)
			for (int dj2 = 0; dj2 < SNOVA_v; dj2++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						P11t[((di * SNOVA_v + dj2) * SNOVA_v + dj) * SNOVA_l2 + k1 * SNOVA_l + i1] =
						    P11[((di * SNOVA_v + dj) * SNOVA_v + dj2) * SNOVA_l2 + i1 * SNOVA_l + k1];

	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_v; dj++)
			for (int dj2 = 0; dj2 < SNOVA_v; dj2++)
				for (int dk = 0; dk < SNOVA_o; dk++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								F12_16[((di * SNOVA_o + dk) * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    T12t[(dj2 * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    P11t[((di * SNOVA_v + dj2) * SNOVA_v + dj) * SNOVA_l2 + k1 * SNOVA_l + j1];

	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_v; dj++)
			for (int dk = 0; dk < SNOVA_o; dk++)
				for (int j1 = 0; j1 < SNOVA_l; j1++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						F12[((di * SNOVA_v + dj) * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + j1] =
						    (F12_16[((di * SNOVA_o + dk) * SNOVA_v + dj) * SNOVA_l2 + j1 * SNOVA_l + i1] +
						     P12[((di * SNOVA_v + dj) * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + j1]) %
						    SNOVA_q;

	for (int di = 0; di < SNOVA_o; di++)
		for (int dj = 0; dj < SNOVA_v; dj++)
			for (int dj2 = 0; dj2 < SNOVA_v; dj2++)
				for (int dk = 0; dk < SNOVA_o; dk++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								F21_16[((di * SNOVA_o + dk) * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    T12[(dj2 * SNOVA_o + dk) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    P11[((di * SNOVA_v + dj2) * SNOVA_v + dj) * SNOVA_l2 + k1 * SNOVA_l + j1];

	for (int i1 = 0; i1 < SNOVA_o * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		F21[i1] = (F21_16[i1] + P21[i1]) % SNOVA_q;
	}

	// Generate ABQ
	gf_t Am[4 * SNOVA_o * SNOVA_alpha * SNOVA_l2];
	gf_t *Bm = Am + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *Q1 = Bm + SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *Q2 = Q1 + SNOVA_o * SNOVA_alpha * SNOVA_l2;

	gf_t *aptr = P_matrix + (SNOVA_o * (SNOVA_n * SNOVA_n - SNOVA_o * SNOVA_o)) * SNOVA_l2;
	gf_t *q1 = aptr + 2 * SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q2 = q1 + SNOVA_o * SNOVA_alpha * SNOVA_l;

	gen_ABQ(aptr, Am, Bm, Q1, Q2);

	// Calculate message has of size l^2o
	gf_t hash_in_GF16[GF16_HASH];

	uint8_t sign_hashb[BYTES_HASH];
	hash_combined(sign_hashb, digest, len_digest, sk, salt);
	convert_bytes_to_GF(hash_in_GF16, sign_hashb, GF16_HASH);

	// Find a solution for T.X
	gf_t gauss[SNOVA_o * SNOVA_l2][SNOVA_o * SNOVA_l2 + 1];
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

		/**
		 * Whip vinegar part of signature
		 */
		uint32_t Fvv_in_GF[SNOVA_m * SNOVA_l2] = {0};
		gf_t whipped_sig[SNOVA_l * SNOVA_v * SNOVA_l2] = {0};
		uint16_t whipped_sig16[SNOVA_l * SNOVA_v * SNOVA_l2] = {0};
		uint32_t whipped_hash[SNOVA_m * SNOVA_l2 * SNOVA_l2] = {0};
		uint16_t whipped_hash16[SNOVA_m * SNOVA_l2 * SNOVA_l2] = {0};

		for (int i1 = 0; i1 < SNOVA_v * SNOVA_l2; i1++) {
			whipped_sig16[i1] = signature_in_GF[i1];
		}

		for (int ab = 1; ab < SNOVA_l; ++ab)
			for (int idx = 0; idx < SNOVA_v; ++idx)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							whipped_sig16[(ab * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
							    gf_S[ab * SNOVA_l2 + i1 * SNOVA_l + k1] * signature_in_GF[idx * SNOVA_l2 + k1 * SNOVA_l + j1];

		for (int ab = 0; ab < SNOVA_l; ++ab)
			for (int idx = 0; idx < SNOVA_v; ++idx)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						whipped_sig[(i1 * SNOVA_v + idx) * SNOVA_l2 + ab * SNOVA_l + j1] =
						    whipped_sig16[(ab * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + j1] % SNOVA_q;

		for (int ab = 0; ab < SNOVA_l; ++ab)
			for (int idx = 0; idx < SNOVA_v; ++idx)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						whipped_sig16[(i1 * SNOVA_v + idx) * SNOVA_l2 + ab * SNOVA_l + j1] =
						    whipped_sig[(i1 * SNOVA_v + idx) * SNOVA_l2 + ab * SNOVA_l + j1];

		/**
		 * Evaluate whipped central map
		 */
		for (int mi = 0; mi < SNOVA_o; mi++) {
			uint16_t sum_t0[SNOVA_v * SNOVA_l * SNOVA_l2] = {0};

			for (int ni = 0; ni < SNOVA_v; ++ni)
				for (int nj = 0; nj < SNOVA_v; ++nj)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							for (int b1 = 0; b1 < SNOVA_l; b1++)
								for (int j1 = 0; j1 < SNOVA_l; j1++)
									sum_t0[(ni * SNOVA_l + i1) * SNOVA_l2 + b1 * SNOVA_l + j1] +=
									    P11[((mi * SNOVA_v + ni) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1] *
									    whipped_sig16[(k1 * SNOVA_v + nj) * SNOVA_l2 + b1 * SNOVA_l + j1];

			for (int ni = 0; ni < SNOVA_v; ++ni)
				for (int a1 = 0; a1 < SNOVA_l; a1++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							for (int b1 = 0; b1 < SNOVA_l; b1++)
								for (int j1 = 0; j1 < SNOVA_l; j1++)
									whipped_hash[(mi * SNOVA_l2 + a1 * SNOVA_l + b1) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
									    whipped_sig16[(k1 * SNOVA_v + ni) * SNOVA_l2 + a1 * SNOVA_l + i1] *
									    sum_t0[(ni * SNOVA_l + k1) * SNOVA_l2 + b1 * SNOVA_l + j1];
		}

		for (int i1 = 0; i1 < SNOVA_m * SNOVA_l2 * SNOVA_l2; i1++) {
			whipped_hash16[i1] = whipped_hash[i1] % SNOVA_q;
		}

		/**
		 * Squeeze whipped Fvv
		 */
		for (int mi = 0; mi < SNOVA_o; mi++) {
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
				int mi_prime = i_prime(mi, alpha);
				uint32_t sum_whip[SNOVA_l2] = {0};
				uint32_t sum_t0[SNOVA_l2] = {0};

				for (int a1 = 0; a1 < SNOVA_l; a1++)
					for (int b1 = 0; b1 < SNOVA_l; b1++) {
						uint16_t q12 =
						    q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + a1] * q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];
						for (int i1 = 0; i1 < SNOVA_l2; i1++) {
							sum_whip[i1] += q12 * whipped_hash16[(mi_prime * SNOVA_l2 + a1 * SNOVA_l + b1) * SNOVA_l2 + i1];
						}
					}

				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							sum_t0[i1 * SNOVA_l + j1] +=
							    sum_whip[i1 * SNOVA_l + k1] * Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];

				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							Fvv_in_GF[mi * SNOVA_l2 + i1 * SNOVA_l + j1] +=
							    Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] * sum_t0[k1 * SNOVA_l + j1];
			}
		}

		// Set the last column of gauss matrix
		for (int mi = 0; mi < SNOVA_o; mi++)
			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					Fvv_in_GF[mi * SNOVA_l2 + i1 * SNOVA_l + j1] = Fvv_in_GF[mi * SNOVA_l2 + i1 * SNOVA_l + j1] % SNOVA_q;
				}

		// evaluate the vinegar part of central map
		for (int mi = 0; mi < SNOVA_o; mi++) {
			gf_t Left[SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};
			uint16_t Left32[SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};
			gf_t Right[SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};
			uint16_t Right32[SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};

			uint16_t gf16m_temp1[SNOVA_alpha * SNOVA_v * SNOVA_l2] = {0};

			// Left. Transpose multiply
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha)
				for (int idx = 0; idx < SNOVA_v; ++idx)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int ab = 0; ab < SNOVA_l; ab++)
								gf16m_temp1[(alpha * SNOVA_v + idx) * SNOVA_l2 + j1 * SNOVA_l + i1] +=
								    whipped_sig16[(j1 * SNOVA_v + idx) * SNOVA_l2 + ab * SNOVA_l + i1] *
								    q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + ab];

			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha)
				for (int idx = 0; idx < SNOVA_v; ++idx)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								Left32[(alpha * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    gf16m_temp1[(alpha * SNOVA_v + idx) * SNOVA_l2 + j1 * SNOVA_l + k1];

			// Same for right
			memset(gf16m_temp1, 0, sizeof(gf16m_temp1));
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha)
				for (int idx = 0; idx < SNOVA_v; ++idx)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int ab = 0; ab < SNOVA_l; ab++)
								gf16m_temp1[(alpha * SNOVA_v + idx) * SNOVA_l2 + j1 * SNOVA_l + i1] +=
								    whipped_sig16[(j1 * SNOVA_v + idx) * SNOVA_l2 + ab * SNOVA_l + i1] *
								    q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + ab];

			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha)
				for (int idx = 0; idx < SNOVA_v; ++idx)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								Right32[(alpha * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    gf16m_temp1[(alpha * SNOVA_v + idx) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];

			// Modulus on result
			for (int alpha = 0; alpha < SNOVA_alpha; alpha++)
				for (int dj = 0; dj < SNOVA_v; dj++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							Left[(alpha * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + k1] =
							    Left32[(alpha * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + k1] % SNOVA_q;

			for (int i1 = 0; i1 < SNOVA_alpha * SNOVA_v * SNOVA_l2; i1++) {
				Right[i1] = Right32[i1] % SNOVA_q;
			}

			// compute the coefficients of Xo and put into gauss matrix and compute
			// the coefficients of Xo^t and add into gauss matrix

			uint32_t gauss32l[SNOVA_o * SNOVA_l2 * SNOVA_l2] = {0};
			uint32_t gauss32r[SNOVA_o * SNOVA_l2 * SNOVA_l2] = {0};
			uint32_t Left_X_tmp[SNOVA_o * SNOVA_alpha * SNOVA_l2] = {0};
			uint32_t Right_X_tmp[SNOVA_o * SNOVA_alpha * SNOVA_l2] = {0};

			uint16_t gf16m_temp0[SNOVA_o * SNOVA_alpha * SNOVA_l2] = {0};
			for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
				int mi_prime = i_prime(mi, alpha);

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int dj = 0; dj < SNOVA_v; dj++)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								for (int j1 = 0; j1 < SNOVA_l; j1++)
									gf16m_temp0[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
									    Left[(alpha * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + k1] *
									    F12[((mi_prime * SNOVA_v + dj) * SNOVA_o + idx) * SNOVA_l2 + k1 * SNOVA_l + j1];
			}

			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								Left_X_tmp[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    gf16m_temp0[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];
				}
			}

			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++)
					for (int ti1 = 0; ti1 < SNOVA_l; ti1++)
						for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
							for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
								for (int tj2 = 0; tj2 < SNOVA_l; tj2++)
									gauss32l[(idx * SNOVA_l2 + ti1 * SNOVA_l + ti2) * SNOVA_l2 + tj1 * SNOVA_l + tj2] +=
									    Left_X_tmp[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + ti1 * SNOVA_l + tj1] *
									    Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + tj2 * SNOVA_l + ti2];
			}

			uint16_t gf16m_temp3[SNOVA_o * SNOVA_alpha * SNOVA_l2] = {0};

			for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
				int mi_prime = i_prime(mi, alpha);

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int dj = 0; dj < SNOVA_v; ++dj)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								for (int j1 = 0; j1 < SNOVA_l; j1++)
									gf16m_temp3[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
									    Right[(alpha * SNOVA_v + dj) * SNOVA_l2 + k1 * SNOVA_l + j1] *
									    F21[((mi_prime * SNOVA_o + idx) * SNOVA_v + dj) * SNOVA_l2 + i1 * SNOVA_l + k1];
			}

			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								Right_X_tmp[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
								    Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    gf16m_temp3[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];
				}
			}

			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++)
					for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
						for (int ti1 = 0; ti1 < SNOVA_l; ti1++)
							for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
								for (int tj2 = 0; tj2 < SNOVA_l; tj2++)
									gauss32r[(idx * SNOVA_l2 + tj1 * SNOVA_l + ti2) * SNOVA_l2 + ti1 * SNOVA_l + tj2] +=
									    Right_X_tmp[(idx * SNOVA_alpha + alpha) * SNOVA_l2 + tj1 * SNOVA_l + ti2] *
									    Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + ti1 * SNOVA_l + tj2];
			}

			for (int idx = 0; idx < SNOVA_o; idx++) {
				// Modulus on final
				for (int ti1 = 0; ti1 < SNOVA_l; ti1++)
					for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
						for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
							for (int tj2 = 0; tj2 < SNOVA_l; tj2++) {
								gauss[mi * SNOVA_l2 + ti1 * SNOVA_l + ti2][idx * SNOVA_l2 + tj1 * SNOVA_l + tj2] =
								    (gauss32l[(idx * SNOVA_l2 + ti1 * SNOVA_l + ti2) * SNOVA_l2 + tj1 * SNOVA_l + tj2] +
								     gauss32r[(idx * SNOVA_l2 + tj1 * SNOVA_l + ti2) * SNOVA_l2 + ti1 * SNOVA_l + tj2]) %
								    SNOVA_q;
							}
			}
		}

		// Set the last column of gauss matrix
		for (int mi = 0; mi < SNOVA_o; mi++)
			for (int i1 = 0; i1 < SNOVA_l2; i1++) {
				gauss[mi * SNOVA_l2 + i1][SNOVA_o * SNOVA_l2] =
				    gf_sub(hash_in_GF16[mi * SNOVA_l2 + i1], Fvv_in_GF[mi * SNOVA_l2 + i1] % SNOVA_q);
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
		uint16_t sum = 0;
		for (int k = i + 1; k < SNOVA_m * SNOVA_l2; ++k) {
			sum += gauss[i][k] * solution[k];
		}
		solution[i] = gf_sub(gauss[i][SNOVA_m * SNOVA_l2], sum % SNOVA_q);
	}

	// Establish signature using T12
	for (int idx = 0; idx < SNOVA_v; ++idx) {
		for (int di = 0; di < SNOVA_o; ++di) {
			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					uint32_t sum = 0;
					for (int k1 = 0; k1 < SNOVA_l; k1++) {
						sum += T12[(idx * SNOVA_m + di) * SNOVA_l2 + i1 * SNOVA_l + k1] *
						       solution[di * SNOVA_l2 + k1 * SNOVA_l + j1];
					}
					signature_in_GF[idx * SNOVA_l2 + i1 * SNOVA_l + j1] =
					    (signature_in_GF[idx * SNOVA_l2 + i1 * SNOVA_l + j1] + sum) % SNOVA_q;
				}
		}
	}
	memcpy(signature_in_GF + SNOVA_v * SNOVA_l2, solution, SNOVA_o * SNOVA_l2);

	compress_gf(sig, signature_in_GF, SNOVA_n * SNOVA_l2);
	memcpy(sig + BYTES_SIGNATURE - BYTES_SALT, salt, BYTES_SALT);

	return 0;
}

/**
 * Optimized version of verify.
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
	gf_t *P12 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t *P21 = P_matrix + SNOVA_o * SNOVA_v * SNOVA_n * SNOVA_l2;
	gf_t P22[SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2];

	if (expand_gf(P22, pk + SEED_LENGTH_PUBLIC, SNOVA_o * SNOVA_o * SNOVA_o * SNOVA_l2)) {
		return -1;
	}

	snova_pk_expander_t instance;
	snova_pk_expander_init(&instance, pk, SEED_LENGTH_PUBLIC);

	uint8_t pk_bytes[NUM_GEN_PUB_BYTES];
	snova_pk_expander(pk_bytes, NUM_GEN_PUB_BYTES, &instance);
	convert_bytes_to_GF(P_matrix, (uint8_t *)pk_bytes, NUM_GEN_PUB_GF);

	gf_t P[SNOVA_m * SNOVA_n * SNOVA_n * SNOVA_l2];
	for (int mi = 0; mi < SNOVA_m; ++mi)
		for (int ni = 0; ni < SNOVA_v; ++ni)
			for (int nj = 0; nj < SNOVA_v; ++nj)
				for (int idx = 0; idx < SNOVA_l2; idx++)
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P11[((mi * SNOVA_v + ni) * SNOVA_v + nj) * SNOVA_l2 + idx];

	for (int mi = 0; mi < SNOVA_m; ++mi)
		for (int ni = 0; ni < SNOVA_v; ++ni)
			for (int nj = SNOVA_v; nj < SNOVA_n; ++nj)
				for (int idx = 0; idx < SNOVA_l2; idx++)
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P12[((mi * SNOVA_v + ni) * SNOVA_o + (nj - SNOVA_v)) * SNOVA_l2 + idx];

	for (int mi = 0; mi < SNOVA_m; ++mi)
		for (int ni = SNOVA_v; ni < SNOVA_n; ++ni)
			for (int nj = 0; nj < SNOVA_v; ++nj)
				for (int idx = 0; idx < SNOVA_l2; idx++)
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P21[((mi * SNOVA_o + (ni - SNOVA_v)) * SNOVA_v + nj) * SNOVA_l2 + idx];

	for (int mi = 0; mi < SNOVA_m; ++mi)
		for (int ni = SNOVA_v; ni < SNOVA_n; ++ni)
			for (int nj = SNOVA_v; nj < SNOVA_n; ++nj)
				for (int idx = 0; idx < SNOVA_l2; idx++)
					P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + idx] =
					    P22[((mi * SNOVA_o + (ni - SNOVA_v)) * SNOVA_o + nj - SNOVA_v) * SNOVA_l2 + idx];

	/**
	 * Create ABQ matrices
	 */
	gf_t Am[2 * SNOVA_o * SNOVA_alpha * SNOVA_l2];
	gf_t *Bm = Am + SNOVA_o * SNOVA_alpha * SNOVA_l2;

	gf_t *aptr = P_matrix + (SNOVA_o * (SNOVA_n * SNOVA_n - SNOVA_o * SNOVA_o)) * SNOVA_l2;
	gf_t *q1 = aptr + 2 * SNOVA_o * SNOVA_alpha * SNOVA_l2;
	gf_t *q2 = q1 + SNOVA_o * SNOVA_alpha * SNOVA_l;

	gen_q_AB(aptr, Am, Bm);

	gf_t signature_in_GF[NUMGF_SIGNATURE];
	if (expand_gf(signature_in_GF, sig, NUMGF_SIGNATURE)) {
		return -1;
	}

	/**
	 * Whip signature
	 */

	gf_t hash_in_GF[SNOVA_m * SNOVA_l2] = {0};
	uint16_t whipped_sig[SNOVA_l * SNOVA_n * SNOVA_l2] = {0};
	gf_t whipped_hash[SNOVA_m * SNOVA_l2 * SNOVA_l2] = {0};
	gf_t whipped_sig_2[SNOVA_l * SNOVA_n * SNOVA_l2] = {0};

	for (int ab = 0; ab < SNOVA_l; ++ab)
		for (int idx = 0; idx < SNOVA_n; ++idx)
			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						whipped_sig[(ab * SNOVA_n + idx) * SNOVA_l2 + i1 * SNOVA_l + j1] +=
						    gf_S[ab * SNOVA_l2 + i1 * SNOVA_l + k1] * signature_in_GF[idx * SNOVA_l2 + k1 * SNOVA_l + j1];

	for (int nj = 0; nj < SNOVA_n; ++nj)
		for (int b1 = 0; b1 < SNOVA_l; b1++)
			for (int k1 = 0; k1 < SNOVA_l; k1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++)
					whipped_sig_2[(k1 * SNOVA_n + nj) * SNOVA_l2 + b1 * SNOVA_l + j1] =
					    whipped_sig[(b1 * SNOVA_n + nj) * SNOVA_l2 + k1 * SNOVA_l + j1] % SNOVA_q;

	/**
	 * Evaluate Central map
	 */
	for (int mi = 0; mi < SNOVA_m; ++mi) {
		uint32_t value[SNOVA_l2 * SNOVA_l2] = {0};
		uint32_t sum_t0[SNOVA_l * SNOVA_n * SNOVA_l2] = {0};

		// Right side
		for (int ni = 0; ni < SNOVA_n; ++ni)
			for (int nj = 0; nj < SNOVA_n; ++nj)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						for (int b1 = 0; b1 < SNOVA_l; b1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								sum_t0[(i1 * SNOVA_n + ni) * SNOVA_l2 + b1 * SNOVA_l + j1] +=
								    P[((mi * SNOVA_n + ni) * SNOVA_n + nj) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    whipped_sig_2[(k1 * SNOVA_n + nj) * SNOVA_l2 + b1 * SNOVA_l + j1];

		// Left. Transposed multiply
		for (int a1 = 0; a1 < SNOVA_l; a1++)
			for (int b1 = 0; b1 < SNOVA_l; b1++)
				for (int ni = 0; ni < SNOVA_n; ++ni)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								value[(a1 * SNOVA_l + b1) * SNOVA_l2 + k1 * SNOVA_l + j1] +=
								    sum_t0[(i1 * SNOVA_n + ni) * SNOVA_l2 + b1 * SNOVA_l + j1] *
								    whipped_sig[(a1 * SNOVA_n + ni) * SNOVA_l2 + i1 * SNOVA_l + k1];

		// Modulus on final result
		for (int a1 = 0; a1 < SNOVA_l; a1++)
			for (int b1 = 0; b1 < SNOVA_l; b1++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						whipped_hash[(mi * SNOVA_l2 + a1 * SNOVA_l + b1) * SNOVA_l2 + i1 * SNOVA_l + j1] =
						    value[(a1 * SNOVA_l + b1) * SNOVA_l2 + i1 * SNOVA_l + j1] % SNOVA_q;
	}

	/**
	 * Squeeze whipped signature
	 */
	for (int mi = 0; mi < SNOVA_m; ++mi) {
		uint32_t res_mi[SNOVA_l2] = {0};
		for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
			int mi_prime = i_prime(mi, alpha);
			gf_t sum_whip[SNOVA_l2] = {0};
			uint16_t sum_t0[SNOVA_l2] = {0};
			uint16_t sum_t1[SNOVA_l2] = {0};

			for (int a1 = 0; a1 < SNOVA_l; a1++)
				for (int b1 = 0; b1 < SNOVA_l; b1++) {
					uint16_t q12 =
					    q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + a1] * q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];
					for (int i1 = 0; i1 < SNOVA_l2; i1++) {
						sum_t1[i1] += q12 * whipped_hash[(mi_prime * SNOVA_l2 + a1 * SNOVA_l + b1) * SNOVA_l2 + i1];
					}
				}

			for (int i1 = 0; i1 < SNOVA_l2; i1++) {
				sum_whip[i1] = sum_t1[i1] % SNOVA_q;
			}

			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					for (int k1 = 0; k1 < SNOVA_l; k1++) {
						sum_t0[i1 * SNOVA_l + j1] +=
						    sum_whip[i1 * SNOVA_l + k1] * Bm[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];
					}
				}

			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					for (int k1 = 0; k1 < SNOVA_l; k1++) {
						res_mi[i1 * SNOVA_l + j1] +=
						    Am[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] * sum_t0[k1 * SNOVA_l + j1];
					}
				}
		}
		for (int i1 = 0; i1 < SNOVA_l2; i1++) {
			hash_in_GF[mi * SNOVA_l2 + i1] = res_mi[i1] % SNOVA_q;
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
