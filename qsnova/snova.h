#ifndef SNOVA_H
#define SNOVA_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef SNOVA_q
#include "snova_params.h"
#endif

#if ((SNOVA_v * SNOVA_l) & 1) != 0
// P11 is not byte-aligned if both l and v are odd
#error "Not supported"
#endif

#define PARAM_JOIN_(a, b, c, d, f) snova_##a##_##b##_##c##_##d##_##f
#define PARAM_JOIN(a, b, c, d, f) PARAM_JOIN_(a, b, c, d, f)
#define SNOVA_NAMESPACE(f) PARAM_JOIN(SNOVA_v, SNOVA_o, SNOVA_q, SNOVA_l, f)

#define SEED_LENGTH_PUBLIC 16
#define SEED_LENGTH_PRIVATE 32
#define SEED_LENGTH (SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE)

#define BYTES_SALT 16

// Derived
#define SNOVA_m (SNOVA_o)
#define SNOVA_n (SNOVA_v + SNOVA_o)
#define SNOVA_l2 (SNOVA_l * SNOVA_l)

#define NUMGF_PK (SNOVA_m * SNOVA_o * SNOVA_o * SNOVA_l2)
#define NUMGF_SIGNATURE (SNOVA_n * SNOVA_l2)

#if SNOVA_q == 11
#define BYTES_GF(x) ((7 * (x) + 15) / 16)
#elif SNOVA_q > 16
#define BYTES_GF(x) (x)
#else
#define BYTES_GF(x) ((4 * (x) + 7) / 8)
#endif

#define BYTES_PK (BYTES_GF(NUMGF_PK) + SEED_LENGTH_PUBLIC)
#define BYTES_SIGNATURE (BYTES_GF(NUMGF_SIGNATURE) + BYTES_SALT)

#define GF16_HASH (SNOVA_m * SNOVA_l2)
#if SNOVA_q > 16
#define BYTES_HASH (GF16_HASH)
#else
#define BYTES_HASH ((GF16_HASH + 1) / 2)
#endif

#define SNOVA_alpha (SNOVA_l * SNOVA_l + SNOVA_l)
#define NUM_GEN_PUB_GF                                                                              \
    ((SNOVA_m * (SNOVA_n * SNOVA_n - SNOVA_o * SNOVA_o) + 2 * (SNOVA_o * SNOVA_alpha)) * SNOVA_l2 + \
     2 * SNOVA_o * SNOVA_alpha * SNOVA_l)

#if SNOVA_q > 16
#define NUM_GEN_PUB_BYTES (NUM_GEN_PUB_GF)
#define NUM_GEN_SEC_BYTES (SNOVA_v * SNOVA_l2)
#else
#define NUM_GEN_PUB_BYTES ((NUM_GEN_PUB_GF + 1) / 2)
#define NUM_GEN_SEC_BYTES ((SNOVA_v * SNOVA_l2 + 1) / 2)
#endif

int SNOVA_NAMESPACE(genkeys)(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int SNOVA_NAMESPACE(sign)(uint8_t *sig, const uint8_t *digest, size_t len_digest, const uint8_t *salt, const uint8_t *sk);
int SNOVA_NAMESPACE(verify)(const uint8_t *digest, size_t len_digest, const uint8_t *sig, const uint8_t *pk);

#define i_prime(mi, alpha) ((alpha + mi) % SNOVA_m)

#endif
