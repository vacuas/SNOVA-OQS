// SPDX-License-Identifier: MIT

/**
 * Interface to NIST API.
 *
 * This file is the ony point where randbytes are used by SNOVA.
 * The snova_* implementations are deterministic.
 *
 * SNOVA Team 2025
 */

#include <string.h>

#include "api.h"
#include "rng.h"
#include "symmetric.h"

// Size of the message digest in the hash-and-sign paragdigm.
#define BYTES_DIGEST 64

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
	uint8_t seed[SEED_LENGTH];

	randombytes(seed, SEED_LENGTH);
	return SNOVA_NAMESPACE(genkeys)(pk, sk, seed);
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk) {
	uint8_t digest[BYTES_DIGEST];
	uint8_t salt[BYTES_SALT];

	shake256(digest, BYTES_DIGEST, m, mlen);
	randombytes(salt, BYTES_SALT);

	int res = SNOVA_NAMESPACE(sign)(sm, digest, BYTES_DIGEST, salt, sk);
	if (!res) {
		memcpy(sm + CRYPTO_BYTES, m, mlen);
		*smlen = mlen + CRYPTO_BYTES;
	}

	return res;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk) {
	if (smlen < CRYPTO_BYTES) {
		return -1;
	}

	uint8_t digest[BYTES_DIGEST];
	shake256(digest, BYTES_DIGEST, sm + CRYPTO_BYTES, smlen - CRYPTO_BYTES);

	int res = SNOVA_NAMESPACE(verify)(digest, BYTES_DIGEST, sm, pk);

	if (!res) {
		memcpy(m, sm + CRYPTO_BYTES, smlen - CRYPTO_BYTES);
		*mlen = smlen - CRYPTO_BYTES;
	}

	return res;
}
