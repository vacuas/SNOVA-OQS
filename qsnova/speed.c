// SPDX-License-Identifier: MIT

/**
 * Test program to determine scheme cycle counts.
 * Also serves as a test to verify behavior for both legitimate and forged signatures.
 *
 * Copyright (c) 2025 SNOVA TEAM
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "rng.h"

// Test duration in seconds
#ifndef DURATION
#define DURATION 3
#endif

// MAx numver of tests if reached before the test duration
#ifndef MAX_TESTS
#define MAX_TESTS 100000
#endif

#define TEXT_LEN 64

/*
To get additional timing info use

make clean speed P="-DANALYZE_TIMING"

#define ANALYZE_TIMING 0
extern uint64_t cycles0, cycles1, cycles2, cycles3, cycles4, cycles5, cycles6, cycles7;
uint64_t get_cycles(void);


#ifdef ANALYZE_TIMING
    uint64_t start_cycles, end_cycles;
    start_cycles = get_cycles();
#endif


#ifdef ANALYZE_TIMING
    end_cycles = get_cycles();
    cycles0 += end_cycles - start_cycles;
    start_cycles = get_cycles();
#endif
*/

uint64_t cycles0 = 0, cycles1 = 0, cycles2 = 0, cycles3 = 0, cycles4 = 0, cycles5 = 0, cycles6 = 0, cycles7 = 0;

double get_cpu_f(void);

#ifdef __ARM_ARCH
// cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq
// sudo cpufreq-set -d 2.4GHz
#define CYCLES_PER_NS 2.4
#else
// Uncomment for times in ns
// #define CYCLES_PER_NS 1
#endif

#ifdef CYCLES_PER_NS
uint64_t get_cycles(void) {
	struct timespec time;
	timespec_get(&time, TIME_UTC);
	return (int64_t)((time.tv_sec * 1e9 + time.tv_nsec) * CYCLES_PER_NS);
}
#else
uint64_t get_cycles(void) {
	uint32_t lo, hi;
	uint64_t o;
	__asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi) : : "%ecx");
	o = hi;
	o <<= 32;
	return (o | lo);
}
#endif

void print_number(unsigned long n) {
	if (n < 1000) {
		printf("%lu", n);
		return;
	}
	print_number(n / 1000);
	printf(",%03lu", n % 1000);
}

int cmp_uint64(const void *a, const void *b) {
	if (*(uint64_t *)a < * (uint64_t *)b) {
		return -1;
	}
	if (*(uint64_t *)a > *(uint64_t *)b) {
		return 1;
	}
	return 0;
}

uint64_t median(uint64_t *l, size_t len) {
	qsort(l, len, sizeof(uint64_t), cmp_uint64);

	if (len % 2) {
		return l[len / 2];
	} else {
		return (l[len / 2 - 1] + l[len / 2]) / 2;
	}
}

uint64_t summary(uint64_t *t, int test_n) {
	uint64_t td[MAX_TESTS];

	for (int i = 0; i < test_n; ++i) {
		td[i] = t[i * 2 + 1] - t[i * 2];
	}

	uint64_t res = median(td, test_n);

	return res;
}

uint64_t average(uint64_t *t, size_t len) {
	uint64_t acc = 0;
	for (size_t i = 0; i < len; i++) {
		acc += t[i];
	}
	return acc / len;
}

uint64_t avg_summary(uint64_t *t, int test_n) {
	uint64_t td[MAX_TESTS];

	for (int i = 0; i < test_n; ++i) {
		td[i] = t[i * 2 + 1] - t[i * 2];
	}

	uint64_t res = average(td, test_n);

	return res;
}

int main(void) {
	uint8_t seed[48] = {0};

	uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
	uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};

	uint8_t text[TEXT_LEN] = {0};
	uint8_t text1[TEXT_LEN] = {0};
	uint8_t sm[CRYPTO_BYTES + TEXT_LEN] = {0};
	unsigned long long smlen = 0;
	unsigned long long len1 = 0;

	uint64_t t0[MAX_TESTS * 2] = {0};
	uint64_t t1[MAX_TESTS * 2] = {0};
	uint64_t t2[MAX_TESTS * 2] = {0};
	int r = 0;
	int res;
	int fail;

	randombytes_init(seed, NULL, 256);

	struct timespec start_time;
	timespec_get(&start_time, TIME_UTC);
	int i = 0;
	for (; i < MAX_TESTS; i++) {
		t0[i * 2] = get_cycles();
		crypto_sign_keypair(pk, sk);
		t0[i * 2 + 1] = get_cycles();

		t1[i * 2] = get_cycles();
		crypto_sign(sm, &smlen, text, TEXT_LEN, sk);
		t1[i * 2 + 1] = get_cycles();

		t2[i * 2] = get_cycles();
		// Also test failures
		fail = i % 2;
		if (fail) {
			sm[(i / 8) % BYTES_SIGNATURE] ^= 1 << (i % 8);
		}
		res = crypto_sign_open(text1, &len1, sm, smlen, pk);
		r += res + fail;
		t2[i * 2 + 1] = get_cycles();

		struct timespec time;
		timespec_get(&time, TIME_UTC);
		if (((time.tv_sec - start_time.tv_sec) + (time.tv_nsec - start_time.tv_nsec) / 1e9) > DURATION) {
			break;
		}
	}
	int test_n = i;

	if (r == 0) {
		printf("%s & (%d, %lld)", CRYPTO_ALGNAME, CRYPTO_PUBLICKEYBYTES, smlen - TEXT_LEN);
	} else {
		printf("\nFAIL!!\n\n%s & (%d, %lld)", CRYPTO_ALGNAME, CRYPTO_PUBLICKEYBYTES, smlen - TEXT_LEN);
	}

#ifdef AVERAGE
	printf(" & avg. & ");
	print_number(avg_summary(t0, test_n));
	printf(" & ");
	print_number(avg_summary(t1, test_n));
	printf(" & ");
	print_number(avg_summary(t2, test_n));
#else
	printf(" & ");
	print_number(summary(t0, test_n));
	printf(" & ");
	print_number(summary(t1, test_n));
	printf(" & ");
	print_number(summary(t2, test_n));
#endif
	printf(" \\\\");

	if (cycles0) {
		printf("=>    %ld, %ld,    %ld, %ld, %ld,    %ld, %ld, %ld\n", cycles0 / test_n, cycles1 / test_n, cycles2 / test_n,
		       cycles3 / test_n, cycles4 / test_n, cycles5 / test_n, cycles6 / test_n, cycles7 / test_n);
	}

	printf(" \n");

	return 0;
}
