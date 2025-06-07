ARCH=native

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -O3 -march=$(ARCH) -mtune=$(ARCH)
# CFLAGS += -g -fstack-usage
EXTRA_CFLAGS = $(P)

# Select appropriate source file
ifeq ($(OPT), REF)
OBJS = ./build/snova_ref.o
else ifeq ($(OPT), OPT)
OBJS = ./build/snova_opt.o
else ifeq ($(OPT), OPT_16)
OBJS = ./build/snova_opt_16.o
else ifeq ($(OPT), AVX2_16)
OBJS = ./build/snova_avx2_16.o
else
# Default to OPT
OBJS = ./build/snova_opt.o
endif

OBJS += ./build/rng.o ./build/symmetric.o ./build/sign.o
HDRS = api.h rng.h symmetric.h snova.h snova_params.h
LIBS = -lcrypto


all: build kat speed

clean:
	rm -rf build *.req *.rsp

build:
	mkdir build

./build/%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

./build/PQCgenKAT_sign: $(OBJS) ./build/PQCgenKAT_sign.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

kat: build ./build/PQCgenKAT_sign
	./build/PQCgenKAT_sign

./build/speed: $(OBJS) ./build/speed.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

speed: build ./build/speed
	@./build/speed
