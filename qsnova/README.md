SNOVA
=======
This directory contains an implementation of the SNOVA signature scheme in C language which allows the field order $q$ to be 11, 13, 16, 17 or 31. Building SNOVA requires a C compiler, make and the OpenSSL library. 

There is only a single version of the source code of SNOVA. The SNOVA parameters are set in `snova_params.h`. The SNOVA parameters can also be changed by the command line parameters of the `make` command as in
```
make P="-D SNOVA_l=4 -D SNOVA_q=11 -D SNOVA_o=5 -D SNOVA_v=24" clean all
```

Building for $q=16$ requires a dedicated switch `OPT=OPT_16`, e.g.
```
make OPT=OPT_16 P="-D SNOVA_l=4 -D SNOVA_q=16 -D SNOVA_o=5 -D SNOVA_v=24" clean kat
```
This will recreate the KAT files of the NIST Round 2 submission.

Available optimization options are:
1. Use `make OPT=REF` to build the reference implementation. This works for all supported values of $q$, also $q=16$.
2. Use `make OPT=OPT` (default) for the optimized version for prime values of $q$.
3. Use `make OPT=OPT_16` for an optimized version for $q=16$.
4. Use `make OPT=AVX2_16` to build an optimized version using AVX2 instruction. AVX2 currently only works for $q=16$. 
