SNOVA
=======
This directory contains a constant-time implementation of the SNOVA signature scheme.
The SNOVA parameters cannot be changed. Use the version in the `src` subdirectory if you want to use other parameters. 

Building
-------
Building SNOVA requires a C compiler, `make` and the OpenSSL library:
```
make clean all
```

Available optimization options are:
2. Use `make OPT=OPT` for the optimized version. This version uses vectorization instructions when available.
3. Use `make OPT=ASM` (default) or `ARCH=skylake make OPT=ASM` for a vectorized version compiled to assembler by gcc 15.1.1. This may yield a better performance. As gcc is not backwards compatible, this option may or may not result in a working binary. Also using OPT may result in a faster version.
