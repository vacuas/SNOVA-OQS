SNOVA AVX2
=======
This directory contains assembler versions of some recommended SNOVA signature using AVX2 instructions. 
The SNOVA parameters cannot be changed. Use the version in the `oddqsrc` if you want to use other parameters. 

Building
-------

Building SNOVA requires a C compiler, `make` and the OpenSSL library. To test
```
make clean all
```

The assembler `*.s` files were created from the source in the `oddqsrc` directory using gcc version 15.1.1.
