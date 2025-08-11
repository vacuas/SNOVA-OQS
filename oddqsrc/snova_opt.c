#include "snova.h"

#if SNOVA_q == 16
#if (__AVX2__ || __ARM_NEON) && !defined(NOVECTOR)
#include "snova_vector_16.c"
#else
#include "snova_opt_16.c"
#endif

#else
#include "snova_opt_q.c"
#endif
