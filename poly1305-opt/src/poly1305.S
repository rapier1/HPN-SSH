#if (defined(__i386__  ) || defined(__x86_64__))
	#include "gcc-x86.inc"
#endif

#if (defined(__arm__  ) || defined(__aarch64__))
	#include "gcc-arm.inc"
#endif


#if (IS_X86_64)

#if defined(HAVE_AVX2)
#include "poly1305_avx2-64.inc"
#endif
#if defined(HAVE_AVX)
#include "poly1305_avx-64.inc"
#endif
#if defined(HAVE_SSE2)
#include "poly1305_sse2-64.inc"
#endif

#include "poly1305_x86-64.inc"

#endif /* IS_X86_64 */


#if (IS_X86_32)

#if defined(HAVE_AVX2)
#include "poly1305_avx2-32.inc"
#endif

#if defined(HAVE_AVX)
#include "poly1305_avx-32.inc"
#endif

#if defined(HAVE_SSE2)
#include "poly1305_sse2-32.inc"
#endif

#include "poly1305_x86-32.inc"

#endif /* IS_X86_32 */


#if defined(HAVE_ARMv6)
#include "poly1305_armv6-32.inc"
#endif

#if (defined(CPU_32BITS) && defined(HAVE_NEON))
#include "poly1305_neon-32.inc"
#endif
