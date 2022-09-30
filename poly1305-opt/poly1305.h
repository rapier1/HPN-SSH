#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct poly1305_key {
	unsigned char b[32];
};

#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__) || \
defined(__i386__) || defined(__i386) || defined(i386)

#if !defined(poly1305_auth) && defined(__AVX2__)
void poly1305_auth_avx2(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);
#define poly1305_auth poly1305_auth_avx2
#endif

#if !defined(poly1305_auth) && defined(__AVX__)
void poly1305_auth_avx(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);
#define poly1305_auth poly1305_auth_avx
#endif

#if !defined(poly1305_auth) && defined(__SSE2__)
void poly1305_auth_sse2(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);
#define poly1305_auth poly1305_auth_sse2
#endif

void poly1305_auth_x86(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);

#ifndef poly1305_auth
#define poly1305_auth poly1305_auth_x86
#endif

#endif /* __x86_64__ || __i386__ etc... */

#if __ARM_ARCH >= 6

/* TODO: only implemented for 32-bit? */

#if !defined(poly1305_auth) && __ARM_NEON == 1
void poly1305_auth_neon(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);
#define poly1305_auth poly1305_auth_neon
#endif

void poly1305_auth_armv6(unsigned char *mac, const unsigned char *in,
    size_t inlen, const struct poly1305_key *key);

#ifndef poly1305_auth
#define poly1305_auth poly1305_auth_armv6
#endif

#endif /* __ARM_ARCH >= 6 */

#if defined(__cplusplus)
}
#endif

#endif /* POLY1305_H */
