#ifndef CHACHA_POLY_LIBCRYPTO_FORKS_H
#define CHACHA_POLY_LIBCRYPTO_FORKS_H

#include "cipher-chachapoly.h"

#define KEYSTREAMLEN ((((SSH_IOBUFSZ + 128 - 1)/CHACHA_BLOCKLEN) + 1) \
    * CHACHA_BLOCKLEN)
#define AADLEN 4

struct chachapoly_ctx;

struct chachapoly_ctx * chachapolyf_new(struct chachapoly_ctx *oldctx,
    const u_char *key, u_int keylen)
    __attribute__((__bounded__(__buffer__, 2, 3)));
void chachapolyf_free(struct chachapoly_ctx *cpctx);

int chachapolyf_crypt(struct chachapoly_ctx *cpctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt);
int chachapolyf_get_length(struct chachapoly_ctx *cpctx, u_int *plenp,
    u_int seqnr, const u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_LIBCRYPTO_FORKS_H */
