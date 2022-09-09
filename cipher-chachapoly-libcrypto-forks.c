/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly-libcrypto.c,v 1.1 2020/04/03 04:32:21 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <sys/wait.h>

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly-forks.h"

#define READ_END 0
#define WRITE_END 1

#define NUMWORKERS 4

#define WORKERPATH "ssh-worker-chacha20"

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
	struct chachapolyf_ctx * cpf_ctx;
};

struct chachapolyf_ctx {
	int rpipes[NUMWORKERS][2];
	int wpipes[NUMWORKERS][2];
	pid_t pids[NUMWORKERS];
};

struct chachapoly_ctx *
chachapolyf_new(const u_char *key, u_int keylen)
{
	fprintf(stderr,"DEBUGX: %s() START\n",__func__);
	struct chachapoly_ctx *cp_ctx = chachapoly_new(key,keylen);
	if(cp_ctx == NULL)
		return NULL;

	if ((cp_ctx->cpf_ctx = calloc(1, sizeof(*(cp_ctx->cpf_ctx)))) == NULL) {
		chachapoly_free(cp_ctx);
		return NULL;
	}
	struct chachapolyf_ctx *ctx = cp_ctx->cpf_ctx;

	for(int i=0; i<NUMWORKERS; i++) {
		if(pipe(ctx->wpipes[i]) != 0) {
			for(int j=i-1; i>=0; i--) {
				close(ctx->wpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				close(ctx->rpipes[j][WRITE_END]);
			}
			freezero(ctx,sizeof(*ctx));
			return NULL;
		}
		if(pipe(ctx->rpipes[i]) != 0) {
			close(ctx->wpipes[i][READ_END]);
			close(ctx->wpipes[i][WRITE_END]);
			for(int j=i-1; i>=0; i--) {
				close(ctx->wpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				close(ctx->rpipes[j][WRITE_END]);
			}
			freezero(ctx,sizeof(*ctx));
			return NULL;
		}
	}

	u_int streams = NUMWORKERS;

	for(u_int i=0; i<NUMWORKERS; i++) {
		ctx->pids[i] = fork();
		if(ctx->pids[i] == -1) {
			close(ctx->wpipes[i][READ_END]);
			close(ctx->wpipes[i][WRITE_END]);
			close(ctx->rpipes[i][READ_END]);
			close(ctx->rpipes[i][WRITE_END]);
			for(int j=i-1; j>=0; j--) {
				write(ctx->wpipes[j][WRITE_END], "q", 1);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				waitpid(ctx->pids[j], NULL, 0);
			}
			freezero(ctx,sizeof(*ctx));
			return NULL;
		}
		if(ctx->pids[i] != 0) {
			/* parent process */
			/* TODO: what do we do if these fail?! */
			close(ctx->wpipes[i][READ_END]);
			close(ctx->rpipes[i][WRITE_END]);

			if(write(ctx->wpipes[i][WRITE_END], "b", 1) != 1      ||
			   write(ctx->wpipes[i][WRITE_END], &streams, 1) != 1 ||
			   write(ctx->wpipes[i][WRITE_END], &i, 1) != 1       ||
			   write(ctx->wpipes[i][WRITE_END], key, keylen)
			       != keylen                                      ||
			   write(ctx->wpipes[i][WRITE_END], "g", 1) != 1) {
				close(ctx->wpipes[i][WRITE_END]);
				close(ctx->rpipes[i][READ_END]);
				waitpid(ctx->pids[i], NULL, 0);
				for(int j=i-1; j>=0; j--) {
					write(ctx->wpipes[j][WRITE_END], "q",
					    1);
					close(ctx->wpipes[j][WRITE_END]);
					close(ctx->rpipes[j][READ_END]);
					waitpid(ctx->pids[j], NULL, 0);
				}
				freezero(ctx,sizeof(*ctx));
				return NULL;
			}
		} else {
			/* child process */
			if(dup2(ctx->rpipes[i][WRITE_END],STDOUT_FILENO) == -1)
				exit(1);
			if(dup2(ctx->wpipes[i][READ_END],STDIN_FILENO) == -1)
				exit(1);
			if(close(ctx->wpipes[i][READ_END]) == -1)
				exit(1);
			if(close(ctx->wpipes[i][WRITE_END]) == -1)
				exit(1);
			if(close(ctx->rpipes[i][READ_END]) == -1)
				exit(1);
			if(close(ctx->rpipes[i][WRITE_END]) == -1)
				exit(1);
			execlp(WORKERPATH,WORKERPATH,(char *) NULL);
			exit(1);
		}
	}
	return cp_ctx;
}

void
chachapolyf_free(struct chachapoly_ctx *cpctx)
{
	fprintf(stderr,"DEBUGX: %s() START\n",__func__);
	if (cpctx == NULL)
		return;
	struct chachapolyf_ctx * cpfctx = cpctx->cpf_ctx;
	if (cpfctx != NULL) {
		for(int i=0; i<NUMWORKERS; i++) {
			write(cpfctx->wpipes[i][WRITE_END], "q", 1);
			close(cpfctx->wpipes[i][WRITE_END]);
			close(cpfctx->rpipes[i][READ_END]);
			waitpid(cpfctx->pids[i],NULL,0);
		}
		freezero(cpfctx,sizeof(*cpfctx));
	}
	chachapoly_free(cpctx);
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapolyf_crypt(struct chachapoly_ctx *cp_ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	fprintf(stderr,"DEBUGX: %s() START\n",__func__);
	if(cp_ctx->cpf_ctx == NULL) {
		return chachapoly_crypt(cp_ctx, seqnr, dest, src, len, aadlen,
		    authlen, do_encrypt);
	}
	struct chachapolyf_ctx * ctx = cp_ctx->cpf_ctx;

	u_char xorStream[KEYSTREAMLEN + AADLEN];
	u_char expected_tag[POLY1305_TAGLEN];
	u_char poly_key[POLY1305_KEYLEN];
	int r = SSH_ERR_INTERNAL_ERROR;
	if (write(ctx->wpipes[seqnr % NUMWORKERS][WRITE_END], "p", 1) ||
	    write(ctx->wpipes[seqnr % NUMWORKERS][WRITE_END], &len,
	    sizeof(len))                                              ||
	    read(ctx->rpipes[seqnr % NUMWORKERS][READ_END], poly_key,
	    POLY1305_KEYLEN * sizeof(u_char))                         ||
	    read(ctx->rpipes[seqnr % NUMWORKERS][READ_END], xorStream,
	    (KEYSTREAMLEN + AADLEN) * sizeof(u_char))                 ||
	    write(ctx->wpipes[seqnr % NUMWORKERS][WRITE_END], "ng", 2))
		goto out;

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	for (u_int i = 0; i < KEYSTREAMLEN + AADLEN; i++)
		dest[i] = xorStream[i] ^ src[i];

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		     poly_key);
	}
	r = 0;
 out:
	explicit_bzero(xorStream, sizeof(xorStream));
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapolyf_get_length(struct chachapoly_ctx *cp_ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	fprintf(stderr,"DEBUGX: %s() START\n",__func__);
	if(cp_ctx->cpf_ctx == NULL)
		return chachapoly_get_length(cp_ctx, plenp, seqnr, cp, len);
	struct chachapolyf_ctx * ctx = cp_ctx->cpf_ctx;

	u_char buf[4];
	u_char xorStream[4];
	u_int zero = 0;

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	
	if (write(ctx->wpipes[seqnr % NUMWORKERS][WRITE_END], "r", 1) ||
	    write(ctx->wpipes[seqnr % NUMWORKERS][WRITE_END], &zero,
	    sizeof(zero))                                             ||
	    read(ctx->rpipes[seqnr % NUMWORKERS][READ_END], xorStream,
	    len * sizeof(u_char))) {
	    /* TODO: better error message here */
	    return SSH_ERR_LIBCRYPTO_ERROR;
	}
	for (u_int i=0; i < sizeof(buf); i++)
		buf[i] = xorStream[i] ^ cp[i];
	*plenp = PEEK_U32(buf);
	explicit_bzero(buf,sizeof(buf));
	explicit_bzero(xorStream,sizeof(xorStream));
	return 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
