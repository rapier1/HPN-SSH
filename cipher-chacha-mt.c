/*
 * OpenSSH Multi-threaded CHACHA Cipher
 *
 * Multithreaded Chacha20 cipher made by Michael Zhang
 * Based off of code written by Chris Rapier
 */
#include "includes.h"
#include "cipher-chacha-mt.h"
#include "cipher-chachapoly.h"

#if defined(WITH_OPENSSL)
#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>

#include "xmalloc.h"
#include "log.h"
#include <unistd.h>

/* compatibility with old or broken OpenSSL versions */
#include "openbsd-compat/openssl-compat.h"

#ifndef USE_BUILTIN_RIJNDAEL
#include <openssl/aes.h>
#endif

#include <pthread.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

/*-------------------- TUNABLES --------------------*/
/* maximum number of threads and queues */
#define MAX_THREADS      6
#define MAX_NUMKQ        (MAX_THREADS * 4)

// chacha block is 16 32-bit words
#define CHACHA_BLOCKSIZE 16

/* Number of pregen threads to use */
/* this is a default value. The actual number is
 * determined during init as a function of the number
 * of available cores */
int cc20_threads = 2;

/* Number of keystream queues */
/* ideally this should be large enough so that there is
 * always a key queue for a thread to work on
 * so maybe double of the number of threads. Again this
 * is a default and the actual value is determined in init*/
int cc20_numkq = 8;

/* Length of a keystream queue */
/* one queue holds 64KB of key data
 * being that the queues are destroyed after a rekey
 * and at leats one has to be fully filled prior to
 * enciphering data we don't want this to be too large */
#define KQLEN 8192

/* Processor cacheline length */
#define CACHELINE_LEN	64

/* Can the system do unaligned loads natively? */
#if defined(__aarch64__) || \
    defined(__i386__)    || \
    defined(__powerpc__) || \
    defined(__x86_64__)
# define CIPHER_UNALIGNED_OK
#endif
#if defined(__SIZEOF_INT128__)
# define CIPHER_INT128_OK
#endif
/*-------------------- END TUNABLES --------------------*/

#define HAVE_NONE       0
#define HAVE_KEY        1
#define HAVE_IV         2
int cc20_structID = 0;

const EVP_CIPHER *evp_chacha_mt(void);

/* Keystream Queue state */
enum {
	KQINIT,
	KQEMPTY,
	KQFILLING,
	KQFULL,
	KQDRAINING
};

/* Keystream Queue struct */
// commented out padding
struct kq {
	u_char		keys[KQLEN][CHACHA_BLOCKSIZE]; /* 8192 x 16B */
	u_char		ctr[CHACHA_BLOCKSIZE]; /* 16B */
	// u_char          pad0[CACHELINE_LEN];
	pthread_mutex_t	lock;
	pthread_cond_t	cond;
	int             qstate;
	// u_char          pad1[CACHELINE_LEN];
};

/* Context struct */
struct chacha_ctx_mt
{
	int              struct_id;
	int              keylen;
	int		 state;
	int		 qidx;
	int		 ridx;
	int              id[MAX_THREADS]; /* 6 */
	u_int            chacha_key[16];
	const u_char     *orig_key;
/* need to move the counter to seqbuf */
	u_char           chacha_counter[CHACHA_BLOCKSIZE];	// from original chacha struct
	pthread_t	 tid[MAX_THREADS]; /* 6 */
	pthread_rwlock_t tid_lock;
	struct kq	 q[MAX_NUMKQ]; /* 24 */
// #ifdef __APPLE__
// 	pthread_rwlock_t stop_lock;
// 	int		exit_flag;
// #endif /* __APPLE__ */
};

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

/* <friedl>
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
static void
ssh_ctr_inc(u_char *ctr, size_t len)
{
	int i;

	for (i = len - 1; i >= 0; i--)
		if (++ctr[i])	/* continue on overflow */
			return;
}

/*
 * Add num to counter 'ctr'
 */
static void
ssh_ctr_add(u_char *ctr, uint32_t num, u_int len)
{
	int i;
	uint16_t n;

	for (n = 0, i = len - 1; i >= 0 && (num || n); i--) {
		n = ctr[i] + (num & 0xff) + n;
		num >>= 8;
		ctr[i] = n & 0xff;
		n >>= 8;
	}
}

/*
 * Threads may be cancelled in a pthread_cond_wait, we must free the mutex
 */
static void
thread_loop_cleanup(void *x)
{
	pthread_mutex_unlock((pthread_mutex_t *)x);
}
// comment out apple stuff

// #ifdef __APPLE__
// /* Check if we should exit, we are doing both cancel and exit condition
//  * since on OSX threads seem to occasionally fail to notice when they have
//  * been cancelled. We want to have a backup to make sure that we won't hang
//  * when the main process join()-s the cancelled thread.
//  */
// static void
// thread_loop_check_exit(struct chacha_ctx_mt *c)
// {
// 	int exit_flag;

// 	pthread_rwlock_rdlock(&c->stop_lock);
// 	exit_flag = c->exit_flag;
// 	pthread_rwlock_unlock(&c->stop_lock);

// 	if (exit_flag)
// 		pthread_exit(NULL);
// }
// #else
# define thread_loop_check_exit(s)
// #endif /* __APPLE__ */

/*
 * Helper function to terminate the helper threads
 */
static void
stop_and_join_pregen_threads(struct chacha_ctx_mt *c)
{
	int i;

// #ifdef __APPLE__
// 	/* notify threads that they should exit */
// 	pthread_rwlock_wrlock(&c->stop_lock);
// 	c->exit_flag = TRUE;
// 	pthread_rwlock_unlock(&c->stop_lock);
// #endif /* __APPLE__ */

	/* Cancel pregen threads */
	for (i = 0; i < cc20_threads; i++) {
		debug ("Canceled %lu (%d,%d)", c->tid[i], c->struct_id, c->id[i]);
		pthread_cancel(c->tid[i]);
	}
	for (i = 0; i < cc20_threads; i++) {
		if (pthread_kill(c->tid[i], 0) != 0)
			debug3("Chacha20 MT pthread_join failure: Invalid thread id %lu in %s", c->tid[i], __FUNCTION__);
		else {
			debug ("Joining %lu (%d, %d)", c->tid[i], c->struct_id, c->id[i]);
			pthread_join(c->tid[i], NULL);
		}
	}
}

/*
 * The life of a pregen thread:
 *    Find empty keystream queues and fill them using their counter.
 *    When done, update counter for the next fill.
 */
/* previously this used the low level interface which is, sadly,
 * slower than the EVP interface by a long shot. The original ctx (from the
 * body of the code) isn't passed in here but we have the key and the counter
 * which means we should be able to create the exact same ctx and use that to
 * fill the keystream queues. I'm concerned about additional overhead but the
 * additional speed from AESNI should make up for it.  */
/* The above comment was made when I thought I needed to do a new EVP init for
 * each counter increment. Turns out not to be the case -cjr 10/15/21*/

static void *
thread_loop(void *x)
{
	EVP_CIPHER_CTX *chacha_ctx;
	struct chacha_ctx_mt *c = x;
	struct kq *q;
	int i;
	int qidx;
	pthread_t first_tid;
	int outlen;
	//u_char seqbuf[16];
	u_char mynull[CHACHA_BLOCKSIZE];

	memset(&mynull, 0, CHACHA_BLOCKSIZE);
	//memset(&seqbuf, 0, sizeof(seqbuf));

	/* get the thread id to see if this is the first one */
	pthread_rwlock_rdlock(&c->tid_lock);
	first_tid = c->tid[0];
	pthread_rwlock_unlock(&c->tid_lock);

	/* create the context for this thread */
	/* if (!(chacha_ctx = EVP_CIPHER_CTX_new())) { */
	/* 	logit("error with creating chacha context. Exiting"); */
	/* 	exit(1); */
	/* } */

	// initialize cipher ctx with provided key???
	/* if (1 != EVP_CipherInit_ex(chacha_ctx, EVP_chacha20(), NULL, c->orig_key, NULL, 1)) { */
	/* 	logit("error with intializing chacha cipher. Exiting"); */
	/* 	exit(1); */
	/* } */

	/*
	 * Handle the special case of startup, one thread must fill
	 * the first KQ then mark it as draining. Lock held throughout.
	 */

	if (pthread_equal(pthread_self(), first_tid)) {
		/* get the first element of the keyque struct */
		q = &c->q[0];
		/* not convinced using c->ctr is correct. Need to verify against
		 * seqnr in cipher.c */
		//POKE_U64(seqbuf + 8, q->ctr);
		/* need to set the block counter as well
		 * do we need to track the block counter in addition to the seqnr? */
		//seqbuf[0] = 1;

		pthread_mutex_lock(&q->lock);
		/* if we are in the INIT state then fill the queue */
		if (q->qstate == KQINIT) {
			/* set the initial counter */
			EVP_CipherInit(chacha_ctx, NULL, NULL, q->ctr, 1);
			for (i = 0; i < KQLEN; i++) {
				/* encypher a block sized null string (mynull) with the key. This
				 * returns the keystream because xoring the keystream
				 * against null returns the keystream. Store that in the appropriate queue */
				EVP_CipherUpdate(chacha_ctx, q->keys[i], &outlen, mynull, CHACHA_BLOCKSIZE);
				/* increment the counter */
				ssh_ctr_inc(q->ctr, CHACHA_BLOCKSIZE);
			}
			ssh_ctr_add(q->ctr, KQLEN * (cc20_numkq - 1), CHACHA_BLOCKSIZE);
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
		}
		pthread_mutex_unlock(&q->lock);
	}

	/*
	 * Normal case is to find empty queues and fill them, skipping over
	 * queues already filled by other threads and stopping to wait for
	 * a draining queue to become empty.
	 *
	 * Multiple threads may be waiting on a draining queue and awoken
	 * when empty.  The first thread to wake will mark it as filling,
	 * others will move on to fill, skip, or wait on the next queue.
	 */
	for (qidx = 1;; qidx = (qidx + 1) % cc20_numkq) {
		/* Check if I was cancelled, also checked in cond_wait */
		pthread_testcancel();

		/* Check if we should exit as well */
		thread_loop_check_exit(c);

		/* Lock queue and block if its draining */
		q = &c->q[qidx];
		/* not convinced using q->ctr is correct. Need to verify against
		 * seqnr in cipher.c */
		/* q->ctr is already in LSB so that should be fine */
		//POKE_U64(seqbuf + 8, q->ctr);

		pthread_mutex_lock(&q->lock);
		pthread_cleanup_push(thread_loop_cleanup, &q->lock);
		while (q->qstate == KQDRAINING || q->qstate == KQINIT) {
			thread_loop_check_exit(c);
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_cleanup_pop(0);

		/* If filling or full, somebody else got it, skip */
		if (q->qstate != KQEMPTY) {
			pthread_mutex_unlock(&q->lock);
			continue;
		}

		/*
		 * Empty, let's fill it.
		 * Queue lock is relinquished while we do this so others
		 * can see that it's being filled.
		 */
		q->qstate = KQFILLING;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);

		/* set the initial counter */
		EVP_CipherInit(chacha_ctx, NULL, NULL, q->ctr, 1);

		/* see coresponding block above for useful comments */
		for (i = 0; i < KQLEN; i++) {
			EVP_CipherUpdate(chacha_ctx, q->keys[i], &outlen, mynull, CHACHA_BLOCKSIZE);
			ssh_ctr_inc(q->ctr, CHACHA_BLOCKSIZE);
		}

		/* Re-lock, mark full and signal consumer */
		pthread_mutex_lock(&q->lock);
		ssh_ctr_add(q->ctr, KQLEN * (cc20_numkq - 1), CHACHA_BLOCKSIZE);
		q->qstate = KQFULL;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
	}

	return NULL;
}

/* this is where the data is actually enciphered and deciphered */
/* this may also benefit from upgrading to the EVP API */
int
ccmt_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest, const u_char *src,
	   u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	typedef union {
#ifdef CIPHER_INT128_OK
		__uint128_t *u128;
#endif
		uint64_t *u64;
		uint32_t *u32;
		uint8_t *u8;
		const uint8_t *cu8;
		uintptr_t u;
	} ptrs_t;
	ptrs_t destp, srcp, bufp;
	uintptr_t align;
	struct chacha_ctx_mt *c;
	struct kq *q, *oldq;
	int ridx;
	u_char *buf;
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	int r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];

	if (len == 0)
		return 1;
	if ((c = EVP_CIPHER_CTX_get_app_data(ctx->main_evp)) == NULL)
		return 0;

	q = &c->q[c->qidx];
	ridx = c->ridx;

	debug("CRYPT!!!");
	
	/* generate poly key */
	memset(seqbuf, 0, sizeof(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, sizeof(poly_key));
	if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_key,
	    poly_key, sizeof(poly_key)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* check tag if decrypting */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;
		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* crypt additional authentciation data */
	if (aadlen) {
		if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

        /* src already padded to block multiple */
	srcp.cu8 = src+aadlen;
	destp.u8 = dest+aadlen;
	do { /* do until len is 0 */
		buf = q->keys[ridx];
		bufp.u8 = buf;

		/* figure out the alignment on the fly */
#ifdef CIPHER_UNALIGNED_OK
		align = 0;
#else
		align = destp.u | srcp.u | bufp.u;
#endif

		/* xor the src against the key (buf)
		 * different systems can do all 16 bytes at once or
		 * may need to do it in 8 or 4 bytes chunks
		 * worst case is doing it as a loop */
#ifdef CIPHER_INT128_OK
		if ((align & 0xf) == 0) {
			destp.u128[0] = srcp.u128[0] ^ bufp.u128[0];
		} else
#endif
		/* 64 bits */
		if ((align & 0x7) == 0) {
			destp.u64[0] = srcp.u64[0] ^ bufp.u64[0];
			destp.u64[1] = srcp.u64[1] ^ bufp.u64[1];
		/* 32 bits */
		} else if ((align & 0x3) == 0) {
			destp.u32[0] = srcp.u32[0] ^ bufp.u32[0];
			destp.u32[1] = srcp.u32[1] ^ bufp.u32[1];
			destp.u32[2] = srcp.u32[2] ^ bufp.u32[2];
			destp.u32[3] = srcp.u32[3] ^ bufp.u32[3];
		} else {
			/*1 byte at a time*/
			size_t i;
			for (i = 0; i < CHACHA_BLOCKSIZE; ++i)
				dest[i] = src[i] ^ buf[i];
		}

		/* inc/decrement the pointers by the block size (16)*/
		destp.u += CHACHA_BLOCKSIZE;
		srcp.u += CHACHA_BLOCKSIZE;

		/* Increment read index, switch queues on rollover */
		if ((ridx = (ridx + 1) % KQLEN) == 0) {
			oldq = q;

			/* Mark next queue draining, may need to wait */
			c->qidx = (c->qidx + 1) % cc20_numkq;
			q = &c->q[c->qidx];
			pthread_mutex_lock(&q->lock);
			while (q->qstate != KQFULL) {
				pthread_cond_wait(&q->cond, &q->lock);
			}
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
			pthread_mutex_unlock(&q->lock);

			/* Mark consumed queue empty and signal producers */
			pthread_mutex_lock(&oldq->lock);
			oldq->qstate = KQEMPTY;
			pthread_cond_broadcast(&oldq->cond);
			pthread_mutex_unlock(&oldq->lock);
		}
	} while (len -= CHACHA_BLOCKSIZE);
	c->ridx = ridx;

	/* if encyrpting append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	/* return errors. 0 for no error*/
	r = 0;
out:
	/* zero out tags */
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

struct chachapoly_ctx *
ccmt_init(const u_char *key, int keylen)
{
	struct chachapoly_ctx *ctx;
	struct chacha_ctx_mt *c;
	int i;

	debug ("INIT!!!");
 	/* get the number of cores in the system
	 * peak performance seems to come with assigning half the number of
	 * physical cores in the system. This was determined by interating
	 * over the variables */
	/* tests on a 32 physical core system indicates that more than 6 cores
	 * is either a waste or hurts performance -cjr 10/14/21 */
#ifdef __linux__
	int divisor; /* Wouldn't it be nice if linux had sysctlbyname? Yes. */
	FILE *fp;
	int status = 0;
	/* determine is hyperthreading is enabled */
	fp = fopen("/sys/devices/system/cpu/smt/active", "r");
	/* can't find the file so assume that it does not exist */
	if (fp != NULL) {
		fscanf(fp, "%d", &status);
		fclose(fp);
	}
	/* 1 for HT on 0 for HT off */
	if (status == 1)
		divisor = 4;
	else
		divisor = 2;
	cc20_threads = sysconf(_SC_NPROCESSORS_ONLN) / divisor;
#endif  /*__linux__*/
#ifdef  __APPLE__
	int count;
	size_t count_len = sizeof(count);
	sysctlbyname("hw.physicalcpu", &count, &count_len, NULL, 0);
	cc20_threads = count / 2;
#endif  /*__APPLE__*/
#ifdef  __FREEBSD__
	int threads_per_core;
	int cores;
	size_t cores_len = sizeof(cores);
	size_t tpc_len = sizeof(threads_per_core);
	sysctlbyname("kern.smp.threads_per_core", &threads_per_core, &tpc_len, NULL, 0);
	sysctlbyname("kern.smp.cores", &cores, &cores_len, NULL, 0);
	cc20_threads = cores / threads_per_core;
#endif  /*__FREEBSD__*/

 	/* if they have less than 4 cores spin up 2 threads anyway */
	if (cc20_threads < 2)
		cc20_threads = 2;

	if (cc20_threads > MAX_THREADS)
		cc20_threads = MAX_THREADS;

	/* set the number of keystream queues. 4 for each thread
	 * this seems to reduce waiting in the cipher process for queues
	 * to fill up */
	cc20_numkq = cc20_threads * 4;

	if (cc20_numkq > MAX_NUMKQ)
		cc20_numkq = MAX_NUMKQ;

	debug("Starting %d threads and %d queues\n", cc20_threads, cc20_numkq);

	/* set up the chacha ctx */
	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		goto out;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		goto out;
	if ((ctx->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == NULL) {
		chachapoly_free(ctx);
		goto out;
	}
	if (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, NULL, 1)) {
		chachapoly_free(ctx);
		goto out;
	}
	if (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, NULL, 1)) {
		chachapoly_free(ctx);
		goto out;
	}
	if (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16) {
		chachapoly_free(ctx);
		goto out;
	}

	/* set up the initial state of c (our cipher stream struct) */
 	if ((c = EVP_CIPHER_CTX_get_app_data(ctx->main_evp)) == NULL) {
		c = xmalloc(sizeof(*c));
		pthread_rwlock_init(&c->tid_lock, NULL);
#ifdef __APPLE__
		pthread_rwlock_init(&c->stop_lock, NULL);
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		c->state = HAVE_NONE;

		/* initialize the mutexs and conditions for each lock in our struct */
		for (i = 0; i < cc20_numkq; i++) {
			pthread_mutex_init(&c->q[i].lock, NULL);
			pthread_cond_init(&c->q[i].cond, NULL);
		}

		/* attach our struct to the context */
		EVP_CIPHER_CTX_set_app_data(ctx->main_evp, c);
	}

	/* we are initializing but the current structure already
	 *  has a key so we want to kill the existing key data
	 *  and start over.
	 *  This is important when we need to rekey the data stream
	 */
	if (c->state == HAVE_KEY) {
		/* tell the pregen threads to exit */
		stop_and_join_pregen_threads(c);

#ifdef __APPLE__
		/* reset the exit flag */
		c->exit_flag = FALSE;
#endif /* __APPLE__ */

		/* Start over getting key */
		c->state = HAVE_NONE;
	}

	/* set the initial key for this key stream queue */
	if (key != NULL) {
		debug("INIT!");
		//EVP_CipherInit(key, NULL, NULL, iv, 1); /* set base of ctx */
		//chacha_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
		//   &c->chacha_key);
		c->orig_key = key;
		c->keylen = EVP_CIPHER_CTX_key_length(ctx->main_evp) * 8;
		c->state = HAVE_KEY;
	}

	/* set up the initial sequence buffer */
	memset(c->chacha_counter, 0, CHACHA_BLOCKSIZE);
	/* this is normally the sequence number but we can't get it
	 * at this point. So it may be necessary to move the following
	 * initialization block to the crypt function. That's not a huge deal
	 * but something to keep in mind
	 */
	POKE_U64(c->chacha_counter + 8, 0);
	c->chacha_counter[0] = 1;

	debug ("POINT 1");
	
	if (c->state == HAVE_KEY) {
		/* Clear queues */
		/* set the first key in the key queue to the current counter */
		memcpy(c->q[0].ctr, c->chacha_counter, CHACHA_BLOCKSIZE);
		/* indicate that it needs to be initialized */
		c->q[0].qstate = KQINIT;
		/* for each of the remaining queues set the first counter to the
		 * counter and then add the size of the queue to the counter */
		for (i = 1; i < cc20_numkq; i++) {
			memcpy(c->q[i].ctr, c->chacha_counter, CHACHA_BLOCKSIZE);
			ssh_ctr_add(c->q[i].ctr, i * KQLEN, CHACHA_BLOCKSIZE);
			c->q[i].qstate = KQEMPTY;
		}
		c->qidx = 0;
		c->ridx = 0;

		debug ("STARTING THREADS!");
		/* Start threads */
		for (i = 0; i < cc20_threads; i++) {
			pthread_rwlock_wrlock(&c->tid_lock);
			if (pthread_create(&c->tid[i], NULL, thread_loop, c) != 0)
				debug ("CHACHA MT Could not create thread in %s", __FUNCTION__); /*should die here */
			else {
				if (!c->struct_id)
					c->struct_id = cc20_structID++;
				c->id[i] = i;
				debug ("CHACHA MT spawned a thread with id %lu in %s (%d, %d)", c->tid[i], __FUNCTION__, c->struct_id, c->id[i]);
			}
			pthread_rwlock_unlock(&c->tid_lock);
			debug("point 2");
		}
		pthread_mutex_lock(&c->q[0].lock);
		debug ("point 3");
		// wait for all of the threads to be initialized
		while (c->q[0].qstate == KQINIT)
			pthread_cond_wait(&c->q[0].cond, &c->q[0].lock);
		pthread_mutex_unlock(&c->q[0].lock);
	}
	debug ("!!! INIT COMPLETE !!!");
	
	return ctx;
out:
	return NULL;
}

void
ccmt_cleanup(struct chachapoly_ctx *ctx)
{
	struct chacha_ctx_mt *c;

	if (ctx == NULL)
		return;

	if ((c = EVP_CIPHER_CTX_get_app_data(ctx->main_evp)) != NULL) {
		stop_and_join_pregen_threads(c);

		memset(c, 0, sizeof(*c));
		free(c);
		EVP_CIPHER_CTX_set_app_data(ctx->main_evp, NULL);
	}
	EVP_CIPHER_CTX_free(ctx->main_evp);
	EVP_CIPHER_CTX_free(ctx->header_evp);
	freezero(ctx, sizeof(*ctx));
}

#endif /* defined(WITH_OPENSSL) */
