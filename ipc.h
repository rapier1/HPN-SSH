#ifndef IPC_H
#define IPC_H

#include "includes.h"

#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>

#include "defines.h"
#include "misc.h"
#include "sshbuf.h"

#define SMEM_SIZE          (SSH_IOBUFSZ * 4)

#define DATA_OFFSET        0
#define SIGNAL_OFFSET      (SSH_IOBUFSZ * 2)
#define RLEN_OFFSET        (SSH_IOBUFSZ * 3)
#define WLEN_OFFSET        ((SSH_IOBUFSZ * 3) + 4)
#define MESSAGE_OFFSET     ((SSH_IOBUFSZ * 3) + 8)

/* do {...} while(0) is used to swallow any extra semicolons */
/* https://gcc.gnu.org/onlinedocs/cpp/Swallowing-the-Semicolon.html */

struct smem_internal {
	u_int path;
	volatile char * m;
	volatile u_int * rlen;
	volatile u_int * wlen;
};

struct smem {
	volatile char * signal;
	volatile char * message;
	volatile char * data;
	struct smem_internal internal;
};

struct smem *
smem_create()
{
	struct smem * s;
	char pathstr[10];
	int fd;

	s = malloc(sizeof(struct smem));
	if (s == NULL)
		return NULL;

	do {
		s->internal.path = arc4random();
		sprintf(pathstr, "/%08x", s->internal.path);
		fd = shm_open(pathstr, O_RDWR | O_CREAT | O_EXCL,
		    S_IRUSR | S_IWUSR);
	} while ((fd == -1) && (errno == EEXIST));
	
	if (fd == -1) {
		free(s);
		return NULL;
	}

	if(ftruncate(fd, SMEM_SIZE) != 0) {
		close(fd);
		shm_unlink(pathstr);
		free(s);
		return NULL;
	}

	s->internal.m = mmap(NULL, SMEM_SIZE, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	close(fd);
	if (s->internal.m == MAP_FAILED) {
		shm_unlink(pathstr);
		free(s);
		return NULL;
	}

	s->data = &(s->internal.m[DATA_OFFSET]);
	s->signal = &(s->internal.m[SIGNAL_OFFSET]);
	s->internal.rlen = (u_int *) &(s->internal.m[RLEN_OFFSET]);
	s->internal.wlen = (u_int *) &(s->internal.m[WLEN_OFFSET]);
	s->message = &(s->internal.m[MESSAGE_OFFSET]);

	memset(s->data, 0, 2 * (SSH_IOBUFSZ));
	memset(s->signal, 0, SSH_IOBUFSZ);
	*(s->internal.rlen) = 0;
	*(s->internal.wlen) = 0;
	memset(s->message, 0, SSH_IOBUFSZ - 8);

	return s;
}

void
smem_free(struct smem * s)
{
	char pathstr[10];

	if (s == NULL)
		return;
	explicit_bzero(s->internal.m, SMEM_SIZE);
	munmap(s->internal.m, SMEM_SIZE);
	sprintf(pathstr, "/%08x", s->internal.path);
	shm_unlink(pathstr);
	free(s);
}

u_int
smem_getpath(struct smem * s)
{
	return s->internal.path;
}

struct smem *
smem_join(u_int num)
{
	struct smem * s;
	char pathstr[10];
	int fd;

	s = malloc(sizeof(struct smem));
	if (s == NULL)
		return NULL;

	s->internal.path = num;
	sprintf(pathstr, "/%08x", s->internal.path);

	fd = shm_open(pathstr, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		free(s);
		return NULL;
	}

	s->internal.m = mmap(NULL, SMEM_SIZE, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	close(fd);
	if (s->internal.m == MAP_FAILED) {
		free(s);
		return NULL;
	}

	s->data = &(s->internal.m[DATA_OFFSET]);
	s->signal = &(s->internal.m[SIGNAL_OFFSET]);
	s->internal.rlen = (u_int *) &(s->internal.m[RLEN_OFFSET]);
	s->internal.wlen = (u_int *) &(s->internal.m[WLEN_OFFSET]);
	s->message = &(s->internal.m[MESSAGE_OFFSET]);

	return s;
}

void
smem_leave(struct smem * s)
{
	if (s == NULL)
		return;
	munmap(s->internal.m, SMEM_SIZE);
	free(s);
}

size_t
smem_nread_msg(const struct smem * s, void * buf, const size_t n)
{
	size_t m;
	if ((s == NULL) || (buf == NULL) || (n == 0))
		return 0;
	if (n > (*(s->internal.wlen)) - (*(s->internal.rlen)))
		m = (*(s->internal.wlen)) - (*(s->internal.rlen));
	else
		m = n;
	memcpy(buf, s->message + (*(s->internal.rlen)), m);
	*(s->internal.rlen) += m;
	return m;
}

size_t
smem_nwrite_msg(struct smem * s, const void * buf, const size_t n)
{
	size_t m;
	if ((s == NULL) || (buf == NULL) || (n == 0))
		return 0;
	if (n > (SSH_IOBUFSZ - 8 - (*(s->internal.wlen))))
		m = SSH_IOBUFSZ - 8 - (*(s->internal.wlen));
	else
		m = n;
	memcpy(s->message + (*(s->internal.wlen)), buf, m);
	*(s->internal.wlen) += m;
	return m;
}

void
smem_reset_msg(struct smem * s)
{
	if (s == NULL)
		return;
	*(s->internal.rlen) = 0;
	*(s->internal.wlen) = 0;
}

void
smem_dump(struct smem * s)
{
	if (s == NULL) {
		fprintf(stderr, "Invalid smem, can't dump.\n");
		return;
	}
	fprintf(stderr, "Current status: \n");
	fprintf(stderr, "    Signal: %hhu\n", *(s->signal));
	fprintf(stderr, "    Message &RLEN: %p\n", s->internal.rlen);
	fprintf(stderr, "    Message RLEN: %u\n", *(s->internal.rlen));
	fprintf(stderr, "    Message &WLEN: %p\n", s->internal.wlen);
	fprintf(stderr, "    Message WLEN: %u\n", *(s->internal.wlen));
	fprintf(stderr, "    Message: %02x%02x%02x%02x%02x\n",
	    s->message[8],
	    s->message[9],
	    s->message[10],
	    s->message[11],
	    s->message[12]);
}

#define smem_spinwait(s, v)         \
do {                                \
	while (*(s->signal) != v) { \
		;                   \
	}                           \
} while (0)

#define smem_gspinwait(s, v, g)                 \
do {                                            \
	struct timespec t;                      \
	t.tv_sec = 0;                           \
	t.tv_nsec = g;                          \
	long _n = 0;                            \
	while (*(s->signal) != v) {             \
		nanosleep(&t, NULL);            \
		_n = MIN(_n + 1, LONG_MAX / g); \
	}                                       \
	g = g * _n / 20 + g * (_n - 1) / 20;    \
	g = MAX(g, 1);                          \
	g = MIN(g, 100000);                     \
} while (0)

#define smem_signal(s, v) \
do {                      \
	*(s->signal) = v; \
} while (0)

#define smem_ppidspinwait(s, v)                         \
do {                                                    \
	int i = 0;                                      \
	while (getppid() != 1) {                        \
		while (*(s->signal) != v && i < 1000) { \
			i++;                            \
		}                                       \
	}                                               \
} while (0)

#endif /* IPC_H */
