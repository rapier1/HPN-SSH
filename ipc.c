#include "includes.h"

#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "ipc.h"
#include "misc.h"
#include "sshbuf.h"

struct smem_layout {
	u_char data[(SSH_IOBUFSZ) * 2];
	u_char message[SSH_IOBUFSZ];
	u_char signal;
	u_int  rlen;
	u_int  wlen;
};

struct smem_internal {
	u_int path;
	volatile struct smem_layout * m;
	volatile u_int * rlen;
	volatile u_int * wlen;
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
	s->internal = malloc(sizeof(struct smem_internal));
	if (s->internal == NULL) {
		free(s);
		return NULL;
	}

	do {
		s->internal->path = arc4random();
		sprintf(pathstr, "/%08x", s->internal->path);
		fd = shm_open(pathstr, O_RDWR | O_CREAT | O_EXCL,
		    S_IRUSR | S_IWUSR);
	} while ((fd == -1) && (errno == EEXIST));
	
	if (fd == -1) {
		free(s->internal);
		free(s);
		return NULL;
	}

	if(ftruncate(fd, sizeof(struct smem_layout)) != 0) {
		close(fd);
		shm_unlink(pathstr);
		free(s->internal);
		free(s);
		return NULL;
	}

	s->internal->m = mmap(NULL, sizeof(struct smem_layout),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (s->internal->m == MAP_FAILED) {
		shm_unlink(pathstr);
		free(s->internal);
		free(s);
		return NULL;
	}

	s->data = &(s->internal->m->data);
	s->signal = &(s->internal->m->signal);
	s->internal->rlen = &(s->internal->m->rlen);
	s->internal->wlen = &(s->internal->m->wlen);
	s->message = &(s->internal->m->message);

	memset(s->data, 0, sizeof(s->internal->m->data));
	memset(s->signal, 0, sizeof(s->internal->m->signal));
	*(s->internal->rlen) = 0;
	*(s->internal->wlen) = 0;
	memset(s->message, 0, sizeof(s->internal->m->message));

	return s;
}

void
smem_free(struct smem * s)
{
	char pathstr[10];

	if (s == NULL)
		return;
	explicit_bzero(s->internal->m, sizeof(struct smem_layout));
	munmap(s->internal->m, sizeof(struct smem_layout));
	sprintf(pathstr, "/%08x", s->internal->path);
	shm_unlink(pathstr);
	free(s->internal);
	free(s);
}

u_int
smem_getpath(struct smem * s)
{
	return s->internal->path;
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
	s->internal = malloc(sizeof(struct smem_internal));
	if (s->internal == NULL) {
		free(s);
		return NULL;
	}

	s->internal->path = num;
	sprintf(pathstr, "/%08x", s->internal->path);

	fd = shm_open(pathstr, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		free(s->internal);
		free(s);
		return NULL;
	}

	s->internal->m = mmap(NULL, sizeof(struct smem_layout), PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	close(fd);
	if (s->internal->m == MAP_FAILED) {
		free(s->internal);
		free(s);
		return NULL;
	}

	s->data = &(s->internal->m->data);
	s->signal = &(s->internal->m->signal);
	s->internal->rlen = &(s->internal->m->rlen);
	s->internal->wlen = &(s->internal->m->wlen);
	s->message = &(s->internal->m->message);

	return s;
}

void
smem_leave(struct smem * s)
{
	if (s == NULL)
		return;
	munmap(s->internal->m, sizeof(struct smem_layout));
	free(s->internal);
	free(s);
}

size_t
smem_nread_msg(const struct smem * s, void * buf, const size_t n)
{
	size_t m;
	if ((s == NULL) || (buf == NULL) || (n == 0))
		return 0;
	if (n > (*(s->internal->wlen)) - (*(s->internal->rlen)))
		m = (*(s->internal->wlen)) - (*(s->internal->rlen));
	else
		m = n;
	memcpy(buf, s->message + (*(s->internal->rlen)), m);
	*(s->internal->rlen) += m;
	return m;
}

size_t
smem_nwrite_msg(struct smem * s, const void * buf, const size_t n)
{
	size_t m;
	if ((s == NULL) || (buf == NULL) || (n == 0))
		return 0;
	if (n > (SSH_IOBUFSZ - 8 - (*(s->internal->wlen))))
		m = SSH_IOBUFSZ - 8 - (*(s->internal->wlen));
	else
		m = n;
	memcpy(s->message + (*(s->internal->wlen)), buf, m);
	*(s->internal->wlen) += m;
	return m;
}

void
smem_reset_msg(struct smem * s)
{
	if (s == NULL)
		return;
	*(s->internal->rlen) = 0;
	*(s->internal->wlen) = 0;
}

void
smem_dump(struct smem * s)
{
	if (s == NULL) {
		fprintf(stderr, "Invalid smem, can't dump.\n");
		return;
	}
	fprintf(stderr, "Current status: \n");
	fprintf(stderr, "    Signal: %u\n", *(s->signal));
	fprintf(stderr, "    Message RLEN: %u\n", *(s->internal->rlen));
	fprintf(stderr, "    Message WLEN: %u\n", *(s->internal->wlen));
	fprintf(stderr, "    Message: %02x%02x%02x%02x%02x\n",
	    s->message[8],
	    s->message[9],
	    s->message[10],
	    s->message[11],
	    s->message[12]);
}

void
smem_spinwait(struct smem * s, u_int v)
{
	while (*(s->signal) != v) {
		;
	}
}

long
smem_gspinwait(struct smem * s, u_int v, long g)
{
	struct timespec t;
	long n;

	t.tv_sec = 0;
	t.tv_nsec = g;
	n = 0;

	while (*(s->signal) != v) {
		nanosleep(&t, NULL);
		n = MIN(n + 1, LONG_MAX / g);
	}

	g = g * n / 20 + g * (n - 1) / 20;
	g = MAX(g, 1);
	g = MIN(g, 100000);
	return g;
}

void
smem_signal(struct smem * s, u_int v)
{
	*(s->signal) = v;
}

void
smem_ppidspinwait(struct smem * s, u_int v)
{
	int i = 0;
	while (getppid() != 1) {
		while (*(s->signal) != v && i < 1000) {
			i++;
		}
	}
}
