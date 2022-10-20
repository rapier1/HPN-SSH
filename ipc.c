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
	size_t rpos;
	size_t wpos;
};

struct smem_internal {
	u_int path;
	volatile struct smem_layout * m;
};

struct smem *
smem_create()
{
	struct smem * s;
	char pathstr[18];
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
		sprintf(pathstr, "/ssh-ipc-%08x", s->internal->path);
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

	memset(s->internal->m, 0, sizeof(s->internal->m));
	s->internal->m->rpos = 0;
	s->internal->m->wpos = 0;

	s->data = &(s->internal->m->data);
	s->message = &(s->internal->m->message);
	s->signal = &(s->internal->m->signal);

	return s;
}

void
smem_free(struct smem * s)
{
	char pathstr[18];

	if (s == NULL)
		return;
	explicit_bzero(s->internal->m, sizeof(struct smem_layout));
	munmap(s->internal->m, sizeof(struct smem_layout));
	sprintf(pathstr, "/ssh-ipc-%08x", s->internal->path);
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
	char pathstr[18];
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
	sprintf(pathstr, "/ssh-ipc-%08x", s->internal->path);

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
	s->message = &(s->internal->m->message);
	s->signal = &(s->internal->m->signal);

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
smem_nread_msg(struct smem * s, void * buf, size_t n, u_char v)
{
	size_t ringsz, used, p1, p2;

	if ((s == NULL) || (buf == NULL) || (n <= 0))
		return 0;

	smem_spinwait(s, v);

	ringsz = sizeof(s->internal->m->message);
	used = (s->internal->m->wpos + ringsz - s->internal->m->rpos) % ringsz;

	if (n > used)
		return 0;

	if (s->internal->m->rpos + n <= ringsz) {
		memcpy(buf, s->internal->m->message + s->internal->m->rpos, n);
		s->internal->m->rpos += n;
	} else {
		p1 = ringsz - s->internal->m->rpos;
		p2 = n - p1;
		memcpy(buf, s->internal->m->message + s->internal->m->rpos, p1);
		memcpy(buf + p1, s->internal->m->message, p2);
		s->internal->m->rpos = p2;
	}

	return n;
}

size_t
smem_nwrite_msg(struct smem * s, const void * buf, size_t n, u_char v)
{
	size_t ringsz, used, p1, p2;

	if ((s == NULL) || (buf == NULL) || (n <= 0))
		return 0;

	smem_spinwait(s, v);

	ringsz = sizeof(s->internal->m->message);
	used = (s->internal->m->wpos + ringsz - s->internal->m->rpos) % ringsz;

	if (n > (ringsz - 1 - used))
		return 0;
	
	if (s->internal->m->wpos + n <= ringsz) {
		memcpy(s->internal->m->message + s->internal->m->wpos, buf, n);
		s->internal->m->wpos += n;
	} else {
		p1 = ringsz - s->internal->m->wpos;
		p2 = n - p1;
		memcpy(s->internal->m->message + s->internal->m->wpos, buf, p1);
		memcpy(s->internal->m->message, buf + p1, p2);
		s->internal->m->wpos = p2;
	}

	return n;
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
	fprintf(stderr, "    Message RLEN: %ld\n", s->internal->m->rpos);
	fprintf(stderr, "    Message WLEN: %ld\n", s->internal->m->wpos);
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
