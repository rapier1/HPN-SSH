#ifndef IPC_H
#define IPC_H

#include "defines.h"

struct smem_internal;

struct smem {
	volatile u_char * signal;
	volatile u_char * message;
	volatile u_char * data;
	struct smem_internal * internal;
};

struct smem * smem_create();
void smem_free(struct smem * s);
u_int smem_getpath(struct smem * s);
struct smem * smem_join(u_int num);
void smem_leave(struct smem * s);
size_t smem_nread_msg(const struct smem * s, void * buf, const size_t n);
size_t smem_nwrite_msg(struct smem * s, const void * buf, const size_t n);
void smem_reset_msg(struct smem * s);
void smem_dump(struct smem * s);
void smem_spinwait(struct smem * s, u_int v);
long smem_gspinwait(struct smem * s, u_int v, long g);
void smem_signal(struct smem * s, u_int v);
void smem_ppidspinwait(struct smem * s, u_int v);

#endif /* IPC_H */
