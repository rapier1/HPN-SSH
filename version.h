/* $OpenBSD: version.h,v 1.76 2016/02/23 09:14:34 djm Exp $ */

#define SSH_VERSION	"OpenSSH_7.2"

#define SSH_PORTABLE	"p2"
#define SSH_HPN         "-hpn14v11"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

<<<<<<< HEAD
#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.19"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN SSH_AUDITING
#endif /* NERSC_MOD */
=======
>>>>>>> master
