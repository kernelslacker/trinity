/*
 * atm_vcc_churn - AF_ATMPVC ioctl rotation against the surviving ATM
 * device control surface.
 *
 * Linux 7.2 tore out the atmtcp / clip-arp / lec / lane / signalling-
 * daemon control paths and their UAPI headers (linux/atm_tcp.h,
 * linux/atmarp.h, linux/atmlec.h, linux/atmsvc.h are all gone).  The
 * AF_ATMSVC socket family went with the signalling daemon; only
 * AF_ATMPVC and the generic atmif_sioc device ioctls in
 * net/atm/resources.c remain.
 *
 * What this childop still exercises: the vcc_ioctl() dispatcher on an
 * AF_ATMPVC socket, walking the surviving ATM_GET* / ATM_SET* per-itf
 * ioctls under atm_dev_mutex.  The bug families that motivated the
 * original churn (atmtcp_ioctl GPF, lec_atm_close spinlock BUG,
 * lane_ioctl ODEBUG timer re-init) are all gone with the code that
 * hosted them, so this is now plain dispatcher coverage with a tight
 * open / ioctl-batch / close shape.
 *
 * Self-bounding: every iteration owns its own short-lived socket and
 * closes it before returning, so child.c's SIGALRM(1s) safety net
 * always reaches a clean state.  Rates are clamped via
 * BUDGETED(... CHURN_ITERS_BASE) — adapt_budget is free to scale up
 * on productive runs.
 *
 * EAFNOSUPPORT-latch: kernels built without CONFIG_ATM return
 * EAFNOSUPPORT at the very first socket() call.  That answer is fixed
 * for the life of the process, so the first child that observes it
 * latches ns_atm_unsupported and every subsequent invocation bails
 * cheaply at the top.  Same shape as the EPROTONOSUPPORT-latch in
 * mptcp_pm_churn / af_alg_*.
 *
 * DORMANT in dormant_op_disabled[].  Dave smoke-tests before fleet
 * enable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/atm.h>) && __has_include(<linux/atmdev.h>)

#include <linux/atm.h>
#include <linux/atmdev.h>
#include <linux/atmioc.h>

#include "jitter.h"
#include "random.h"

#include "kernel/socket.h"
#ifndef AF_ATMPVC
#define AF_ATMPVC	8
#endif

/* Userspace ATM stacks historically expose ATMPROTO_AAL5 (= 5) as a
 * synonym for ATM_AAL5; <linux/atm.h> only ships the latter.  The
 * kernel atm_create() takes the AAL number directly as the socket
 * protocol arg, so passing ATM_AAL5 is correct either way. */
#ifndef ATMPROTO_AAL5
#define ATMPROTO_AAL5	ATM_AAL5
#endif

/* Latched per-process: socket(AF_ATMPVC, ...) returned EAFNOSUPPORT.
 * CONFIG_ATM is fixed for the life of the binary so further attempts
 * are pure waste — same shape as the mptcp_pm EPROTONOSUPPORT latch. */
static bool ns_atm_unsupported;

#define CHURN_ITERS_BASE	4U

/* Iterate over a small fixed table of every surviving AF_ATMPVC ioctl
 * request code we want to cover.  All current entries are atmif_sioc
 * consumers in net/atm/resources.c — the per-itf walk under
 * atm_dev_mutex. */
struct atm_ioctl_spec {
	unsigned long	req;
	bool		needs_atmif_sioc;
};

static const struct atm_ioctl_spec atm_ioctl_table[] = {
	/* generic ATM_GET* — atmif_sioc consumers, exercise the
	 * per-itf walk under the atm_dev_mutex. */
	{ ATM_GETLINKRATE,	true },
	{ ATM_GETNAMES,		true },	/* atm_iobuf, but same shape */
	{ ATM_GETTYPE,		true },
	{ ATM_GETESI,		true },
	{ ATM_GETCIRANGE,	true },

	/* generic ATM_SET* mutators that survive. */
	{ ATM_SETESI,		true },
	{ ATM_SETESIF,		true },
};

/*
 * Open one AF_ATMPVC socket.  The kernel atm_create() accepts
 * AF_ATMPVC with SOCK_DGRAM and the AAL number as protocol.  Returns
 * -1 on failure; on the first EAFNOSUPPORT we latch
 * ns_atm_unsupported so subsequent calls bail at the top of the
 * outer entry point.
 */
static int atm_open_one(struct childdata *child, int proto)
{
	int fd;

	fd = socket(AF_ATMPVC, SOCK_DGRAM | SOCK_CLOEXEC, proto);
	if (fd < 0) {
		if (errno == EAFNOSUPPORT) {
			ns_atm_unsupported = true;
			__atomic_add_fetch(&shm->stats.atm_vcc_churn_unsupported,
					   1, __ATOMIC_RELAXED);
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats arrays, same pattern
			 * the child.c dispatch loop uses for the unguarded
			 * write that motivated this guard. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}
	return fd;
}

/*
 * Fire one ioctl from the rotation table.  The atmif_sioc-shaped
 * requests want a populated struct (number = itf index, length, ivec
 * out-pointer) — we hand the kernel a small but coherent buffer so
 * the per-itf walk reaches the dispatcher paths instead of bouncing
 * at copy_from_user.
 */
static void atm_fire_one(int fd, const struct atm_ioctl_spec *spec)
{
	struct atmif_sioc sioc;
	unsigned char ivec[64];
	int rawval;

	__atomic_add_fetch(&shm->stats.atm_vcc_churn_ioctls_sent, 1,
			   __ATOMIC_RELAXED);

	if (spec->needs_atmif_sioc) {
		memset(&sioc, 0, sizeof(sioc));
		memset(ivec, 0, sizeof(ivec));
		sioc.number = (int)(rand32() & 0x7);	/* itf 0..7 */
		sioc.length = (int)sizeof(ivec);
		sioc.arg = ivec;
		if (ioctl(fd, spec->req, &sioc) < 0)
			__atomic_add_fetch(&shm->stats.atm_vcc_churn_kernel_rejected,
					   1, __ATOMIC_RELAXED);
		return;
	}

	rawval = (int)(rand32() & 0xff);
	if (ioctl(fd, spec->req, (unsigned long)rawval) < 0)
		__atomic_add_fetch(&shm->stats.atm_vcc_churn_kernel_rejected,
				   1, __ATOMIC_RELAXED);
}

/*
 * One full churn cycle: open an AF_ATMPVC vcc, drive a small batch of
 * rotated ioctls back-to-back, then close.
 */
static void atm_churn_cycle(struct childdata *child)
{
	const struct atm_ioctl_spec *spec;
	unsigned int batch, j;
	int fd;

	fd = atm_open_one(child, ATMPROTO_AAL5);
	if (fd < 0)
		return;
	__atomic_add_fetch(&shm->stats.atm_vcc_churn_socket_ok, 1,
			   __ATOMIC_RELAXED);

	batch = 1U + rnd_modulo_u32(4U);
	for (j = 0; j < batch; j++) {
		spec = &RAND_ARRAY(atm_ioctl_table);
		atm_fire_one(fd, spec);
	}

	close(fd);
}

bool atm_vcc_churn(struct childdata *child)
{
	unsigned int iters, i;

	__atomic_add_fetch(&shm->stats.atm_vcc_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_atm_unsupported)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_ATM_VCC_CHURN, JITTER_RANGE(CHURN_ITERS_BASE));
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < iters; i++) {
		atm_churn_cycle(child);
		if (ns_atm_unsupported)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/atm*>) */

bool atm_vcc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.atm_vcc_churn_runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.atm_vcc_churn_unsupported, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/atm*>) */
