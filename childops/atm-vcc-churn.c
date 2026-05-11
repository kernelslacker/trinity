/*
 * atm_vcc_churn - AF_ATMPVC / AF_ATMSVC ioctl rotation against the
 * atmtcp / lec / lane / clip control surfaces.
 *
 * Three independent recently-disclosed crash families converge on the
 * same surface: the AF_ATM ioctl multiplexer dispatched off
 * vcc_ioctl() / svc_ioctl() in net/atm/.  All three are reachable from
 * unprivileged userspace given the AF_ATM socket family is built in;
 * none of them requires real ATM hardware.
 *
 *   1. atmtcp_ioctl GPF.  ATMTCP_CREATE / ATMTCP_REMOVE on a vcc whose
 *      atm_dev backend hasn't been bound (or has been torn down out
 *      from under the persistent atmtcp interface) dereferences a NULL
 *      / freed dev->dev_data inside the atmtcp control path.  The
 *      window opens by issuing CREATE, then immediately REMOVE on the
 *      same itf without an intervening dev_register completion.
 *
 *   2. lec_atm_close spinlock-already-unlocked BUG.  An LECD_ATTACH-
 *      shaped op that races a peer close on the LEC control vcc walks
 *      lec_arp_destroy / lec_arp_start with the per-lec ->lock state
 *      machine half-torn-down.  Trinity reaches the entry by sending
 *      the lec attach control op (ATMLEC_CTRL on a fresh vcc) and
 *      then closing both the control fd and the underlying atmsvc fd
 *      back-to-back.
 *
 *   3. lane_ioctl ODEBUG / timer re-init.  Repeated LECD_ATTACH-equiv
 *      attaches against the same itf re-init a per-lec arp_timer
 *      already armed by the previous attach.  ODEBUG flags the second
 *      timer_setup as a re-init of an active object.  Reaching the
 *      bug needs a tight back-to-back attach pair on the same itf
 *      with no intervening detach.
 *
 * The shared shape is "open AF_ATM[PVC|SVC] socket, fire one of the
 * AF_ATM ioctl ranges (atmtcp / lec / lane / clip / generic ATM_GET*),
 * close, repeat."  Every individual ioctl is a single syscall; the
 * race shapes come from the bulk + back-to-back close pattern, not
 * from any one ioctl being structurally invalid.
 *
 * Self-bounding: every iteration owns its own short-lived sockets and
 * closes them before returning, so child.c's SIGALRM(1s) safety net
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
 * enable.  The childop is wired up so when CONFIG_ATM is added to the
 * fuzz config (or the binary is run on a kernel that has it), the
 * coverage is already there to flip on.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/atm.h>) && __has_include(<linux/atmdev.h>) && \
    __has_include(<linux/atmarp.h>) && __has_include(<linux/atmlec.h>) && \
    __has_include(<linux/atmsvc.h>) && __has_include(<linux/atm_tcp.h>)

#include <linux/atm.h>
#include <linux/atmarp.h>
#include <linux/atmdev.h>
#include <linux/atmioc.h>
#include <linux/atmlec.h>
#include <linux/atmsvc.h>
#include <linux/atm_tcp.h>

#include "jitter.h"
#include "random.h"

#ifndef AF_ATMPVC
#define AF_ATMPVC	8
#endif
#ifndef AF_ATMSVC
#define AF_ATMSVC	20
#endif

/* Userspace ATM stacks historically expose ATMPROTO_AAL5 (= 5) as a
 * synonym for ATM_AAL5; <linux/atm.h> only ships the latter.  The
 * kernel atm_create() takes the AAL number directly as the socket
 * protocol arg, so passing ATM_AAL5 is correct either way. */
#ifndef ATMPROTO_AAL5
#define ATMPROTO_AAL5	ATM_AAL5
#endif

/* LECD_ATTACH is internal to net/atm/lec.c and not exported in the
 * UAPI; the lec daemon control vcc is reached via ATMLEC_CTRL on a
 * fresh AF_ATMSVC socket, which is the public entry point that lands
 * in lec_mcast_attach() / lec_arp_init() — exactly the path that
 * surfaces both the lec_atm_close BUG and the lane_ioctl ODEBUG
 * timer re-init in back-to-back attaches. */

/* Latched per-process: socket(AF_ATM*, ...) returned EAFNOSUPPORT.
 * CONFIG_ATM is fixed for the life of the binary so further attempts
 * are pure waste — same shape as the mptcp_pm EPROTONOSUPPORT latch. */
static bool ns_atm_unsupported;

#define CHURN_ITERS_BASE	4U

/* Iterate over a small fixed table of every AF_ATM ioctl request
 * code we want to cover.  Each entry knows whether the kernel will
 * try to copy out a struct (atmif_sioc / atm_iobuf) or treats the
 * arg as a pure int / handle.  Most members of the kernel-side
 * dispatch are reachable via vcc_ioctl(), with svc_ioctl() forwarding
 * the same set on the AF_ATMSVC variant. */
struct atm_ioctl_spec {
	unsigned long	req;
	bool		needs_atmif_sioc;
};

static const struct atm_ioctl_spec atm_ioctl_table[] = {
	/* atmtcp control range — the GPF target.  The kernel rejects
	 * these on a vcc whose backend isn't atmtcp without touching
	 * dev_data; the bug shape opens when the same itf number is
	 * cycled CREATE/REMOVE faster than dev_register completes. */
	{ ATMTCP_CREATE,	false },
	{ ATMTCP_REMOVE,	false },

	/* clip / arp control range. */
	{ ATMARP_MKIP,		false },
	{ ATMARP_SETENTRY,	false },
	{ ATMARP_ENCAP,		false },

	/* lec / lane control range — surfaces both the lec_atm_close
	 * spinlock BUG and the lane_ioctl ODEBUG timer re-init when
	 * issued back-to-back on the same vcc without a teardown. */
	{ ATMLEC_CTRL,		false },
	{ ATMLEC_DATA,		false },
	{ ATMLEC_MCAST,		false },

	/* signalling daemon control vcc. */
	{ ATMSIGD_CTRL,		false },

	/* generic ATM_GET* — atmif_sioc consumers, exercise the
	 * per-itf walk under the atm_dev_mutex. */
	{ ATM_GETLINKRATE,	true },
	{ ATM_GETNAMES,		true },	/* atm_iobuf, but same shape */
	{ ATM_GETTYPE,		true },
	{ ATM_GETESI,		true },
	{ ATM_GETADDR,		true },
	{ ATM_GETCIRANGE,	true },

	/* generic ATM_*ADDR mutators. */
	{ ATM_RSTADDR,		true },
	{ ATM_ADDADDR,		true },
	{ ATM_DELADDR,		true },
	{ ATM_SETESI,		true },
	{ ATM_SETESIF,		true },

	/* lecs address table — also atmif_sioc shaped. */
	{ ATM_ADDLECSADDR,	true },
	{ ATM_DELLECSADDR,	true },
	{ ATM_GETLECSADDR,	true },
};

#define NR_ATM_IOCTLS	ARRAY_SIZE(atm_ioctl_table)

/*
 * Open one AF_ATM* socket.  The kernel atm_create() accepts AF_ATMPVC
 * and AF_ATMSVC, both with SOCK_DGRAM and the AAL number as protocol.
 * Returns -1 on failure; on the first EAFNOSUPPORT we latch
 * ns_atm_unsupported so subsequent calls bail at the top of the
 * outer entry point.
 */
static int atm_open_one(int family, int proto)
{
	int fd;

	fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, proto);
	if (fd < 0) {
		if (errno == EAFNOSUPPORT) {
			ns_atm_unsupported = true;
			__atomic_add_fetch(&shm->stats.atm_vcc_churn_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return -1;
	}
	return fd;
}

/*
 * Fire one ioctl from the rotation table.  The atmif_sioc-shaped
 * requests want a populated struct (number = itf index, length, ivec
 * out-pointer) — we hand the kernel a small but coherent buffer so
 * the per-itf walk reaches the bug-shape paths instead of bouncing
 * at copy_from_user.  Pure-int requests (atmtcp / lec / arp / sigd)
 * take whatever int we hand them; the kernel rejects most for lack
 * of an attached backend, but the rejection itself runs the
 * dispatch-table walk and that's the path we're after.
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
 * One full churn cycle: open a vcc on a randomly-picked AF_ATM*
 * variant, drive a small batch of rotated ioctls back-to-back, then
 * close.  The back-to-back close is intentional — bug class #2
 * (lec_atm_close BUG) and the atmtcp GPF both want a close arriving
 * while the kernel is still walking the dispatch state from the
 * preceding ioctl.
 */
static void atm_churn_cycle(void)
{
	const struct atm_ioctl_spec *spec;
	unsigned int batch, j;
	int family;
	int fd;

	family = RAND_BOOL() ? AF_ATMPVC : AF_ATMSVC;

	fd = atm_open_one(family, ATMPROTO_AAL5);
	if (fd < 0)
		return;
	__atomic_add_fetch(&shm->stats.atm_vcc_churn_socket_ok, 1,
			   __ATOMIC_RELAXED);

	/* Tight batch — same fd sees several ioctls before close, so
	 * the lane re-init / lec_atm_close races have a non-trivial
	 * chance of overlapping a sibling child's parallel cycle on
	 * the same itf number. */
	batch = 1U + (rand32() % 4U);
	for (j = 0; j < batch; j++) {
		spec = &atm_ioctl_table[rand32() % NR_ATM_IOCTLS];
		atm_fire_one(fd, spec);
	}

	close(fd);
}

bool atm_vcc_churn(struct childdata *child)
{
	unsigned int iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.atm_vcc_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_atm_unsupported)
		return true;

	iters = BUDGETED(CHILD_OP_ATM_VCC_CHURN, JITTER_RANGE(CHURN_ITERS_BASE));
	for (i = 0; i < iters; i++) {
		atm_churn_cycle();
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
