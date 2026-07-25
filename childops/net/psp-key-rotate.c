/*
 * psp_key_rotate - net/psp TCP key install + mid-flow key rotation race.
 *
 * Targets a TOCTOU between PSP_CMD_KEY_ROTATE publishing a new key
 * generation on the device and the per-socket SA refcount walked by the
 * tx/rx hot path in net/psp/{psp_main.c,psp_sock.c,psp_nl.c} -- the rotate
 * flips the active key id under an in-flight sendmsg/recvmsg whose assoc
 * still holds the previous generation.  Random syscall fuzz never assembles
 * the coherent stack: a PSP-capable netdev (in-tree vehicle netdevsim +
 * drivers/net/netdevsim/psp.c), a resolved "psp" genetlink family, an
 * enumerated dev via PSP_CMD_DEV_GET, and a TCP fd attached through
 * PSP_CMD_TX_ASSOC + PSP_A_ASSOC_SOCK_FD.
 *
 * Per iteration inside a userns_run_in_ns grandchild (identity userns +
 * CLONE_NEWNET, _exit reaps): rtnl RTM_NEWLINK a netdevsim + IFF_UP, open
 * an AF_INET SOCK_STREAM with per-syscall timeouts and connect() to
 * loopback, resolve psp family, DEV_GET a psp_dev_id, KEY_ROTATE + TX_ASSOC
 * to arm the SA, then a BUDGETED inner loop (base 4 / floor 8 / cap 16,
 * 200 ms wall) pairing send/recv against a mid-flow KEY_ROTATE and a second
 * TX_ASSOC that switches the bound generation while I/O overlaps the
 * rotate publish.
 *
 * Brick-safety: all net mutation inside CLONE_NEWNET; only SOCK_STREAM +
 * genetlink + rtnl (no raw sockets, no modprobe, no /sys writes);
 * per-syscall SO_RCVTIMEO/SO_SNDTIMEO 100 ms keeps a wedged recv from
 * punching past child.c's SIGALRM(1s) backstop.
 *
 * Latches (per-process): ns_unsupported_psp_key_rotate_master on
 * userns_run_in_ns() -EPERM; cap-gate latches on PSP genetlink family
 * resolution failure (-EPERM / -ENOSYS / -EOPNOTSUPP / -ENOPROTOOPT /
 * -EAFNOSUPPORT / -EPROTONOSUPPORT / -ENODEV -- CONFIG absent or
 * netdevsim/psp not loaded).  Transient setup failures skip without
 * latching.
 *
 * Header-gated by __has_include() on linux/genetlink.h, linux/if_link.h,
 * linux/rtnetlink.h.  PSP UAPI integers (PSP_CMD_DEV_GET / KEY_ROTATE /
 * TX_ASSOC, PSP_A_ASSOC_*) get #define-fallback at their stable UAPI
 * values when <linux/psp.h> is absent; the kernel then returns
 * -ENOPROTOOPT / -EOPNOTSUPP and the cap-gate latches.
 *
 * Spec-vs-reality note: spec called out a SOL_TCP / SO_PSP_SPI setsockopt
 * for the per-socket bind, but no such optname exists in upstream PSP UAPI
 * -- the fd is conveyed via PSP_CMD_TX_ASSOC + PSP_A_ASSOC_SOCK_FD.  The
 * spec's spi_set_ok / spi_switch_ok counter names are preserved.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "pids.h"

#include "kernel/psp.h"

#include "psp-key-rotate-internal.h"

#define PDPC_GATE_ONE_IN		4

#define PKR_NL_RX_BUF			4096

/* Per-grandchild gate.  Inherited as false at grandchild fork time
 * and flipped on the first config-absent rejection (genl_open of the
 * PSP family, PSP_CMD_DEV_GET, or initial KEY_ROTATE) seen inside
 * iter_one_in_ns().  Dies with the grandchild on _exit(); each
 * subsequent grandchild re-discovers the latch in its own fresh
 * netns.  The detection arms are preserved because a fresh user
 * namespace cannot manufacture an absent kernel CONFIG -- the gate
 * still short-circuits the rest of the grandchild's iteration once
 * it fires. */
bool ns_unsupported_psp_key_rotate;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gate
 * above dies with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent
 * invocations. */
static bool ns_unsupported_psp_key_rotate_master;

static void warn_once_unsupported_psp_key_rotate(const char *reason, int err)
{
	if (ns_unsupported_psp_key_rotate_master)
		return;
	ns_unsupported_psp_key_rotate_master = true;
	outputerr("psp_key_rotate: %s failed (errno=%d), latching unsupported_psp_key_rotate\n",
		  reason, err);
}

struct iter_one_ctx {
	unsigned int iter_idx;
	const struct timespec *t_outer;
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the
 * netdevsim instance, rtnl/genl sockets and TCP socket left behind
 * are reaped along with the namespace.  Explicit close() and the
 * randomised teardown order are still issued so the in-ns stats
 * counters move on the success path; correctness does not depend on
 * them.  Writes to ns_unsupported_psp_key_rotate happen in the
 * grandchild's COW memory and die with the grandchild -- the
 * re-discovery cost is paid per invocation.  shm->stats writes (incl.
 * the childop_latch_reason store) propagate because shm is MAP_SHARED.
 * Return value is ignored by the helper.
 */
static int iter_one_in_ns(void *arg)
{
	struct iter_one_ctx *ictx = (struct iter_one_ctx *)arg;
	unsigned int iter_idx = ictx->iter_idx;
	const struct timespec *t_outer = ictx->t_outer;
	struct childdata *child = ictx->child;
	struct nl_ctx rtnl = { .fd = -1 };
	struct genl_ctx psp_ctx = { .nl = { .fd = -1 } };
	int sockfd = -1;
	uint32_t dev_id = 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (psp_key_rotate_iter_setup(&rtnl) != 0)
		goto out;

	if (psp_key_rotate_iter_family_resolve(&psp_ctx, &dev_id) != 0)
		goto out;

	sockfd = psp_key_rotate_iter_socket_install(&psp_ctx, dev_id);
	if (sockfd < 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_psp_key_rotate) {
		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		psp_key_rotate_iter_traffic(sockfd, &psp_ctx, dev_id, t_outer);
	}

	psp_key_rotate_iter_teardown(iter_idx, sockfd, &psp_ctx, &rtnl);
	if (ns_unsupported_psp_key_rotate && valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_NS_UNSUPPORTED,
				 __ATOMIC_RELAXED);
	return 0;

out:
	if (sockfd >= 0)
		close(sockfd);
	if (psp_ctx.nl.fd >= 0)
		genl_close(&psp_ctx);
	if (rtnl.fd >= 0)
		nl_close(&rtnl);
	if (ns_unsupported_psp_key_rotate && valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_NS_UNSUPPORTED,
				 __ATOMIC_RELAXED);
	return 0;
}

static void iter_one(unsigned int iter_idx, const struct timespec *t_outer,
		     struct childdata *child)
{
	struct iter_one_ctx ictx = {
		.iter_idx = iter_idx,
		.t_outer  = t_outer,
		.child    = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
		return;

	rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_ns, &ictx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_psp_key_rotate(
			"userns_run_in_ns(CLONE_NEWNET)", EPERM);
		return;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
}

bool psp_key_rotate(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.psp_key_rotate.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_psp_key_rotate_master) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_PSP_KEY_ROTATE,
			       JITTER_RANGE(PKR_OUTER_BASE));
	if (outer_iters < PKR_OUTER_FLOOR)
		outer_iters = PKR_OUTER_FLOOR;
	if (outer_iters > PKR_OUTER_CAP)
		outer_iters = PKR_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= PKR_WALL_CAP_NS)
			break;

		if (!ns_unsupported_psp_devlink_port &&
		    ONE_IN(PDPC_GATE_ONE_IN))
			iter_devlink_port_churn(i, &t_outer);
		else
			iter_one(i, &t_outer, child);

		if (ns_unsupported_psp_key_rotate_master)
			break;
	}

	return true;
}

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
bool psp_key_rotate(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.psp_key_rotate.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
