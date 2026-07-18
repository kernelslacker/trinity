/*
 * netns_mountns_setup_probe - hammer the fresh-namespace SETUP path for
 * net + mount namespaces.  Setup-side twin of netns_teardown_churn: that
 * op races cleanup_net() and the pernet ->exit / ->exit_batch hooks;
 * this one races setup_net() and the pernet ->init hooks plus the fresh
 * mount-ns propagation-mode initialisation.
 *
 * Random blob mutation never composes a valid setup sequence (unshare
 * flags collide with MS_* constants; mount() targets are unreachable
 * without a prior propagation flip), so the sequence is hand-rolled.
 *
 * Per invocation runs inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET|CLONE_NEWNS, _exit reaps).  BUDGETED outer loop
 * body:
 *   a. unshare(CLONE_NEWNET|CLONE_NEWNS) — fresh net + mount ns nested
 *      inside the grandchild's owned userns.  Repeated unshares are
 *      allowed because the grandchild holds CAP_SYS_ADMIN in the
 *      enclosing userns; each unshare drops the prior nested pair and
 *      allocates a new one, driving setup_net() + copy_mnt_ns() again.
 *   b. mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) — flip the fresh
 *      mount-ns's propagation mode away from the inherited shared type
 *      so subsequent mount ops don't leak upward.
 *   c. best-effort rtnl RTM_NEWLINK IFLA lo UP + RTM_NEWADDR 127.0.0.1
 *      — drives the pernet netdev init path for the freshly-installed
 *      loopback device.
 *   d. socket(AF_INET, SOCK_DGRAM, 0) — first sock_alloc in the fresh
 *      netns; touches sock_net attribution and the pernet inet init
 *      state.  Immediately closed; the fresh netns is torn down by the
 *      next iter's unshare (or grandchild _exit) with no accumulated
 *      sockets.
 *
 * Brick-safety: every mount / netlink / socket op runs inside the
 * transient grandchild's private user+net+mount ns; on grandchild
 * _exit() the kernel reaps the whole namespace stack.  No persistent
 * state.  Best-effort throughout — a helper failure bumps its phase's
 * counter (or doesn't bump the success one) and the loop continues to
 * the next iter, since the interesting race is the setup sequence
 * itself, not any single helper's success.
 *
 * Cap-gate latch: ns_unsupported_netns_mountns_setup on
 * userns_run_in_ns() -EPERM in the persistent child; subsequent
 * invocations bump setup_failed and return.  Matches the
 * ns_unsupported_netns_teardown latch in netns-teardown-churn.c.
 *
 * Bounds: outer BUDGETED base NETNS_MSP_OUTER_BASE / cap
 * NETNS_MSP_OUTER_CAP, JITTER +/-50%.
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#if __has_include(<sched.h>) && __has_include(<linux/netlink.h>)

#include <netinet/in.h>
#include <sched.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if.h>

#include "childops-netlink.h"
#include "jitter.h"

#include "kernel/netlink.h"

/* Per-process latched gate: userns_run_in_ns() returned -EPERM, meaning
 * unshare(CLONE_NEWUSER) inside the grandchild was refused by a
 * hardened policy (user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  Without a private user ns the
 * setup-path probe cannot drive net+mount ns setup at all, so the op
 * stays disabled for the remainder of this child's lifetime.  Mirrors
 * ns_unsupported_netns_teardown in netns-teardown-churn.c. */
static bool ns_unsupported_netns_mountns_setup;

#define NETNS_MSP_OUTER_BASE	2U
#define NETNS_MSP_OUTER_CAP	6U

/*
 * RTM_NEWLINK setlink ifindex IFLA_IFI_UP — flip the loopback device's
 * IFF_UP bit inside the fresh net ns.  ifi_change set to IFF_UP only so
 * we don't mask any other flags.
 */
static int lo_set_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * RTM_NEWADDR ipv4 /8 attached to ifindex with 127.0.0.1.  EEXIST is
 * benign — a fresh net ns already carries the address on most kernels
 * via the v4 zero-config path.  We issue it anyway to drive the pernet
 * inetaddr init side of the setup path.
 */
static int lo_add_addr(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 8;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_HOST;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	addr = htonl(0x7f000001U);
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Bring lo up + assign 127.0.0.1 inside the fresh net ns.  Returns 0
 * iff nl_open() succeeded (drives the pernet netdev init path even if
 * either sub-op fails); returns -1 iff nl_open() failed, meaning we
 * never touched the setup path at all.
 */
static int bring_up_loopback(void)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto = NETLINK_ROUTE,
		.recv_timeo_s = 1,
	};
	const int lo_ifindex = 1;	/* lo is always ifindex 1 in a fresh net ns */

	if (nl_open(&ctx, &opts) < 0)
		return -1;

	(void)lo_add_addr(&ctx, lo_ifindex);
	(void)lo_set_up(&ctx, lo_ifindex);
	nl_close(&ctx);
	return 0;
}

/*
 * One outer iteration.  Drives one full setup-path cycle: fresh
 * net+mount ns → propagation flip → loopback bring-up → first
 * in-netns socket.  Best-effort; a helper failure bumps its phase's
 * failure signal (or simply skips the success counter) and we continue
 * the sequence, since the interesting race is the setup sequence
 * itself, not any single helper's success.  The grandchild's next iter
 * (or its _exit) reaps whatever nested ns state we leave behind.
 */
static void iter_one(struct childdata *child)
{
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int fd;

	if (unshare(CLONE_NEWNET | CLONE_NEWNS) < 0) {
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	__atomic_add_fetch(&shm->stats.netns_mountns_setup.unshare_ok,
			   1, __ATOMIC_RELAXED);
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0) {
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.mount_private_ok,
				   1, __ATOMIC_RELAXED);
	}

	if (bring_up_loopback() == 0) {
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.loopback_ok,
				   1, __ATOMIC_RELAXED);
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.socket_ok,
				   1, __ATOMIC_RELAXED);
		(void)close(fd);
	}

	__atomic_add_fetch(&shm->stats.netns_mountns_setup.completed_ok,
			   1, __ATOMIC_RELAXED);
}

struct netns_mountns_setup_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside a private user+net+mount
 * namespace.  Executed in a transient grandchild forked by
 * userns_run_in_ns(CLONE_NEWNET|CLONE_NEWNS); the grandchild's whole
 * namespace stack is torn down on _exit() so every nested ns / mount /
 * socket left behind by the BUDGETED outer loop is reaped by the
 * kernel.  Return value is ignored by the helper.
 */
static int netns_mountns_setup_in_ns(void *arg)
{
	struct netns_mountns_setup_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	unsigned int outer_iters, i;

	outer_iters = BUDGETED(CHILD_OP_NETNS_MOUNTNS_SETUP_PROBE,
			       JITTER_RANGE(NETNS_MSP_OUTER_BASE));
	if (outer_iters > NETNS_MSP_OUTER_CAP)
		outer_iters = NETNS_MSP_OUTER_CAP;
	if (outer_iters == 0U)
		outer_iters = 1U;

	for (i = 0; i < outer_iters; i++)
		iter_one(child);

	return 0;
}

bool netns_mountns_setup_probe(struct childdata *child)
{
	struct netns_mountns_setup_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.netns_mountns_setup.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_netns_mountns_setup) {
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET | CLONE_NEWNS,
			      netns_mountns_setup_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_netns_mountns_setup = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary CLONE_NEWNET|CLONE_NEWNS unshare).  Skip this
		 * iteration without latching -- the failure is not policy
		 * and may not recur. */
		__atomic_add_fetch(&shm->stats.netns_mountns_setup.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<sched.h>) || !<linux/netlink.h> */

bool netns_mountns_setup_probe(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.netns_mountns_setup.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.netns_mountns_setup.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
