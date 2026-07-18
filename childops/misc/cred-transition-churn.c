/*
 * cred_transition_churn - rapidly toggle the calling task's own
 * credentials, then immediately drive a permission-sensitive syscall in
 * the same task so the kernel's snapshot-vs-mid-op cred re-check path
 * fires under motion.
 *
 * The kernel snapshots creds at various points (security_prepare_creds,
 * commit_creds, prepare_kernel_cred) and re-checks them mid-operation
 * (per-file open re-validate, keyring possessor gate against current
 * cred->session_keyring, ns_capable against the current user_ns).
 * Random arg-mutation fuzzers never produce a coherent transition
 * sequence: they mutate arguments but leave the caller's cred vector
 * pinned.  This op hand-rolls the sequence:
 *
 *   1. capset() re-installs a churned effective-cap subset of the
 *      permitted set inside a fresh user + net namespace.  Only
 *      effective moves -- permitted stays pinned so subsequent
 *      iterations can raise/drop the same bits without EPERM'ing on
 *      the "effective subset of permitted" rule.
 *   2. Immediately drive one cred-checked op in the SAME task: raw
 *      socket open (CAP_NET_RAW), in-ns unshare(CLONE_NEW*) (CAP_SYS_
 *      ADMIN in the current user_ns), or keyctl(KEYCTL_READ) against a
 *      session-anchored user key (uid/possessor gate).
 *   3. Interleave keyctl session-keyring churn (KEYCTL_JOIN_SESSION_
 *      KEYRING rotates the caller's session anchor, add_key produces a
 *      fresh serial, KEYCTL_READ / KEYCTL_REVOKE terminate lifecycle).
 *      Every op mutates the CALLING task's creds and MUST run in the
 *      same task that ran capset() -- a sibling thread would not see
 *      the effective-cap transition.
 *
 * Environment: userns_run_in_ns() forks a transient grandchild with a
 * fresh identity user namespace + CLONE_NEWNET.  The grandchild is
 * unprivileged in the init user_ns but holds ns-scoped caps inside its
 * own userns; every ns_capable() gate against the fresh user_ns
 * therefore fires meaningfully.  setresuid/setresgid/setgroups are
 * deliberately absent: with only ns uid/gid 0 mapped and setgroups
 * denied, they collapse to EINVAL/EPERM without reaching commit_creds.
 *
 * Bricking / safety: everything happens in the transient grandchild;
 * _exit() reaps every socket, keyring, and namespace ref this op
 * touched.  Tolerated failure modes (that is the point of the reject-
 * path coverage): EPERM, EACCES, EINVAL from capset / socket / unshare
 * / keyctl.  Never spins on failure -- iteration count is BUDGETED-
 * capped.
 *
 * Cap-gate latch: ns_unsupported_cred_transition on userns_run_in_ns()
 * -EPERM in the persistent child; subsequent invocations bump
 * setup_failed and short-circuit.  Mirrors the netns-teardown-churn
 * latch pattern.
 *
 * Bounds: outer BUDGETED base CRED_XN_OUTER_BASE / cap CRED_XN_OUTER_
 * CAP, JITTER +/- 50%.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#if __has_include(<sched.h>) && __has_include(<linux/capability.h>) && \
    __has_include(<linux/keyctl.h>)

#include <linux/capability.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "jitter.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "syscall-gate.h"

#include "kernel/keyctl.h"

/* Per-process latched gate: userns_run_in_ns() returned -EPERM, meaning
 * the grandchild's unshare(CLONE_NEWUSER) was refused by a hardened
 * policy (user.max_user_namespaces=0 or kernel.unprivileged_userns_
 * clone=0).  Without a private user namespace we cannot rehearse the
 * capset() re-install path at all (the persistent fuzz child runs
 * cap-dropped and would silently EPERM out of every raise), so the op
 * stays disabled for the remainder of this child's lifetime.  Mirrors
 * the netns_teardown_churn latch. */
static bool ns_unsupported_cred_transition;

#define CRED_XN_OUTER_BASE		4U
#define CRED_XN_OUTER_CAP		12U
#define CRED_XN_LIVE_KEYS		4U
#define CRED_XN_PAYLOAD_BYTES		16U

/* Curated set of capability bits worth churning in the effective mask.
 * All live in the low 32 bits (data[0]) of a v3 capset payload, so a
 * single mask covers them without straddling the data[1] boundary.
 * Each maps to a distinct kernel gate we drive in the "op" arm:
 *   CAP_NET_RAW      -> AF_INET SOCK_RAW open
 *   CAP_NET_ADMIN    -> raw socket bind + SO_BROADCAST-style setsockopts
 *   CAP_SYS_ADMIN    -> unshare(CLONE_NEW*) inside the current user_ns
 *   CAP_DAC_OVERRIDE -> opens against restrictive DAC (kept in mask so
 *                       capset install path exercises the bit) */
#define CRED_XN_CHURN_CAPS ( \
	(1u << CAP_NET_RAW) | \
	(1u << CAP_NET_ADMIN) | \
	(1u << CAP_SYS_ADMIN) | \
	(1u << CAP_DAC_OVERRIDE))

/* Post-capset op arms.  Each is gated on a capability in
 * CRED_XN_CHURN_CAPS so the op's success/EPERM outcome tracks whether
 * the just-installed effective mask carries that bit. */
enum cred_xn_op {
	CRED_XN_OP_RAW_SOCKET = 0,
	CRED_XN_OP_UNSHARE_NS,
	CRED_XN_OP_KEYCTL_READ,
	NR_CRED_XN_OPS,
};

/* Per-iteration ctx.  Lifetime is exactly one iter_one() invocation. */
struct cred_xn_ctx {
	int32_t		live_keys[CRED_XN_LIVE_KEYS];
	__u32		permitted_low;	/* data[0].permitted snapshot from capget */
	__u32		permitted_high;	/* data[1].permitted snapshot from capget */
};

/*
 * capget(hdr, data) into a v3 two-datum buffer.  Returns 0 on success
 * and fills the permitted-low / permitted-high snapshot fields.
 * Failure returns
 * -1 (rare: only if the kernel refuses v3, which no supported kernel
 * does).  Called once per iter_one so the caller has a fresh snapshot
 * of the permitted mask before picking a churned effective subset --
 * the mask can shift under us if a sibling capset() ran between iters.
 */
static int cred_transition_capget_snapshot(struct cred_xn_ctx *it)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	if (syscall(SYS_capget, &hdr, data) != 0)
		return -1;

	it->permitted_low  = data[0].permitted;
	it->permitted_high = data[1].permitted;
	return 0;
}

/*
 * Phase 1: capset() to a churned effective-cap subset of permitted.
 * Only effective moves; permitted / inheritable stay pinned so
 * subsequent iterations can raise or drop the same churned bits
 * without EPERM'ing on the "effective subset of permitted" rule.  The
 * churn mask is drawn as (rand32() & permitted & CRED_XN_CHURN_CAPS)
 * so only the bits we actually gate ops on move; every unrelated cap
 * stays as capget saw it.  Bumps capset_ok / capset_failed.
 */
static void cred_transition_iter_capset(struct cred_xn_ctx *it)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];
	__u32 churn_low;

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	churn_low = rand32() & it->permitted_low & CRED_XN_CHURN_CAPS;

	data[0].effective   = churn_low;
	data[0].permitted   = it->permitted_low;
	data[0].inheritable = 0;
	data[1].effective   = 0;
	data[1].permitted   = it->permitted_high;
	data[1].inheritable = 0;

	if (syscall(SYS_capset, &hdr, data) == 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.capset_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.capset_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Op arm 1: raw socket open.  Gated on CAP_NET_RAW in the current
 * user_ns; with the bit cleared from effective by the previous capset
 * the kernel returns EPERM.  Close-on-return -- we do not thread the
 * fd onto anything else (the goal is to exercise the ns_capable() gate
 * at socket() time, not to build socket state).
 */
static void cred_transition_op_raw_socket(void)
{
	int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);

	if (fd >= 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.op_ok,
				   1, __ATOMIC_RELAXED);
		(void)close(fd);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.op_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Op arm 2: in-ns unshare().  CLONE_NEWUTS / CLONE_NEWIPC gate on
 * ns_capable(current_user_ns(), CAP_SYS_ADMIN); with the bit cleared
 * the kernel returns EPERM.  The unshare mutates the caller's nsproxy,
 * which is fine -- the transient grandchild's _exit() reaps every
 * namespace it accumulated.
 */
static void cred_transition_op_unshare_ns(void)
{
	int flag = RAND_BOOL() ? CLONE_NEWUTS : CLONE_NEWIPC;

	if (unshare(flag) == 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.op_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.op_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Op arm 3: keyctl(KEYCTL_READ) against a live session-anchored user
 * key.  The read gate walks the cred->session_keyring possessor chain
 * and cross-checks fsuid against the key's owner -- both are cred
 * fields the JOIN_SESSION_KEYRING churn moves under us.  Skips when
 * the ring is empty (early iter before any add_key produced a serial).
 */
static void cred_transition_op_keyctl_read(struct cred_xn_ctx *it)
{
	unsigned char buf[32];
	int32_t serial = 0;
	unsigned int i;
	long rc;

	for (i = 0; i < CRED_XN_LIVE_KEYS; i++) {
		if (it->live_keys[i] != 0) {
			serial = it->live_keys[i];
			break;
		}
	}
	if (serial == 0)
		return;

	rc = trinity_raw_syscall(__NR_keyctl,
				 (unsigned long)KEYCTL_READ,
				 (unsigned long)serial,
				 (unsigned long)buf,
				 (unsigned long)sizeof(buf), 0UL);
	if (rc >= 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.op_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.op_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 2 dispatch: pick one of the three op arms and drive it in the
 * SAME task that just ran capset().  Vary per-iter so no single arm
 * dominates the coverage.
 */
static void cred_transition_iter_op(struct cred_xn_ctx *it)
{
	enum cred_xn_op op = (enum cred_xn_op)rnd_modulo_u32(NR_CRED_XN_OPS);

	switch (op) {
	case CRED_XN_OP_RAW_SOCKET:
		cred_transition_op_raw_socket();
		break;
	case CRED_XN_OP_UNSHARE_NS:
		cred_transition_op_unshare_ns();
		break;
	case CRED_XN_OP_KEYCTL_READ:
		cred_transition_op_keyctl_read(it);
		break;
	case NR_CRED_XN_OPS:
		break;
	}
}

/*
 * KEYCTL_JOIN_SESSION_KEYRING: install a fresh anonymous session
 * keyring on the caller.  Rotates cred->session_keyring, invalidating
 * every serial previously added to the old session anchor -- so drop
 * the tracking ring on success.  Passing NULL asks the kernel for an
 * anonymous keyring name.
 */
static void cred_transition_keyctl_join(struct cred_xn_ctx *it)
{
	long rc = trinity_raw_syscall(__NR_keyctl,
				      (unsigned long)KEYCTL_JOIN_SESSION_KEYRING,
				      0UL, 0UL, 0UL, 0UL);

	if (rc >= 0) {
		memset(it->live_keys, 0, sizeof(it->live_keys));
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * add_key("user", ...) anchored to KEY_SPEC_SESSION_KEYRING.  The
 * serial the kernel returns lands in the tracking ring so the
 * KEYCTL_READ op arm has something to read.  Overwrites the oldest
 * slot on ring full.
 */
static void cred_transition_keyctl_add(struct cred_xn_ctx *it,
				       unsigned int iter,
				       const unsigned char *payload)
{
	char desc[64];
	long rc;

	snprintf(desc, sizeof(desc), "trinity-cred-xn-%u-%u",
		 (unsigned int)mypid(), iter);

	rc = trinity_raw_syscall(__NR_add_key, "user", desc, payload,
				 (size_t)CRED_XN_PAYLOAD_BYTES,
				 (unsigned long)KEY_SPEC_SESSION_KEYRING);
	if (rc >= 0) {
		unsigned int slot = rnd_modulo_u32(CRED_XN_LIVE_KEYS);
		unsigned int i;
		for (i = 0; i < CRED_XN_LIVE_KEYS; i++) {
			if (it->live_keys[i] == 0) {
				slot = i;
				break;
			}
		}
		it->live_keys[slot] = (int32_t)rc;
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * KEYCTL_REVOKE against a live serial.  Terminates the key's usable
 * lifecycle; subsequent KEYCTL_READ against the same serial will
 * exercise the -EKEYREVOKED validate path.  Clears the ring slot
 * regardless of return value -- a failing revoke on a serial we
 * thought was live means the ring is stale anyway.
 */
static void cred_transition_keyctl_revoke(struct cred_xn_ctx *it)
{
	unsigned int i;
	int32_t serial = 0;
	long rc;

	for (i = 0; i < CRED_XN_LIVE_KEYS; i++) {
		if (it->live_keys[i] != 0) {
			serial = it->live_keys[i];
			it->live_keys[i] = 0;
			break;
		}
	}
	if (serial == 0)
		return;

	rc = trinity_raw_syscall(__NR_keyctl,
				 (unsigned long)KEYCTL_REVOKE,
				 (unsigned long)serial, 0UL, 0UL, 0UL);
	if (rc >= 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.cred_transition.keyctl_failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase 3: one interleaved keyctl session-keyring churn call per iter.
 * Distribution is weighted -- add_key runs ~half the time so the
 * tracking ring stays fed for the KEYCTL_READ op arm, JOIN and REVOKE
 * each ~quarter.  Every arm mutates or reads state anchored to the
 * calling task's cred->session_keyring, which the JOIN arm just
 * rotated -- the point of the interleave.
 */
static void cred_transition_iter_keyctl(struct cred_xn_ctx *it,
					unsigned int iter,
					const unsigned char *payload)
{
	unsigned int bucket = rnd_modulo_u32(4);

	if (bucket < 2)
		cred_transition_keyctl_add(it, iter, payload);
	else if (bucket == 2)
		cred_transition_keyctl_join(it);
	else
		cred_transition_keyctl_revoke(it);
}

/*
 * One outer iteration: capget snapshot, capset re-install, cred-checked
 * op, keyctl churn.  Best-effort; per-arm counter bumps carry the
 * success signal.  A capget failure short-circuits the iter (without
 * a fresh permitted snapshot the capset() below would be running on
 * stale data and could refuse the effective bits).
 */
static void iter_one(struct cred_xn_ctx *it, unsigned int iter,
		     const unsigned char *payload)
{
	if (cred_transition_capget_snapshot(it) != 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	cred_transition_iter_capset(it);
	cred_transition_iter_op(it);
	cred_transition_iter_keyctl(it, iter, payload);
}

/*
 * Per-invocation state carried into the userns_run_in_ns callback.
 * child is the caller's struct childdata so the in-ns body can attribute
 * per-childop yield counters to child->op_type.
 */
struct cred_transition_ns_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that runs inside the transient grandchild's
 * fresh user + net namespace.  BUDGETED outer loop over iter_one; the
 * grandchild's _exit() tears every keyring, socket, and nsproxy ref
 * this loop accumulated.  Return value is ignored.
 */
static int cred_transition_churn_in_ns(void *arg)
{
	struct cred_transition_ns_ctx *cctx = arg;
	struct childdata *child = cctx->child;
	struct cred_xn_ctx it;
	unsigned char payload[CRED_XN_PAYLOAD_BYTES];
	unsigned int iters, i;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int)op >= 0 && op < NR_CHILD_OP_TYPES);

	memset(&it, 0, sizeof(it));
	memset(payload, 0xa5, sizeof(payload));

	iters = BUDGETED(CHILD_OP_CRED_TRANSITION_CHURN,
			 JITTER_RANGE(CRED_XN_OUTER_BASE));
	if (iters > CRED_XN_OUTER_CAP)
		iters = CRED_XN_OUTER_CAP;
	if (iters == 0U)
		iters = 1U;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	for (i = 0; i < iters; i++)
		iter_one(&it, i, payload);

	return 0;
}

bool cred_transition_churn(struct childdata *child)
{
	struct cred_transition_ns_ctx cctx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.cred_transition.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_cred_transition) {
		__atomic_add_fetch(&shm->stats.cred_transition.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rc = userns_run_in_ns(CLONE_NEWNET, cred_transition_churn_in_ns, &cctx);
	if (rc == -EPERM) {
		ns_unsupported_cred_transition = true;
		{
			const enum child_op_type op = child->op_type;
			if ((int)op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.cred_transition.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.cred_transition.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<sched.h>) || !<linux/capability.h> || !<linux/keyctl.h> */

bool cred_transition_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.cred_transition.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.cred_transition.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
