/*
 * afxdp_churn - AF_XDP UMEM + ring + XSKMAP + XDP redirect-prog churn.
 *
 * AF_XDP is the most step-heavy family in the kernel: UMEM + four
 * rings (RX/TX/FILL/COMPLETION) + XDP program + XSKMAP entry + bind()
 * all required before a packet flows, so random-syscall fuzzing never
 * assembles a working socket.  Target functions: net/xdp/xsk*.c,
 * net/core/xdp.c:xdp_do_redirect, kernel/bpf/xskmap.c.  Bug class:
 * xsk_setsockopt UAF on duplicate XDP_*_RING, xsk_buff_pool refcount
 * imbalance on bind/unbind churn, xskmap update vs xsk close, and the
 * xdp_do_redirect map-UAF when the bound XSKMAP entry is deleted mid-
 * walk.
 *
 * Per outer iteration (BUDGETED+JITTER, base 5 / floor 16 / cap 64,
 * 200 ms wall cap): stand up an AF_XDP socket with UMEM (64 KiB / 16
 * chunks) and all four rings, create an XSKMAP, BPF_PROG_LOAD the
 * minimal redirect-map program (returns XDP_REDIRECT), bind to lo
 * qid=0 with XDP_USE_NEED_WAKEUP, attach the XDP program (BPF_LINK_
 * CREATE preferred, RTM_NEWLINK IFLA_XDP with XDP_FLAGS_SKB_MODE as
 * fallback -- SKB mode is mandatory on lo), TX one packet, then race
 * MAP_DELETE_ELEM on the bound key against the live redirect walker
 * and munmap a ring while still bound.
 *
 * Brick-safety: lo only, no external NICs; qid=0 (XDP_COPY explicit --
 * no zero-copy on lo).  Attach lifetime is bounded by the link fd
 * (auto-detaches on teardown / child crash) and the 200 ms wall cap
 * bounds any localhost disruption.  UMEM/ring memory is per-iter
 * MAP_PRIVATE|MAP_ANONYMOUS.  setsockopt/sendto are non-blocking with
 * <= 8 EAGAIN/EBUSY retries.
 *
 * Latches: ns_unsupported_afxdp on AF_XDP socket() probe
 * (EAFNOSUPPORT/EPROTONOSUPPORT/EPERM), ns_unsupported_bpf_xdp on
 * BPF_PROG_LOAD failure (AF_XDP without redirect is still useful).
 * Header-gated by __has_include on <linux/if_xdp.h>/<linux/bpf.h>;
 * per-symbol UAPI-integer fallbacks let older sysroots compile
 * (kernel returns -ENOPROTOOPT/-EOPNOTSUPP, latches fire).
 *
 * The setup/attach/io/teardown helpers live in afxdp-churn-{umem,
 * attach,io,teardown}.c; shared declarations, UAPI fallbacks and the
 * per-iter state struct are in afxdp-churn-internal.h.  Only the
 * CHILDOP entry (afxdp_churn) and the iter_one orchestrator stay
 * here.
 */

#if __has_include(<linux/if_xdp.h>) && __has_include(<linux/bpf.h>)

#include "afxdp-churn-internal.h"

/* Definitions of the shared unsupported latches declared extern in
 * afxdp-churn-internal.h.  Kept here (the CHILDOP entry's TU) so
 * there's one obvious owner; every split TU sees them through the
 * internal header. */
bool ns_unsupported_afxdp;
bool ns_unsupported_bpf_xdp;
bool ns_unsupported_xdp_sg;
bool ns_unsupported_tx_metadata;
bool ns_cap_denied_afxdp;

/* One full setup + race + teardown cycle on a fresh AF_XDP socket. */
static void iter_one(struct childdata *child, unsigned int idx,
		     const struct timespec *t_outer)
{
	struct xsk_state st;
	char tun_name[IFNAMSIZ];
	unsigned int target_ifindex;
	bool want_sg, want_tx_md, want_tun, want_tailroom;

	(void)idx;

	if ((unsigned long long)ns_since(t_outer) >= AFXDP_WALL_CAP_NS)
		return;

	xsk_init(&st);

	if (afxdp_iter_setup_umem(child, &st, &want_sg, &want_tx_md, &want_tun) < 0)
		goto out;

	if (afxdp_iter_setup_rings(&st) < 0)
		goto out;

	if (afxdp_iter_setup_bpf(&st) < 0)
		goto out;

	if (afxdp_iter_bind(&st, want_sg, &want_tun, tun_name,
			    &target_ifindex) < 0)
		goto out;

	/* Per-iter acceptance / data-path counters: only credit an iter that
	 * reached a bound xsk — without bind() the downstream attach / tx /
	 * race phases all no-op internally, so neither counter applies.  Gating
	 * both on st.bound preserves the data_path <= setup_accepted invariant
	 * (either both bump together or neither does). */

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (st.bound && valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
	}

	afxdp_iter_attach_prog(&st, target_ifindex);

	if (st.bound && valid_op) {
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	/* Tailroom-probe knob: independent of sg/tx_md.  Fires on ~25% of
	 * iterations to keep the near-full-chunk + ptype_all clone path in
	 * rotation without crowding out the other lanes. */
	want_tailroom = (rnd_u32() & 3U) == 0U;

	afxdp_iter_tx_burst(&st, want_sg, want_tx_md, want_tailroom);

	afxdp_iter_run_races(&st);

out:
	xsk_teardown(&st);
}

bool afxdp_churn(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.afxdp_churn.runs,
			   1, __ATOMIC_RELAXED);

	/* Runtime cap-denied probe: socket(AF_XDP) returned EPERM/EACCES
	 * in a previous iteration; the fuzz user lacks CAP_NET_RAW or is
	 * LSM-blocked.  Distinct from ns_unsupported_afxdp which also fires
	 * for EAFNOSUPPORT (AF_XDP absent from kernel).  Checked first so
	 * dump_stats_dead_arm_check() can emit RUNTIME_DEAD_ARM (cap issue,
	 * fixable) rather than UNSUPPORTED_ARM (kernel build issue). */
	if (ns_cap_denied_afxdp) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed_cap_denied,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (ns_unsupported_afxdp) {
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.afxdp_churn.setup_failed_unsupported,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_AFXDP_CHURN,
			       JITTER_RANGE(AFXDP_OUTER_BASE));
	if (outer_iters < AFXDP_OUTER_FLOOR)
		outer_iters = AFXDP_OUTER_FLOOR;
	if (outer_iters > AFXDP_OUTER_CAP)
		outer_iters = AFXDP_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= AFXDP_WALL_CAP_NS)
			break;

		iter_one(child, i, &t_outer);

		if (ns_unsupported_afxdp)
			break;
	}

	return true;
}

#else  /* missing <linux/if_xdp.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
bool afxdp_churn(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.afxdp_churn.runs_stubbed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
