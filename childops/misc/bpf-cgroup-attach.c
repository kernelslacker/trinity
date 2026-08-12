/*
 * bpf_cgroup_attach - cgroup BPF attach/detach lifecycle race over a live UDP
 * socket against rotating cgroup attach types (CGROUP_SKB ingress/egress and
 * CGROUP_SOCK_ADDR connect/sendmsg/recvmsg).
 *
 * Per-syscall fuzzing rolls bpf() commands one at a time and never composes
 * the three pieces of state every cgroup-bpf bug class requires:
 *
 *   1. cgroup membership for the current task,
 *   2. a verifier-passing program loaded for a matching attach type, and
 *   3. a live socket op that actually drives the hook chain.
 *
 * Without all three coinciding, kernel/bpf/cgroup.c (the per-cgroup
 * bpf_prog_array dispatch) and net/core/filter.c (cgroup_skb / sock_addr
 * verifier-blessed runtime) stay almost entirely cold.  CVE-2023-39193
 * (cgroup_skb verdict UAF), CVE-2024-26654 (cgroup BPF link refcount),
 * CVE-2023-2163 (cgroup_storage), and the broader cgroup-bpf attach/detach
 * race family all live on the lifecycle window between PROG_ATTACH /
 * PROG_DETACH and the hook actually firing inside a syscall.
 *
 * Sequence per invocation:
 *
 *   1. Open a writable cgroup directory under /sys/fs/cgroup/trinity{0..7}
 *      (the same set munge_process() arranges for sibling fd providers).
 *      Latch off on missing/EACCES so a kernel without those dirs pays
 *      the cost once per child.
 *   2. Pick an attach type uniformly from:
 *        BPF_CGROUP_INET_INGRESS / BPF_CGROUP_INET_EGRESS    (CGROUP_SKB)
 *        BPF_CGROUP_INET4_CONNECT                            (SOCK_ADDR)
 *        BPF_CGROUP_UDP4_SENDMSG / BPF_CGROUP_UDP4_RECVMSG   (SOCK_ADDR)
 *      Pick the matching prog_type and set expected_attach_type at
 *      PROG_LOAD for SOCK_ADDR (the verifier requires it; SKB programs
 *      can be loaded without it).
 *   3. PROG_LOAD a 2-insn template "r0 = 1; exit" (return 1 = allow).
 *      That's the smallest verifier-passing CGROUP_SKB / SOCK_ADDR
 *      program — what we want is the attach/detach race surface, not
 *      verifier coverage (bpf_lifecycle.c covers verifier paths).
 *      Latch off on EPERM/EACCES so a kernel without CAP_BPF skips
 *      the rest of this child's life.
 *   4. PROG_ATTACH to the cgroup with attach_flags=0 (~50%) or
 *      BPF_F_ALLOW_MULTI (~50%) so both single-attach and multi-attach
 *      dispatch arrays get exercised.
 *   5. Drive the attached hook with a UDP loopback burst:
 *        - socket(AF_INET, SOCK_DGRAM)
 *        - sendto(127.0.0.1) drives EGRESS / UDP4_SENDMSG hooks;
 *          the matching INGRESS / UDP4_RECVMSG hook fires when the kernel
 *          delivers the packet back into our cgroup
 *        - connect(127.0.0.1) drives INET4_CONNECT
 *      Multiple iterations populate the per-cgroup hook array's
 *      access pattern.
 *   6. PROG_DETACH while another burst is still in flight.  This is the
 *      attach-vs-detach race window the CVE class lives in: the
 *      bpf_prog_array_copy_to_user / __cgroup_bpf_detach path mutates
 *      cgrp->bpf.effective[type] under cgroup_mutex, but the dispatch
 *      side (BPF_PROG_RUN_ARRAY_CG) walks the array under RCU only.
 *      Send a post-detach burst — should hit the empty/just-detached
 *      array; UAF in stale dispatch tables surfaces here.
 *   7. Close the program fd and the cgroup fd.
 *
 * Self-bounding: single-pass per call, all sockets non-blocking, all bpf()
 * failures swallowed (errno-based stat increments only).  The SIGALRM(1s)
 * the parent installs in child.c bounds any pathological blocking case.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "childop-outcome.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#ifndef BPF_F_ALLOW_MULTI
#define BPF_F_ALLOW_MULTI	(1U << 1)
#endif

/* Older UAPI headers may lack SOCK_ADDR and SOCKOPT attach types.  Provide
 * the canonical numeric values from include/uapi/linux/bpf.h so this builds
 * on stale kernel headers (Trinity targets a wide kernel range). */
#ifndef BPF_CGROUP_INET4_CONNECT
#define BPF_CGROUP_INET4_CONNECT	10
#endif
#ifndef BPF_CGROUP_UDP4_SENDMSG
#define BPF_CGROUP_UDP4_SENDMSG		14
#endif
#ifndef BPF_CGROUP_UDP4_RECVMSG
#define BPF_CGROUP_UDP4_RECVMSG		19
#endif
#ifndef BPF_CGROUP_GETSOCKOPT
#define BPF_CGROUP_GETSOCKOPT		21
#endif
#ifndef BPF_CGROUP_SETSOCKOPT
#define BPF_CGROUP_SETSOCKOPT		22
#endif
#ifndef BPF_PROG_TYPE_CGROUP_SOCK_ADDR
#define BPF_PROG_TYPE_CGROUP_SOCK_ADDR	18
#endif
#ifndef BPF_PROG_TYPE_CGROUP_SOCKOPT
#define BPF_PROG_TYPE_CGROUP_SOCKOPT	25
#endif
#ifndef SOL_UDP
#define SOL_UDP			17
#endif

#define BURST		4

/*
 * Latched off on first irrecoverable failure (no cgroup access, no
 * CAP_BPF) so we don't spin for the rest of this child's life.
 * Per-child static — each forked child gets its own copy.
 */
static bool latched_off;

struct attach_combo {
	uint32_t prog_type;
	uint32_t attach_type;
	bool needs_expected_at;
};

static const struct attach_combo combos[] = {
	{ BPF_PROG_TYPE_CGROUP_SKB,      BPF_CGROUP_INET_INGRESS,  false },
	{ BPF_PROG_TYPE_CGROUP_SKB,      BPF_CGROUP_INET_EGRESS,   false },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, true  },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG,  true  },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG,  true  },
	/*
	 * CGROUP_SOCKOPT: the kernel substitutes a tight kmalloc(ctx.optlen)
	 * heap buffer for the user pointer on BPF context export when
	 * optlen <= BPF_SOCKOPT_KERN_BUF_SIZE (32 bytes).  A pass-through
	 * program is sufficient — setsockopt_burst() biases toward optlen
	 * <= 32 to stay in that heap-buffer path.  expected_attach_type is
	 * required at PROG_LOAD time (same as SOCK_ADDR).
	 */
	{ BPF_PROG_TYPE_CGROUP_SOCKOPT,  BPF_CGROUP_SETSOCKOPT,    true  },
	{ BPF_PROG_TYPE_CGROUP_SOCKOPT,  BPF_CGROUP_GETSOCKOPT,    true  },
};

/*
 * Load the smallest possible verifier-passing program for the given
 * combo: "r0 = 1; exit".  Returns 1 = allow on every attach type listed
 * above (CGROUP_SKB: pass packet; SOCK_ADDR: allow the operation).
 *
 * SOCK_ADDR programs require expected_attach_type at load time so the
 * verifier picks the right context-access rules.  CGROUP_SKB doesn't
 * strictly need it but accepts it.
 */
static int load_allow_prog(const struct attach_combo *c)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 1),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = c->prog_type;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;
	if (c->needs_expected_at)
		attr.expected_attach_type = c->attach_type;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/*
 * Load the EFAULT-probe program for CGROUP_SETSOCKOPT / CGROUP_GETSOCKOPT.
 *
 * The program unconditionally overwrites ctx->optlen with a value far above
 * BPF_SOCKOPT_KERN_BUF_SIZE (32 bytes).  After the program returns,
 * __cgroup_bpf_run_filter_setsockopt() (and its getsockopt twin) checks:
 *
 *   if (ctx.optlen > max_optlen || ctx.optlen < -1)  =>  return -EFAULT;
 *
 * A valid user buffer combined with a valid optname can never trigger that
 * branch on its own, so observing EFAULT on a setsockopt/getsockopt call
 * is conclusive proof the BPF hook actually ran.
 *
 * bpf_sockopt context layout (uapi/linux/bpf.h):
 *   offset  0: sk         (8 bytes)
 *   offset  8: optval     (8 bytes)
 *   offset 16: optval_end (8 bytes)
 *   offset 24: level      (4 bytes)
 *   offset 28: optname    (4 bytes)
 *   offset 32: optlen     (4 bytes)  <-- overwritten by this program
 *   offset 36: retval     (4 bytes)
 */
static int load_efault_probe_prog(const struct attach_combo *c)
{
	struct bpf_insn insns[] = {
		/* r2 = 0x01000000 (16 MiB; far above max_optlen = 32) */
		EBPF_MOV64_IMM(BPF_REG_2, 0x01000000),
		/* *(u32 *)(r1 + 32) = r2 — overwrite ctx->optlen */
		EBPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, 32),
		/* r0 = 1 (allow) */
		EBPF_MOV64_IMM(BPF_REG_0, 1),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = c->prog_type;	/* BPF_PROG_TYPE_CGROUP_SOCKOPT */
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;
	attr.expected_attach_type = c->attach_type;	/* required for CGROUP_SOCKOPT */

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static bool is_sockopt_combo(const struct attach_combo *c)
{
	return c->attach_type == BPF_CGROUP_SETSOCKOPT ||
	       c->attach_type == BPF_CGROUP_GETSOCKOPT;
}

/*
 * Drive CGROUP_SETSOCKOPT / CGROUP_GETSOCKOPT hooks on a UDP socket
 * already inside the cgroup.  Bias toward optlen <= 32 — that is the
 * BPF_SOCKOPT_KERN_BUF_SIZE threshold where the kernel allocates a tight
 * kmalloc(ctx.optlen) on BPF context export, making any over-read into
 * that buffer immediately KASAN-visible.
 *
 * Both set and get are issued for every option so a single burst drives
 * both attach types.
 *
 * Hook-reach detection: when the EFAULT probe program is attached, any
 * setsockopt/getsockopt that returns -EFAULT proves the hook ran (the
 * probe bumps ctx->optlen past max_optlen; a valid buffer + optname
 * can never trigger that path on its own).  The count of EFAULTs is
 * returned through *set_reach_out (setsockopt) and *get_reach_out
 * (getsockopt) independently.  After PROG_DETACH the probe is gone,
 * so EFAULTs should drop to zero — a non-zero post-detach value
 * flags a stale-dispatch bug in the cgroup BPF plumbing.
 */
static void setsockopt_burst(uint32_t attach_type, bool probe_active,
			     unsigned int *calls_out,
			     unsigned long *set_reach_out,
			     unsigned long *get_reach_out)
{
	/*
	 * Level and optname pools are drawn independently on each
	 * iteration so every (level, optname) cross-product is reachable.
	 * Most cross-protocol combinations are rejected by the kernel's
	 * protocol-layer validation (ENOPROTOOPT / EINVAL) after the
	 * cgroup BPF hook has already run, so each call still reaches the
	 * hook and contributes to the KASAN surface regardless of whether
	 * the optname is valid for the chosen level.
	 */
	static const int levels[] = {
		SOL_SOCKET,
		IPPROTO_IP,
		IPPROTO_TCP,
		SOL_UDP,
	};
	static const struct {
		int		optname;
		unsigned int	optlen;
	} optnames[] = {
		/* SOL_SOCKET options — original private table */
		{ SO_REUSEADDR,  4  },	/* 4 B — tight kmalloc path */
		{ SO_KEEPALIVE,  4  },
		{ SO_RCVBUF,     4  },
		{ SO_SNDBUF,     4  },
		{ SO_PRIORITY,   4  },
		{ SO_RCVBUF,     16 },	/* 16 B — still < 32 */
		{ SO_SNDBUF,     16 },
		{ SO_KEEPALIVE,  32 },	/* 32 B — at the threshold */
		/* IPPROTO_IP options */
		{ IP_TTL,        4  },
		{ IP_TOS,        4  },
		{ IP_RECVTTL,    4  },
		/* IPPROTO_TCP options */
		{ TCP_NODELAY,   4  },
		{ TCP_KEEPIDLE,  4  },
		{ TCP_KEEPINTVL, 4  },
		{ TCP_MAXSEG,    4  },
		/* SOL_UDP options */
		{ UDP_CORK,      4  },
	};
	uint8_t buf[32];
	unsigned long set_reach = 0;
	unsigned long get_reach = 0;
	unsigned int calls = 0;
	unsigned int i;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	calls++;
	if (s < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(optnames); i++) {
		socklen_t len;
		/*
		 * Pick level independently of optname to exercise the full
		 * cross-protocol combination space through the hook.
		 */
		int level = levels[rnd_modulo_u32(ARRAY_SIZE(levels))];

		memset(buf, 0, sizeof(buf));
		buf[0] = 1;	/* non-zero value for boolean options */

		/*
		 * setsockopt — drives the CGROUP_SETSOCKOPT hook before
		 * kernel-level option validation.  With the EFAULT probe
		 * attached, the hook overwrites ctx->optlen to a large
		 * value and the kernel returns EFAULT; count it as
		 * confirmed hook reach.
		 */
		if (setsockopt(s, level, optnames[i].optname,
			       buf, optnames[i].optlen) < 0 && errno == EFAULT)
			set_reach++;
		if (attach_type == BPF_CGROUP_SETSOCKOPT && probe_active)
			__atomic_add_fetch(
				&shm->stats.bpf_cgroup_attach.setsockopt_probe_calls,
				1, __ATOMIC_RELAXED);
		calls++;

		/* getsockopt — separate CGROUP_GETSOCKOPT hook invocation */
		len = (socklen_t)optnames[i].optlen;
		if (getsockopt(s, level, optnames[i].optname,
			       buf, &len) < 0 && errno == EFAULT)
			get_reach++;
		if (attach_type == BPF_CGROUP_GETSOCKOPT && probe_active)
			__atomic_add_fetch(
				&shm->stats.bpf_cgroup_attach.getsockopt_probe_calls,
				1, __ATOMIC_RELAXED);
		calls++;
	}

	close(s);
	calls++;
out:
	*calls_out = calls;
	*set_reach_out = set_reach;
	*get_reach_out = get_reach;
}

/* Drive the hook with a UDP loopback burst.  For CONNECT we additionally
 * issue connect() to fire INET4_CONNECT.  Returns the count of send/connect
 * ops that returned >= 0 — used for the packets_sent stat.  Emits the
 * number of direct kernel calls issued (socket/connect/sendto/recv/close,
 * the syscalls that actually drive the cgroup-bpf hook chain) through
 * *calls_out for the childop_direct_syscalls reporter.
 */
static unsigned int udp_burst(uint32_t attach_type, unsigned int *calls_out)
{
	struct sockaddr_in sin;
	unsigned int sent = 0;
	unsigned int calls = 0;
	int s;
	int i;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)RAND_RANGE(1024, 65535));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (i = 0; i < BURST; i++) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		calls++;
		if (s < 0)
			continue;

		(void)fcntl(s, F_SETFL, O_NONBLOCK);

		if (attach_type == BPF_CGROUP_INET4_CONNECT) {
			calls++;
			if (connect(s, (struct sockaddr *)&sin,
				    sizeof(sin)) >= 0)
				sent++;
		}

		calls++;
		if (sendto(s, "x", 1, MSG_DONTWAIT,
			   (struct sockaddr *)&sin, sizeof(sin)) >= 0)
			sent++;

		/* Drain any reply (drives INGRESS / UDP4_RECVMSG when armed). */
		{
			char buf[8];

			(void)recv(s, buf, sizeof(buf), MSG_DONTWAIT);
			calls++;
		}

		close(s);
		calls++;
	}
	*calls_out = calls;
	return sent;
}

bool bpf_cgroup_attach(struct childdata *child)
{
	const struct attach_combo *c;
	union bpf_attr attr;
	char path[64];
	int cgroup_fd = -1;
	int prog_fd = -1;
	bool attached = false;
	uint32_t attach_flags;
	unsigned int sent = 0;
	unsigned int burst_calls = 0;
	unsigned long direct_calls = 0;

	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.runs, 1,
			   __ATOMIC_RELAXED);

	if (latched_off)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	{
		int _slot = child_cgroup_slot();
		unsigned int slot;

		if (_slot < 0) {
			/*
			 * cgroup pool not pre-created; pick randomly.
			 * Hook won't fire (no membership), but we still
			 * exercise attach/detach machinery.
			 */
			slot = rnd_modulo_u32(8);
		} else if (rnd_modulo_u32(8) == 0) {
			/*
			 * Deliberate 1-in-8 mismatch: attach to a cgroup
			 * this child is NOT in.  Negative control — the
			 * hook should not fire; exercises the zero-traffic
			 * dispatch path without dominating the run.
			 */
			slot = ((unsigned int)_slot + 1 + rnd_modulo_u32(7)) % 8;
		} else {
			/* Common case: attach to our own cgroup. */
			slot = (unsigned int)_slot;
		}
		snprintf(path, sizeof(path), "/sys/fs/cgroup/trinity%u", slot);
	}
	cgroup_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		latched_off = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	c = &combos[rnd_modulo_u32(ARRAY_SIZE(combos))];

	/*
	 * For SOCKOPT combos the EFAULT probe confirms hook reach.  However,
	 * BPF_CGROUP_SETSOCKOPT runs *before* the kernel option handler, so
	 * attaching the probe on every burst means every setsockopt call
	 * returns EFAULT and the real handler never executes.  Limit the
	 * probe to ~1-in-8 bursts for SETSOCKOPT so real setsockopt traffic
	 * flows the rest of the time.  BPF_CGROUP_GETSOCKOPT runs after the
	 * kernel handler and never blocks real traffic, so its probe fires
	 * unconditionally.  setsockopt_hook_reach / getsockopt_hook_reach are
 * naturally keyed to
	 * probe-was-attached: the pass-through cannot produce EFAULT.
	 */
	bool use_efault_probe = is_sockopt_combo(c) &&
		(c->attach_type != BPF_CGROUP_SETSOCKOPT ||
		 rnd_modulo_u32(8) == 0);

	prog_fd = use_efault_probe ? load_efault_probe_prog(c)
				   : load_allow_prog(c);
	direct_calls++;
	if (prog_fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			latched_off = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.prog_loaded, 1,
			   __ATOMIC_RELAXED);

	attach_flags = RAND_BOOL() ? BPF_F_ALLOW_MULTI : 0;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd = cgroup_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = c->attach_type;
	attr.attach_flags = attach_flags;
	direct_calls++;
	if (sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
		if (errno == EPERM || errno == EACCES) {
			latched_off = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.attach_rejected,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	attached = true;
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.attached, 1,
			   __ATOMIC_RELAXED);
	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Drive the hook for one or more burst rounds while the program
	 * remains attached.  On ~1-in-4 invocations stay attached for a
	 * bounded slice of extra rounds (4–16) so that sibling children's
	 * concurrent setsockopt corpus traffic passes through the hook for
	 * a meaningful fraction of the run rather than a single-burst
	 * point-in-time window.  The burst logic is otherwise unchanged.
	 */
	{
		unsigned int hold_rounds = (rnd_modulo_u32(4) == 0)
			? (unsigned int)(RAND_RANGE(4, 16)) : 1u;
		unsigned int r;

		for (r = 0; r < hold_rounds; r++) {
			if (is_sockopt_combo(c)) {
				unsigned long set_reach = 0, get_reach = 0;

				if (c->attach_type == BPF_CGROUP_SETSOCKOPT && use_efault_probe)
					__atomic_add_fetch(
						&shm->stats.bpf_cgroup_attach.setsockopt_probe_bursts,
						1, __ATOMIC_RELAXED);
				if (c->attach_type == BPF_CGROUP_GETSOCKOPT)
					__atomic_add_fetch(
						&shm->stats.bpf_cgroup_attach.getsockopt_probe_bursts,
						1, __ATOMIC_RELAXED);
				setsockopt_burst(c->attach_type, use_efault_probe, &burst_calls, &set_reach, &get_reach);
				__atomic_add_fetch(
					&shm->stats.bpf_cgroup_attach.setsockopt_hook_reach,
					set_reach, __ATOMIC_RELAXED);
				__atomic_add_fetch(
					&shm->stats.bpf_cgroup_attach.getsockopt_hook_reach,
					get_reach, __ATOMIC_RELAXED);
			} else {
				sent = udp_burst(c->attach_type, &burst_calls);
				__atomic_add_fetch(
					&shm->stats.bpf_cgroup_attach.packets_sent,
					sent, __ATOMIC_RELAXED);
			}
			direct_calls += burst_calls;
		}
	}

	/* Detach mid-stream — the bug window is "hook fires while
	 * detach is mutating cgrp->bpf.effective[]". */
	memset(&attr, 0, sizeof(attr));
	attr.target_fd = cgroup_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = c->attach_type;
	direct_calls++;
	if (sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == 0) {
		attached = false;
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.detached,
				   1, __ATOMIC_RELAXED);
	}

	/* Post-detach burst — exercises the immediately-after-detach
	 * dispatch path; stale-array UAFs surface here.  With the probe
	 * gone, EFAULTs should drop to zero.  Any non-zero
	 * setsockopt_post_detach_reach / getsockopt_post_detach_reach counts
	 * signal that the cgroup BPF dispatch array was not torn down correctly
	 * after PROG_DETACH. */
	if (is_sockopt_combo(c)) {
		unsigned long set_reach = 0, get_reach = 0;

		setsockopt_burst(c->attach_type, false, &burst_calls, &set_reach, &get_reach);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.setsockopt_post_detach_reach,
				   set_reach, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.getsockopt_post_detach_reach,
				   get_reach, __ATOMIC_RELAXED);
	} else {
		sent = udp_burst(c->attach_type, &burst_calls);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.post_detach_sent,
				   sent, __ATOMIC_RELAXED);
	}
	direct_calls += burst_calls;

out:
	if (attached) {
		memset(&attr, 0, sizeof(attr));
		attr.target_fd = cgroup_fd;
		attr.attach_bpf_fd = prog_fd;
		attr.attach_type = c->attach_type;
		(void)sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
	}
	if (prog_fd >= 0)
		close(prog_fd);
	if (cgroup_fd >= 0)
		close(cgroup_fd);

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
