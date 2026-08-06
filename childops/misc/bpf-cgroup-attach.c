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
#define BPF_CGROUP_INET4_CONNECT	8
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
 * both attach types.  The pass-through program (r0 = 1; exit) lets every
 * call complete normally; optlen rewriting and level/optname decoupling
 * are follow-on variants.
 *
 * Returns the number of setsockopt/getsockopt calls that reached the
 * kernel (hook_calls_out) and the total syscall count through *calls_out.
 */
static void setsockopt_burst(unsigned int *calls_out,
			     unsigned long *hook_calls_out)
{
	static const struct {
		int		level;
		int		optname;
		unsigned int	optlen;
	} opts[] = {
		{ SOL_SOCKET, SO_REUSEADDR,  4  },	/* 4 B — tight kmalloc */
		{ SOL_SOCKET, SO_KEEPALIVE,  4  },
		{ SOL_SOCKET, SO_RCVBUF,     4  },
		{ SOL_SOCKET, SO_SNDBUF,     4  },
		{ SOL_SOCKET, SO_PRIORITY,   4  },
		{ SOL_SOCKET, SO_RCVBUF,     16 },	/* 16 B — still < 32 */
		{ SOL_SOCKET, SO_SNDBUF,     16 },
		{ SOL_SOCKET, SO_KEEPALIVE,  32 },	/* 32 B — at the threshold */
	};
	uint8_t buf[32];
	unsigned long hook_calls = 0;
	unsigned int calls = 0;
	unsigned int i;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	calls++;
	if (s < 0)
		goto out;

	for (i = 0; i < ARRAY_SIZE(opts); i++) {
		socklen_t len = (socklen_t)opts[i].optlen;

		memset(buf, 0, sizeof(buf));
		buf[0] = 1;	/* non-zero value for boolean options */

		/* setsockopt — drives hook at kernel entry before validation */
		(void)setsockopt(s, opts[i].level, opts[i].optname,
				 buf, opts[i].optlen);
		calls++;
		hook_calls++;

		/* getsockopt — separate hook invocation, same kmalloc path */
		len = (socklen_t)opts[i].optlen;
		(void)getsockopt(s, opts[i].level, opts[i].optname,
				 buf, &len);
		calls++;
		hook_calls++;
	}

	close(s);
	calls++;
out:
	*calls_out = calls;
	*hook_calls_out = hook_calls;
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

	snprintf(path, sizeof(path), "/sys/fs/cgroup/trinity%u",
		 rnd_modulo_u32(8));
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

	prog_fd = load_allow_prog(c);
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

	/* Drive the hook in-burst.  Sibling children fuzzing in the same
	 * cgroup at the same time supply the cross-process concurrency
	 * the dispatch-vs-detach race window needs. */
	if (is_sockopt_combo(c)) {
		unsigned long hook_calls = 0;

		setsockopt_burst(&burst_calls, &hook_calls);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.sockopt_hook_calls,
				   hook_calls, __ATOMIC_RELAXED);
	} else {
		sent = udp_burst(c->attach_type, &burst_calls);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.packets_sent,
				   sent, __ATOMIC_RELAXED);
	}
	direct_calls += burst_calls;

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
	 * dispatch path; this is where stale-array UAFs surface. */
	if (is_sockopt_combo(c)) {
		unsigned long hook_calls = 0;

		setsockopt_burst(&burst_calls, &hook_calls);
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach.sockopt_hook_calls,
				   hook_calls, __ATOMIC_RELAXED);
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
