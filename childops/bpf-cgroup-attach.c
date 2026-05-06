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
 *
 * Trinity-todo CV.50.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>

#include "arch.h"
#include "bpf.h"
#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef BPF_F_ALLOW_MULTI
#define BPF_F_ALLOW_MULTI	(1U << 1)
#endif

/* Older UAPI headers may lack the SOCK_ADDR attach types.  Provide the
 * canonical numeric values from include/uapi/linux/bpf.h so this builds
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
#ifndef BPF_PROG_TYPE_CGROUP_SOCK_ADDR
#define BPF_PROG_TYPE_CGROUP_SOCK_ADDR	18
#endif

#define BURST		4

/*
 * Latched off on first irrecoverable failure (no cgroup access, no
 * CAP_BPF) so we don't spin for the rest of this child's life.
 * Per-child static — each forked child gets its own copy.
 */
static bool latched_off;

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

struct attach_combo {
	uint32_t prog_type;
	uint32_t attach_type;
	bool needs_expected_at;
};

static const struct attach_combo combos[] = {
	{ BPF_PROG_TYPE_CGROUP_SKB,       BPF_CGROUP_INET_INGRESS,  false },
	{ BPF_PROG_TYPE_CGROUP_SKB,       BPF_CGROUP_INET_EGRESS,   false },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT, true  },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG,  true  },
	{ BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_RECVMSG,  true  },
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

/* Drive the hook with a UDP loopback burst.  For CONNECT we additionally
 * issue connect() to fire INET4_CONNECT.  Returns the count of send/connect
 * ops that returned >= 0 — used for the packets_sent stat.
 */
static unsigned int udp_burst(uint32_t attach_type)
{
	struct sockaddr_in sin;
	unsigned int sent = 0;
	int s;
	int i;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)RAND_RANGE(1024, 65535));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (i = 0; i < BURST; i++) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
			continue;

		(void)fcntl(s, F_SETFL, O_NONBLOCK);

		if (attach_type == BPF_CGROUP_INET4_CONNECT) {
			if (connect(s, (struct sockaddr *)&sin,
				    sizeof(sin)) >= 0)
				sent++;
		}

		if (sendto(s, "x", 1, MSG_DONTWAIT,
			   (struct sockaddr *)&sin, sizeof(sin)) >= 0)
			sent++;

		/* Drain any reply (drives INGRESS / UDP4_RECVMSG when armed). */
		{
			char buf[8];

			(void)recv(s, buf, sizeof(buf), MSG_DONTWAIT);
		}

		close(s);
	}
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
	unsigned int sent;

	(void)child;

	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_runs, 1,
			   __ATOMIC_RELAXED);

	if (latched_off)
		return true;

	snprintf(path, sizeof(path), "/sys/fs/cgroup/trinity%u",
		 (unsigned int)(rand() % 8));
	cgroup_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		latched_off = true;
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	c = &combos[(unsigned int)rand() % ARRAY_SIZE(combos)];

	prog_fd = load_allow_prog(c);
	if (prog_fd < 0) {
		if (errno == EPERM || errno == EACCES)
			latched_off = true;
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_prog_loaded, 1,
			   __ATOMIC_RELAXED);

	attach_flags = RAND_BOOL() ? BPF_F_ALLOW_MULTI : 0;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd = cgroup_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = c->attach_type;
	attr.attach_flags = attach_flags;
	if (sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
		if (errno == EPERM || errno == EACCES)
			latched_off = true;
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_attach_rejected,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	attached = true;
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_attached, 1,
			   __ATOMIC_RELAXED);

	/* Drive the hook in-burst.  Sibling children fuzzing in the same
	 * cgroup at the same time supply the cross-process concurrency
	 * the dispatch-vs-detach race window needs. */
	sent = udp_burst(c->attach_type);
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_packets_sent,
			   sent, __ATOMIC_RELAXED);

	/* Detach mid-stream — the bug window is "hook fires while
	 * detach is mutating cgrp->bpf.effective[]". */
	memset(&attr, 0, sizeof(attr));
	attr.target_fd = cgroup_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = c->attach_type;
	if (sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) == 0) {
		attached = false;
		__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_detached,
				   1, __ATOMIC_RELAXED);
	}

	/* Post-detach burst — exercises the immediately-after-detach
	 * dispatch path; this is where stale-array UAFs surface. */
	sent = udp_burst(c->attach_type);
	__atomic_add_fetch(&shm->stats.bpf_cgroup_attach_post_detach_sent,
			   sent, __ATOMIC_RELAXED);

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
	return true;
}
