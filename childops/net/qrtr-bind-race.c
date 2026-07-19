/*
 * qrtr_bind_race - race two children binding the SAME AF_QRTR port,
 * then race close() of those sockets to exercise the
 * qrtr_port_remove() drop-ref-before-unpublish window in
 * net/qrtr/af_qrtr.c.
 *
 * Background.  When a qrtr socket is torn down, qrtr_port_remove()
 * drops the per-port refcount BEFORE removing the (node, port) entry
 * from the routing table's published lookup structure.  A concurrent
 * task that resolves the same (node, port) — most reachably another
 * bind() that hashes onto the same slot, or any in-flight lookup
 * driven by sendmsg routing — can grab a reference on the dying
 * struct after its last user has dropped it, producing a refcount /
 * RCU use-after-free on the qrtr_sock.  Random per-syscall sendmsg
 * fuzzing against QRTR_PORT_CTRL (net/proto/qrtr.c) never assembles the
 * concurrent same-port bind/close shape; this op drives it directly.
 *
 * Shape per outer iteration (BUDGETED, bounded wall-clock):
 *   1.  Pick a target sq_port.  Mix of QRTR_PORT_CTRL (0xfffffffe),
 *       small "service" ports in [0x1, 0x80), and any 32-bit value —
 *       the kernel hash slot is what matters, not the numeric value.
 *   2.  fork() two short-lived children, hand both the same port.
 *   3.  Each child opens AF_QRTR SOCK_DGRAM, bind()s sockaddr_qrtr
 *       { sq_family=AF_QRTR, sq_node=local, sq_port=target }, then
 *       _exit(0) — close() of the implicit fd runs through
 *       qrtr_release -> qrtr_port_remove on the way out, racing the
 *       sibling's bind/release.
 *   4.  Parent reaps both via waitpid_eintr(); a sibling killed by
 *       signal bumps a forensic counter (the bug surface is exactly
 *       this kind of one-sided crash).
 *
 * Self-gating.  First invocation per process probes
 * socket(AF_QRTR, SOCK_DGRAM, 0); EAFNOSUPPORT / EPROTONOSUPPORT /
 * EACCES latches ns_unsupported_qrtr_bind_race for the rest of the
 * child's life so the op is a silent no-op on hosts without the qrtr
 * module loaded.  Same shape as net-pernet teardown / af-unix
 * SCM_RIGHTS GC / afxdp_churn latches.
 *
 * Header compat.  AF_QRTR landed in mainline as 42 (commit
 * bdabad3e363d, 2015).  If the build host's uapi predates the macro,
 * fall back to the literal 42 — kernel rejects on unsupported hosts
 * and the latch takes over.  struct sockaddr_qrtr likewise has a
 * fallback shim.
 *
 * Brick-safety.  No host-visible mutation: every fd is per-child,
 * closed on _exit(); no rtnetlink, no module load, no globally-
 * reachable resource.  Bounded outer loop with a hard 200 ms wall-
 * clock cap.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/qrtr.h>)

#include <linux/qrtr.h>

#include "kernel/qrtr.h"
/* AF_QRTR landed in mainline as 42 (commit bdabad3e363d, 2015) but
 * the macro lives in glibc-side <bits/socket.h>, not <linux/qrtr.h>,
 * so sysroots without the bits update need the literal fallback even
 * when <linux/qrtr.h> is present. */
#ifndef AF_QRTR
#define AF_QRTR			42
#endif

#define QRTR_BIND_OUTER_BASE		3U
#define QRTR_BIND_OUTER_CAP		16U
#define QRTR_BIND_WALL_CAP_NS		(200ULL * 1000ULL * 1000ULL)

/* Per-process latch: AF_QRTR is unsupported on this host (module not
 * loaded, kernel not built with CONFIG_QRTR, or denied by LSM).  Once
 * latched, every subsequent invocation short-circuits with
 * setup_failed.  Mirrors the netns_teardown / af_unix_peek_race
 * latches. */
static bool ns_unsupported_qrtr_bind_race;
static bool qrtr_probed;

/*
 * Probe AF_QRTR availability once per process.  Open succeeds on hosts
 * with the qrtr module loaded; everything else (EAFNOSUPPORT /
 * EPROTONOSUPPORT / EACCES) latches the op off.
 */
static void probe_qrtr(struct childdata *child)
{
	int fd;

	qrtr_probed = true;
	fd = socket(AF_QRTR, SOCK_DGRAM, 0);
	if (fd < 0) {
		/* Any failure on the bare socket() probe means we can't
		 * drive the race meaningfully; latch off uniformly. */
		ns_unsupported_qrtr_bind_race = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * arrays, same pattern the child.c dispatch loop uses for
		 * the unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}
	close(fd);
}

/*
 * Pick a target sq_port for this round.  Mix the in-band CTRL port,
 * small service-style ports (where in-tree consumers live), and any
 * 32-bit value.  The hash slot driven by these is what opens the
 * race; the numeric range is incidental.
 *
 * The "any 32-bit value" arm is floored at 0x4000: a fully random u32
 * very often lands on the CTRL port (0xfffffffe) or inside the low
 * service range [0x1, 0x80), both of which fail to bind (EPERM /
 * already in use), so the racing siblings rarely contend on the same
 * live port.  Restricting the random arm to the ephemeral range lets
 * the common case bind succeed while the deliberate CTRL / service
 * special-value coverage above is unchanged.
 */
static uint32_t pick_port(void)
{
	uint32_t r = rnd_u32() & 0x7U;

	if (r == 0)
		return QRTR_PORT_CTRL;
	if (r < 4)
		return 1U + rnd_modulo_u32(0x80U);
	return 0x4000U + rnd_modulo_u32(0xfffffffeU - 0x4000U);
}

/*
 * In-child worker: open AF_QRTR SOCK_DGRAM, bind sockaddr_qrtr to the
 * caller-supplied port, then _exit so the implicit close() drives
 * qrtr_release -> qrtr_port_remove.  No return path — runs in the
 * forked child only.
 */
static __attribute__((noreturn)) void qrtr_bind_child(uint32_t port)
{
	struct sockaddr_qrtr sq, local;
	socklen_t slen = sizeof(local);
	int fd;

	fd = socket(AF_QRTR, SOCK_DGRAM, 0);
	if (fd < 0) {
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.setup_fail,
				   1, __ATOMIC_RELAXED);
		_exit(0);
	}

	/* qrtr_bind() rejects with -EINVAL if sq_node doesn't match the
	 * socket's own node (the kernel checks BEFORE the bind body, so
	 * the socket stays SOCK_ZAPPED and we never reach the teardown
	 * path this op targets).  The local node id is configurable via
	 * the qrtr_local_nid module param (default 1, not 0), so query it
	 * via getsockname() rather than hardcoding. */
	memset(&local, 0, sizeof(local));
	if (getsockname(fd, (struct sockaddr *)&local, &slen) < 0) {
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.setup_fail,
				   1, __ATOMIC_RELAXED);
		_exit(0);
	}

	memset(&sq, 0, sizeof(sq));
	sq.sq_family = AF_QRTR;
	sq.sq_node = local.sq_node;
	sq.sq_port = port;
	(void)bind(fd, (struct sockaddr *)&sq, sizeof(sq));

	/* No explicit close(): _exit closes every fd via the kernel's
	 * do_exit -> exit_files path, which is the teardown that runs
	 * qrtr_release.  Letting two children reach this at once is the
	 * whole point of the op. */
	_exit(0);
}

/*
 * Reap a forked bind-child.  WIFSIGNALED bumps the forensic counter
 * — the bug surface is exactly the one-sided crash where one task's
 * teardown frees the qrtr_sock another task is mid-walk through.
 */
static void reap_bind_child(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;
	if (waitpid_eintr(pid, &status, 0) != pid)
		return;
	if (WIFSIGNALED(status))
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.sibling_crashed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * One outer iteration: pick a port, fork two short-lived bind
 * children, reap both.  Coverage bumps live on each successful step.
 */
static void iter_one(void)
{
	uint32_t port;
	pid_t p1, p2;

	port = pick_port();

	__atomic_add_fetch(&shm->stats.qrtr_bind_race.iter,
			   1, __ATOMIC_RELAXED);

	p1 = fork();
	if (p1 < 0) {
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.fork_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (p1 == 0)
		qrtr_bind_child(port);

	p2 = fork();
	if (p2 < 0) {
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.fork_failed,
				   1, __ATOMIC_RELAXED);
		/* p1 already in flight; reap it so we don't leave a
		 * zombie behind when the outer loop continues. */
		reap_bind_child(p1);
		return;
	}
	if (p2 == 0)
		qrtr_bind_child(port);

	__atomic_add_fetch(&shm->stats.qrtr_bind_race.spawn_pair_ok,
			   1, __ATOMIC_RELAXED);

	reap_bind_child(p1);
	reap_bind_child(p2);
}

bool qrtr_bind_race(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.qrtr_bind_race.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_qrtr_bind_race) {
		__atomic_add_fetch(&shm->stats.qrtr_bind_race.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!qrtr_probed) {
		probe_qrtr(child);
		if (ns_unsupported_qrtr_bind_race) {
			__atomic_add_fetch(&shm->stats.qrtr_bind_race.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_QRTR_BIND_RACE, QRTR_BIND_OUTER_BASE);
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > QRTR_BIND_OUTER_CAP)
		outer_iters = QRTR_BIND_OUTER_CAP;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < outer_iters; i++) {
		if (budget_elapsed_ns(&t_outer, (long)QRTR_BIND_WALL_CAP_NS))
			break;
		iter_one();
		if (ns_unsupported_qrtr_bind_race)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/qrtr.h>) */

bool qrtr_bind_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.qrtr_bind_race.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.qrtr_bind_race.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
