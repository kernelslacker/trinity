/*
 * ipvs_sysctl_writer - per-netns IP_VS sysctl write driver.
 *
 * Targets the conn_tab_bits resize path: a write to
 * /proc/sys/net/ipv4/vs/conn_tab_bits feeds ip_vs_rht_desired_size,
 * which calls roundup_pow_of_two() on the parsed value.  Boundary values
 * (0, negatives, INT_MAX) hit the corner the upstream UBSAN trip
 * (4ee52b7021a7) addressed.  The generic procfs walker doesn't reach
 * the per-netns /proc/sys/net/ipv4/vs tree reliably: the sysctl table is
 * registered lazily on first access from inside ip_vs_init_net(), and
 * the walker's bounded depth + access(W_OK) gate often skips it.  This
 * op forces the per-netns init then writes a curated path list.
 *
 * Runs the per-invocation body inside a transient grandchild forked by
 * userns_run_in_ns(CLONE_NEWNET); the grandchild's userns + netns die
 * on _exit() so the per-net ip_vs sysctl table, conn table, virtual
 * service and writable fds are reaped along with the namespace.  The
 * persistent fuzz child keeps the host credential profile that the
 * cap-drop oracle observes.  Helper -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0) latches ns_unsupported_ipvs_sysctl
 * via a one-shot warn_once; -EAGAIN (transient grandchild setup
 * failure) skips the iteration without latching.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
#define IPVS_CANONICAL_PATH	"/proc/sys/net/ipv4/vs/conn_tab_bits"
#define IPVS_WRITE_BASE		4U
#define IPVS_WRITE_CAP		16U

/* Conn-table burn-in: a virtual TCP service is set up once via ipvsadm
 * inside the netns, then short-lived non-blocking TCP sockets to the VIP
 * drive sustained insert/expire pressure on the per-net ip_vs_conn table.
 * That is the shape that exposed an upstream sleeping-while-atomic in
 * ip_vs_conn_expire on PREEMPT_RT; the same path is harmless but cheap
 * coverage on non-RT.  Iteration cap + parent-armed SIGALRM bound the
 * worst case; ONE_IN gate keeps overall cost low. */
#define IPVS_BURN_VIP		"127.0.0.7:80"
#define IPVS_BURN_RIP		"127.0.0.2:80"
#define IPVS_BURN_FREQ		8U
#define IPVS_BURN_BASE		6U
#define IPVS_BURN_CAP		32U

/* sync_threshold takes a "thresh maxlen" pair, not a single int — flag the
 * row so the writer routes it through the two-value payload below. */
static const struct {
	const char *path;
	bool sync_threshold;
} ipvs_sysctls[] = {
	{ "/proc/sys/net/ipv4/vs/conn_tab_bits",		false },
	{ "/proc/sys/net/ipv4/vs/am_droprate",			false },
	{ "/proc/sys/net/ipv4/vs/expire_nodest_conn",		false },
	{ "/proc/sys/net/ipv4/vs/expire_quiescent_template",	false },
	{ "/proc/sys/net/ipv4/vs/sync_threshold",		true  },
	{ "/proc/sys/net/ipv4/vs/sync_qlen_max",		false },
	{ "/proc/sys/net/ipv4/vs/drop_packet",			false },
	{ "/proc/sys/net/ipv4/vs/sloppy_tcp",			false },
	{ "/proc/sys/net/ipv4/vs/sloppy_sctp",			false },
};
#define NR_IPVS_SYSCTLS		ARRAY_SIZE(ipvs_sysctls)

/* Master gate: persistent across iterations in the persistent fuzz
 * child.  Set when userns_run_in_ns() returns -EPERM (hardened userns
 * policy refused CLONE_NEWUSER) so subsequent invocations short-circuit
 * instead of forking another doomed grandchild. */
static bool ns_unsupported_ipvs_sysctl;

/* One-shot modprobe gate: kernel modules are global, not per-netns, so
 * the load only has to happen once per persistent child and must run
 * with the host's CAP_SYS_MODULE — i.e. before userns_run_in_ns() drops
 * the grandchild into its scoped user namespace where CAP_SYS_MODULE is
 * ineffective against init_user_ns. */
static bool modprobe_tried_ip_vs;

static void warn_once_unsupported_ipvs_sysctl(int err)
{
	static bool warned;

	if (warned)
		return;
	warned = true;
	outputerr("ipvs_sysctl_writer: userns_run_in_ns(CLONE_NEWNET) failed (errno=%d), latching ns_unsupported_ipvs_sysctl\n",
		  err);
}

static void maybe_modprobe_ip_vs(void)
{
	if (modprobe_tried_ip_vs)
		return;
	modprobe_tried_ip_vs = true;
	try_modprobe("ip_vs");
	try_modprobe("ip_vs_rr");
}

/*
 * Per-grandchild iteration state.  Lives on the grandchild's stack and
 * dies when the grandchild _exit()s after the in-ns callback returns;
 * no cross-iteration caching is possible because the netns (and the
 * per-net ip_vs sysctl table, virtual service and writable fds inside
 * it) is recreated on every call.
 */
struct ipvs_sysctl_iter_ctx {
	struct childdata *child;
	int sysctl_fds[NR_IPVS_SYSCTLS];
	bool burn_setup_done;
};

static void try_ipvsadm(const char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execvp("ipvsadm", (char *const *)argv);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

static void ipvs_conn_burn(struct ipvs_sysctl_iter_ctx *ctx)
{
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(80),
	};
	unsigned int i, iters;

	if (!ctx->burn_setup_done) {
		const char *svc[] = { "ipvsadm", "-A", "-t", IPVS_BURN_VIP,
				      "-s", "rr", NULL };
		const char *rs[]  = { "ipvsadm", "-a", "-t", IPVS_BURN_VIP,
				      "-r", IPVS_BURN_RIP, "-m", NULL };
		struct ifreq ifr = { .ifr_name = "lo", .ifr_flags = IFF_UP };
		int s = socket(AF_INET, SOCK_DGRAM, 0);

		if (s >= 0) {
			(void)ioctl(s, SIOCSIFFLAGS, &ifr);
			close(s);
		}
		try_ipvsadm(svc);
		try_ipvsadm(rs);
		ctx->burn_setup_done = true;
	}

	(void)inet_pton(AF_INET, "127.0.0.7", &dst.sin_addr);
	iters = BUDGETED(CHILD_OP_IPVS_SYSCTL_WRITER, JITTER_RANGE(IPVS_BURN_BASE));
	if (iters > IPVS_BURN_CAP)
		iters = IPVS_BURN_CAP;

	for (i = 0; i < iters; i++) {
		int fd = socket(AF_INET,
				SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0)
			continue;
		(void)connect(fd, (struct sockaddr *)&dst, sizeof(dst));
		close(fd);
		__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_burn_iters,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Per-invocation body that runs inside the grandchild's private
 * netns.  userns_run_in_ns() has already entered the netns; this
 * callback triggers per-net ip_vs sysctl registration via a canonical-
 * path probe open, opens writable fds for every row in ipvs_sysctls[],
 * drives the curated write storm, and optionally fires the conn-table
 * burn.  Any partially-built state on a setup-failure path is reaped
 * by the grandchild's _exit().  Return value is ignored by the helper
 * -- per-op stats counters carry the outcome.
 */
static int ipvs_sysctl_writer_in_ns(void *arg)
{
	struct ipvs_sysctl_iter_ctx *ctx = (struct ipvs_sysctl_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	unsigned int iters, i;
	int probe;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats write
	 * entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	for (i = 0; i < NR_IPVS_SYSCTLS; i++)
		ctx->sysctl_fds[i] = -1;

	/* First open of the canonical path triggers ip_vs_init_net()
	 * which registers the per-net sysctl table. */
	probe = open(IPVS_CANONICAL_PATH, O_RDONLY);
	if (probe < 0) {
		__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return 0;
	}
	close(probe);

	for (i = 0; i < NR_IPVS_SYSCTLS; i++)
		ctx->sysctl_fds[i] = open(ipvs_sysctls[i].path,
					  O_WRONLY | O_NONBLOCK | O_CLOEXEC);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	iters = BUDGETED(CHILD_OP_IPVS_SYSCTL_WRITER, JITTER_RANGE(IPVS_WRITE_BASE));
	if (iters > IPVS_WRITE_CAP)
		iters = IPVS_WRITE_CAP;

	for (i = 0; i < iters; i++) {
		unsigned int idx = rnd_modulo_u32(NR_IPVS_SYSCTLS);
		int fd = ctx->sysctl_fds[idx];
		char buf[128];
		unsigned int len;
		ssize_t n;

		if (fd < 0) {
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		if (ipvs_sysctls[idx].sync_threshold) {
			len = (unsigned int)snprintf(buf, sizeof(buf), "%d %d",
						     (int)rand32(), (int)rand32());
		} else {
			len = gen_text_payload(buf, sizeof(buf));
		}

		/* Rewind to offset 0 so each write re-enters the sysctl handler
		 * — most proc_handler write paths short-circuit when *ppos > 0. */
		(void)lseek(fd, 0, SEEK_SET);
		n = write(fd, buf, len);

		if (n > 0)
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_ok,
					   1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_writes_failed,
					   1, __ATOMIC_RELAXED);
	}

	if (ONE_IN(IPVS_BURN_FREQ))
		ipvs_conn_burn(ctx);

	for (i = 0; i < NR_IPVS_SYSCTLS; i++) {
		if (ctx->sysctl_fds[i] >= 0)
			close(ctx->sysctl_fds[i]);
	}
	return 0;
}

bool ipvs_sysctl_writer(struct childdata *child)
{
	struct ipvs_sysctl_iter_ctx ctx = {
		.child = child,
		.burn_setup_done = false,
	};
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_ipvs_sysctl)
		return true;

	maybe_modprobe_ip_vs();

	rc = userns_run_in_ns(CLONE_NEWNET, ipvs_sysctl_writer_in_ns, &ctx);
	if (rc == -EPERM) {
		ns_unsupported_ipvs_sysctl = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_ipvs_sysctl(EPERM);
		__atomic_add_fetch(&shm->stats.ipvs_sysctl_writer_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		return true;
	}

	return true;
}
