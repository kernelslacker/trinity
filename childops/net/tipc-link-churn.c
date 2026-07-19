/*
 * tipc_link_churn - TIPC bearer enable/disable race over a live topology
 * subscription.
 *
 * TIPC link bring-up has historically been a productive bug surface: the
 * 2022 disclosure of CVE-2022-0435 (tipc_link_proto_rcv stack overflow
 * via crafted ACTIVATE_MSG payloads), CVE-2022-0382 (tipc_msg_validate
 * uninitialised-memory leak on short messages), and the tipc_nametbl
 * double-free family all live in code paths that are only reached when
 * a real bearer is enabled, a real link sits in the receive path, and a
 * topology subscriber is actively walking the publication table.  Flat
 * fuzzing of AF_TIPC sockets misses every one of these because none of
 * them assemble the multi-step bring-up dance: a UDP-tunnel bearer
 * enabled via genetlink, a cluster network identity set via
 * TIPC_NL_NET_SET, an RDM socket bound under TIPC_CLUSTER_SCOPE, and a
 * SEQPACKET subscriber to the topology server (TIPC_TOP_SRV) issuing a
 * TIPC_SUB_PORTS subscription before the bearer gets torn back down.
 * This childop assembles that sequence end-to-end on loopback, then
 * disables the bearer mid-subscription so the link teardown races the
 * topology walker — the targeted bug class is exactly that walk-while-
 * teardown window in net/tipc/link.c and net/tipc/topsrv.c.
 *
 * Sequence (per invocation):
 *   1.  modprobe tipc; failure (ENOENT, EPERM, no init_module privilege,
 *       module already loaded → ok) is silently ignored.  EAFNOSUPPORT
 *       on the subsequent AF_TIPC socket latches ns_unsupported_tipc for
 *       the rest of the child's lifetime.
 *   2.  genl_open("TIPCv2", ...) — resolves the family id via a per-ctx
 *       CTRL_CMD_GETFAMILY; -ENOENT latches ns_unsupported_genetlink_tipc
 *       for the rest of the process.  Kernels without CONFIG_TIPC don't
 *       expose the TIPCv2 family.
 *   3.  TIPC_NL_BEARER_ENABLE on udp:127.0.0.1:6118 (loopback only,
 *       random source port stays implicit on the TIPC side; the
 *       remote/local sockaddr_storage payload addresses 127.0.0.1
 *       only — never anything routable).
 *   4.  TIPC_NL_NET_SET cluster id (random small int, well clear of the
 *       reserved 0).  Sets the local node's cluster identity so links
 *       can come up.
 *   5.  socket(AF_TIPC, SOCK_RDM); bind a random TIPC name with
 *       TIPC_CLUSTER_SCOPE so the publication is visible cluster-wide
 *       and the topology server publishes it.
 *   6.  socket(AF_TIPC, SOCK_SEQPACKET); connect to TIPC_TOP_SRV (the
 *       topology server).  Send a TIPC_SUB_PORTS struct tipc_subscr so
 *       the kernel begins walking the publication table on every
 *       publish/withdraw event.
 *   7.  TIPC_NL_BEARER_DISABLE on the same UDP bearer name — the race
 *       window between the active subscriber walking the publication
 *       table and the bearer-disable path tearing down the link state
 *       is the targeted bug.
 *   8.  Close both sockets so the next iteration starts clean.
 *
 * CVE classes reached: CVE-2022-0435 tipc_link_proto_rcv stack overflow;
 * CVE-2022-0382 tipc_msg_validate uninit-mem leak; tipc_nametbl
 * double-free family.  Subsystems exercised: net/tipc/bearer.c (enable/
 * disable + UDP tunnel media), net/tipc/link.c (link state), net/tipc/
 * name_distr.c (publication distribution), net/tipc/topsrv.c (topology
 * server subscription handling), net/tipc/net.c (TIPC_NL_NET_SET).
 *
 * Self-bounding: one full cycle per invocation, every send/recv uses
 * MSG_DONTWAIT, sockets are O_CLOEXEC, the genetlink ack socket has
 * SO_RCVTIMEO so an unresponsive controller can't wedge the child past
 * the alarm(1) cap inherited from child.c.  All UDP-bearer addressing
 * is loopback; the cluster id is bounded; ENOENT/EPERM/EAFNOSUPPORT
 * are treated as benign coverage signals rather than childop failure.
 *
 * Header gating: <linux/tipc.h> + <linux/tipc_netlink.h> may be absent
 * on stripped sysroots that omit the TIPC uapi.  When either is missing
 * the body compiles to a stub that just bumps runs+setup_failed and
 * returns — the rest of the build keeps functioning.  Mirrors the
 * iouring-net-multishot ifndef-fallback shape but uses __has_include
 * because TIPC's uapi doesn't expose a single feature macro we can
 * reliably probe with #ifndef.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/tipc.h>) && __has_include(<linux/tipc_netlink.h>)

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/tipc.h>
#include <linux/tipc_netlink.h>

#include "childops-genl.h"
#include "random.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
#define TIPC_BEARER_NAME_MAX	32

/* Loopback UDP bearer endpoint.  Port 6118 is the IANA-assigned TIPC
 * port; we use it for both local and remote so the bearer thinks it has
 * a real peer at the other end of the loopback tunnel without ever
 * sending bytes off-host.  Never anything but 127.0.0.1 — every other
 * payload byte in this file is randomised, but the address quartet is
 * fixed by design. */
#define TIPC_UDP_PORT		6118

/* Cluster id picked into [1, 4095].  Cluster id 0 is reserved as
 * "unset"; staying well below the legacy 12-bit mask keeps us off
 * the legacy/non-legacy boundary inside net/tipc/net.c. */
#define TIPC_CLUSTER_ID_MIN	1U
#define TIPC_CLUSTER_ID_RANGE	4095U

#define TIPC_GENL_BUF_BYTES	1024
#define TIPC_GENL_RECV_TIMEO_S	1

/* Service-type window for the random publication.  Stay above
 * TIPC_RESERVED_TYPES (64) so we don't collide with TIPC_TOP_SRV /
 * TIPC_LINK_STATE / TIPC_NODE_STATE on the bound socket. */
#define TIPC_USER_TYPE_MIN	(TIPC_RESERVED_TYPES + 1)
#define TIPC_USER_TYPE_RANGE	((1U << 20) - TIPC_RESERVED_TYPES - 1)

/* Latched per-child: AF_TIPC returned EAFNOSUPPORT or modprobe failed
 * once.  The kernel was built without CONFIG_TIPC, the module is
 * blocked, or unprivileged module load is denied — none of these flip
 * during this process's lifetime, so further attempts are pure
 * overhead. */
static bool ns_unsupported_tipc;

/* Latched per-child: genl_open("TIPCv2", ...) returned -ENOENT, so the
 * kernel doesn't expose the TIPCv2 genl family at all.  Either the
 * module isn't loaded (modprobe in step 1 was rejected) or the family
 * was renamed.  Same lifetime semantics as ns_unsupported_tipc. */
static bool ns_unsupported_genetlink_tipc;

/*
 * Best-effort modprobe.  Returns true on success, false on any failure;
 * callers fall through to the AF_TIPC probe regardless because if the
 * module is already loaded the open succeeds without any modprobe call.
 * The fork+execve path is intentional — we don't want to pull libkmod
 * into trinity for one optional probe per child lifetime, and the
 * /sbin/modprobe binary is the documented userspace entry point.
 */
static void try_modprobe_tipc(void)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
		/* Child: silence stdout/stderr so a missing modprobe doesn't
		 * spew into the trinity log on every iteration in distros
		 * without /sbin/modprobe. */
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execl("/sbin/modprobe", "modprobe", "-q", "tipc", (char *)NULL);
		execl("/usr/sbin/modprobe", "modprobe", "-q", "tipc", (char *)NULL);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

/*
 * Build a TIPC_NLA_BEARER nest carrying just BEARER_NAME at the given
 * offset.  Used by both ENABLE (with extra UDP_OPTS) and DISABLE (name
 * only).  Returns the new outer-buf offset, or 0 on overflow.
 */
static size_t put_bearer_name_nest(unsigned char *buf, size_t off, size_t cap,
				   const char *name)
{
	size_t outer_off = off;

	off = nla_nest_start(buf, off, cap, TIPC_NLA_BEARER);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, TIPC_NLA_BEARER_NAME, name);
	if (!off)
		return 0;

	nla_nest_end(buf, outer_off, off);
	return off;
}

/*
 * Build & send TIPC_NL_BEARER_ENABLE for a UDP-tunnel bearer named
 * `name`, both endpoints on 127.0.0.1:TIPC_UDP_PORT.  The TIPC_NLA_UDP
 * sub-nest carries TIPC_NLA_UDP_LOCAL and TIPC_NLA_UDP_REMOTE as
 * sockaddr_storage payloads.  Returns the kernel's ack errno.
 */
static int build_bearer_enable(struct genl_ctx *ctx, const char *name)
{
	unsigned char buf[TIPC_GENL_BUF_BYTES];
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
	struct sockaddr_in *sin;
	struct nlmsghdr *nlh;
	size_t off;
	size_t outer_off, udp_off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   TIPC_NL_BEARER_ENABLE, 0);
	if (!off)
		return -EIO;

	/* Outer TIPC_NLA_BEARER nest. */
	outer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TIPC_NLA_BEARER);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), TIPC_NLA_BEARER_NAME, name);
	if (!off)
		return -EIO;

	/* Inner TIPC_NLA_BEARER_UDP_OPTS nest. */
	udp_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TIPC_NLA_BEARER_UDP_OPTS);
	if (!off)
		return -EIO;

	memset(&local, 0, sizeof(local));
	memset(&remote, 0, sizeof(remote));
	sin = (struct sockaddr_in *)&local;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin->sin_port = htons(TIPC_UDP_PORT);
	sin = (struct sockaddr_in *)&remote;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin->sin_port = htons(TIPC_UDP_PORT);

	off = nla_put(buf, off, sizeof(buf), TIPC_NLA_UDP_LOCAL,
		      &local, sizeof(local));
	if (!off)
		return -EIO;

	off = nla_put(buf, off, sizeof(buf), TIPC_NLA_UDP_REMOTE,
		      &remote, sizeof(remote));
	if (!off)
		return -EIO;

	nla_nest_end(buf, udp_off, off);
	nla_nest_end(buf, outer_off, off);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

static int build_bearer_disable(struct genl_ctx *ctx, const char *name)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   TIPC_NL_BEARER_DISABLE, 0);
	if (!off)
		return -EIO;

	off = put_bearer_name_nest(buf, off, sizeof(buf), name);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send TIPC_NL_NET_SET with TIPC_NLA_NET_ID set to `cluster`.
 * The single u32 attribute lives inside the TIPC_NLA_NET outer nest.
 * Returns the kernel's ack errno; non-zero just means the local node
 * already has a cluster id set, which is fine — the bearer enable
 * step can still succeed against the prior id.
 */
static int build_net_set(struct genl_ctx *ctx, __u32 cluster)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off, outer_off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx, nl_seq_next(&ctx->nl),
			   TIPC_NL_NET_SET, 0);
	if (!off)
		return -EIO;

	outer_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), TIPC_NLA_NET);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), TIPC_NLA_NET_ID, cluster);
	if (!off)
		return -EIO;

	nla_nest_end(buf, outer_off, off);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Bind an AF_TIPC RDM socket to a random publication name with cluster
 * scope.  Returns 0 on accept, negated errno on rejection, -EIO on a
 * local sockaddr setup error.  The publication exists for as long as
 * the caller keeps the socket open; the topology server picks it up
 * automatically once the bearer is up.
 */
static int build_publish(int sock)
{
	struct sockaddr_tipc sa;

	memset(&sa, 0, sizeof(sa));
	sa.family   = AF_TIPC;
	sa.addrtype = TIPC_ADDR_NAMESEQ;
	sa.scope    = TIPC_CLUSTER_SCOPE;
	sa.addr.nameseq.type  = TIPC_USER_TYPE_MIN +
				rnd_modulo_u32(TIPC_USER_TYPE_RANGE);
	sa.addr.nameseq.lower = rand32();
	sa.addr.nameseq.upper = sa.addr.nameseq.lower;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -errno;
	return 0;
}

/*
 * Connect a SEQPACKET socket to TIPC_TOP_SRV (the topology server) and
 * push a TIPC_SUB_PORTS subscription covering every service type.  The
 * kernel begins walking the publication table immediately and emits a
 * tipc_event for each existing publication plus future publish/withdraw
 * events.  Returns true once the subscription send succeeded; false on
 * any earlier failure.
 */
static bool open_topsrv_and_subscribe(int *out_fd)
{
	struct sockaddr_tipc sa;
	struct tipc_subscr sub;
	int fd;
	ssize_t n;

	*out_fd = -1;

	fd = socket(AF_TIPC, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return false;

	memset(&sa, 0, sizeof(sa));
	sa.family   = AF_TIPC;
	sa.addrtype = TIPC_ADDR_NAME;
	sa.scope    = 0;
	sa.addr.name.name.type     = TIPC_TOP_SRV;
	sa.addr.name.name.instance = TIPC_TOP_SRV;
	sa.addr.name.domain        = 0;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return false;
	}
	__atomic_add_fetch(&shm->stats.tipc_link_churn.topsrv_connect_ok,
			   1, __ATOMIC_RELAXED);

	memset(&sub, 0, sizeof(sub));
	sub.seq.type  = 0;
	sub.seq.lower = 0;
	sub.seq.upper = ~0U;
	sub.timeout   = TIPC_WAIT_FOREVER;
	sub.filter    = TIPC_SUB_PORTS;

	n = send(fd, &sub, sizeof(sub), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n != (ssize_t)sizeof(sub)) {
		close(fd);
		return false;
	}
	__atomic_add_fetch(&shm->stats.tipc_link_churn.sub_ports_sent,
			   1, __ATOMIC_RELAXED);

	*out_fd = fd;
	return true;
}

bool tipc_link_churn(struct childdata *child)
{
	char bearer_name[TIPC_BEARER_NAME_MAX];
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	bool ctx_open = false;
	int rdm = -1;
	int topsrv = -1;
	bool bearer_enabled = false;
	__u32 cluster;
	int rc;

	__atomic_add_fetch(&shm->stats.tipc_link_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_tipc || ns_unsupported_genetlink_tipc) {
		__atomic_add_fetch(&shm->stats.tipc_link_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	/* Probe AF_TIPC support before paying for modprobe.  EAFNOSUPPORT
	 * means CONFIG_TIPC=n; ENOENT/EPROTONOSUPPORT means the family
	 * isn't registered.  Either way, latch off. */
	rdm = socket(AF_TIPC, SOCK_RDM | SOCK_CLOEXEC, 0);
	if (rdm < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			/* Try modprobe once, then re-probe. */
			try_modprobe_tipc();
			rdm = socket(AF_TIPC, SOCK_RDM | SOCK_CLOEXEC, 0);
			if (rdm < 0) {
				ns_unsupported_tipc = true;
				if (valid_op)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
				__atomic_add_fetch(&shm->stats.tipc_link_churn.setup_failed,
						   1, __ATOMIC_RELAXED);
				return true;
			}
		} else {
			__atomic_add_fetch(&shm->stats.tipc_link_churn.setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}
	__atomic_add_fetch(&shm->stats.tipc_link_churn.sock_rdm_ok,
			   1, __ATOMIC_RELAXED);

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = TIPC_GENL_V2_NAME;
	opts.version      = TIPC_GENL_V2_VERSION;
	opts.recv_timeo_s = TIPC_GENL_RECV_TIMEO_S;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_genetlink_tipc = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.tipc_link_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	ctx_open = true;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	cluster = TIPC_CLUSTER_ID_MIN + rnd_modulo_u32(TIPC_CLUSTER_ID_RANGE);
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	(void)build_net_set(&ctx, cluster);

	(void)snprintf(bearer_name, sizeof(bearer_name),
		       "udp:trinity%u",
		       (unsigned int)(rand32() & 0xffffu));

	rc = build_bearer_enable(&ctx, bearer_name);
	if (rc == 0) {
		bearer_enabled = true;
		__atomic_add_fetch(&shm->stats.tipc_link_churn.bearer_enable_ok,
				   1, __ATOMIC_RELAXED);
	}

	if (build_publish(rdm) == 0)
		__atomic_add_fetch(&shm->stats.tipc_link_churn.publish_ok,
				   1, __ATOMIC_RELAXED);

	(void)open_topsrv_and_subscribe(&topsrv);

out:
	if (bearer_enabled && ctx_open) {
		if (build_bearer_disable(&ctx, bearer_name) == 0)
			__atomic_add_fetch(&shm->stats.tipc_link_churn.bearer_disable_ok,
					   1, __ATOMIC_RELAXED);
	}

	if (topsrv >= 0)
		close(topsrv);
	if (rdm >= 0)
		close(rdm);
	if (ctx_open)
		genl_close(&ctx);

	return true;
}

#else  /* !__has_include(<linux/tipc.h>) || !__has_include(<linux/tipc_netlink.h>) */

bool tipc_link_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.tipc_link_churn.runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.tipc_link_churn.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/tipc.h>) && __has_include(<linux/tipc_netlink.h>) */
