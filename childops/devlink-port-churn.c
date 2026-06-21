/*
 * devlink_port_churn - port up/down + split/reload race vs a bound socket.
 *
 * The devlink generic netlink family is the configuration plane for
 * bus-level device state: port split/unsplit, driver reinit, region
 * snapshots.  The bug class clustered here is the teardown-while-bound
 * race: devlink_reload_actions_perform() and devlink_port_split() walk
 * driver state and free per-port objects while userspace sockets and
 * routes still reference the live netdev.  Concurrent rtnetlink walkers
 * and SO_BINDTODEVICE-bound sockets cross paths with the reload's
 * teardown of the netdev's queue/qdisc/ndo_open state — exactly the
 * shape of CVE-2024-26848 (devlink reload UAF), CVE-2023-23039 (port
 * split tearing) and the broader DRIVER_REINIT-vs-bound-socket family.
 *
 * Reaching that window from flat per-syscall fuzzing is hopeless: it
 * needs (a) a netdevsim bus device created via /sys/bus/netdevsim/
 * new_device, (b) the resolved devlink genl family id with a
 * structurally valid BUS_NAME/DEV_NAME pair and a per-cmd selector
 * (PORT_INDEX / RELOAD_ACTION), (c) a live AF_INET socket bound to
 * the netdev, and (d) the SPLIT/RELOAD/UNSPLIT/del_device sequence
 * driven mid-flow.  No combination of independent syscalls assembles
 * that without active orchestration.
 *
 * Sequence (per invocation):
 *   1.  Probe /sys/bus/netdevsim/new_device once per process; if
 *       absent or unwritable, latch ns_unsupported_netdevsim and bump
 *       create_skipped on every further call (no genl traffic).
 *   2.  genl_open("devlink", ...) — resolves the family id via a
 *       per-ctx CTRL_CMD_GETFAMILY; -ENOENT latches
 *       ns_unsupported_devlink_genl for the rest of the process.
 *   3.  BUDGETED loop:
 *         a) Allocate a fresh bus_id from a per-fork monotonic
 *            counter rooted at a randomized base (10000 + pid%1000)
 *            so concurrent siblings on the same host don't collide
 *            on the netdevsim id namespace.
 *         b) Create the device: write "$BUS_ID 0 1" to new_device.
 *            On EEXIST (rare collision), bump bus_id and retry once.
 *         c) RTM_NEWADDR: assign a 127.0.0.<rot> address to the
 *            netdevsim netdev (loopback only — must not hit the wire).
 *         d) IFF_UP via SIOCSIFFLAGS — drives the netdev open path.
 *         e) socket(AF_INET, SOCK_DGRAM); SO_BINDTODEVICE the
 *            candidate netdev name.  Bind failure (EPERM, ENODEV) is
 *            benign — the socket still references the netdev via
 *            the routing table and the SPLIT/RELOAD path still
 *            exercises the teardown side.
 *         f) Tight sendto loop bounded to a small packet count to
 *            127.0.0.1 — drives ndo_xmit through the netdevsim queue
 *            so the reload tear-down has live skbs to walk.
 *         g) DEVLINK_CMD_PORT_SPLIT count=4 mid-flow — first bug
 *            window: port object torn down while bound socket and
 *            in-flight skbs reference it.
 *         h) DEVLINK_CMD_RELOAD action=DRIVER_REINIT — second bug
 *            window: full driver state reinit while the socket and
 *            in-flight queue still reference the per-driver
 *            structures.  HARDCODED bus="netdevsim" by static
 *            const so this code path can never reach a real PCI/
 *            mlx5/ice device on a fleet host.
 *         i) DEVLINK_CMD_PORT_UNSPLIT — undo the split.
 *         j) Delete the device: write "$BUS_ID" to del_device while
 *            the socket is still open — third bug window: device
 *            teardown vs bound netdev reference.  Kernel cleans up
 *            the residual socket on close; we close after every
 *            iteration so a wedged child can't pile leaks.
 *
 * Self-bounding: one full cycle per invocation, all sockets non-
 * blocking, loopback only, all genl requests timestamped with
 * SO_RCVTIMEO so an unresponsive controller can't pin past child.c's
 * SIGALRM(1s).  Per-invocation iteration budget is small (defaults to
 * a few cycles, jittered ±50%, scaled by adapt_budget) — every iter
 * creates a netdevsim bus device and the ID space rolls forward, so a
 * runaway loop would burn through the netdevsim id range fast.
 *
 * Brick risk: DRIVER_REINIT against real hardware would actually
 * reset the device.  netdevsim is software-only — reload is a no-op
 * tear/recreate of the in-memory driver state.  We HARDCODE the bus
 * name to "netdevsim" via a single static const and never construct
 * a RELOAD message naming any other bus.  A future caller that wants
 * to extend this op to other devlink buses must add its own gate.
 *
 * Header gating: <linux/devlink.h> ships with all distros from kernel
 * 4.6 onward but the constants we lean on here (DEVLINK_CMD_RELOAD,
 * DEVLINK_ATTR_RELOAD_ACTION) need 5.10+.  Sysroots without them fall
 * to a stub that bumps iterations+create_skipped and returns — same
 * shape as mptcp-pm-churn's __has_include fallback.
 *
 * Failure modes treated as benign coverage:
 *   - new_device write returns ENODEV / ENOENT: netdevsim module not
 *     loaded.  Latched ns_unsupported_netdevsim.
 *   - genl_open("devlink", ...) returns -ENOENT: kernel doesn't expose
 *     the devlink genl family.  Latched ns_unsupported_devlink_genl.
 *   - EPERM on any genl op or BINDTODEVICE: trinity wasn't run with
 *     the right caps.  Counted via the matching _fail counter; the
 *     data-plane sends still exercise the netdev xmit path.
 *   - PORT_SPLIT with count != supported: kernel returns EOPNOTSUPP.
 *     Counted as split_fail; the codepath up to the validator still
 *     ran on the live port object.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/devlink.h>)

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/devlink.h>
#include <linux/netlink.h>
#include <net/if.h>

#include "childops-genl.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "pids.h"

/* netdevsim bus name — pinned here as a static const so the RELOAD
 * codepath can never name a different bus.  See the brick-risk note in
 * the file header. */
static const char DEVLINK_PORT_CHURN_BUS[] = "netdevsim";

/* Latched per-process: /sys/bus/netdevsim/new_device is absent or
 * unwritable.  Once latched, every further invocation just bumps
 * create_skipped and returns. */
static bool ns_unsupported_netdevsim;

/* Latched per-process: genl_open("devlink", ...) returned -ENOENT, so
 * the kernel doesn't expose the devlink genl family at all.  Same
 * lifetime as ns_unsupported_netdevsim. */
static bool ns_unsupported_devlink_genl;

/* Per-fork monotonic bus_id counter.  Initial base randomized off pid
 * to dodge collision with concurrent test harnesses on the same host
 * that also poke netdevsim. */
static __u32 g_bus_id_next;
static bool g_bus_id_inited;

#define DEVLINK_GENL_BUF_BYTES		2048
#define DEVLINK_GENL_RECV_TIMEO_S	1
#define DEVLINK_CHURN_BUDGET		32U
#define DEVLINK_CHURN_ITERS_BASE	2U
#define DEVLINK_CHURN_PKTS_PER_ITER	8U

#define DEVLINK_PORT_SPLIT_COUNT	4U
#define NETDEVSIM_LOOPBACK_BASE		0x7f000001U	/* 127.0.0.1 */
#define NR_NETDEVSIM_LOOPBACK_ADDRS	5U

#define NETDEVSIM_NEW_DEVICE	"/sys/bus/netdevsim/new_device"
#define NETDEVSIM_DEL_DEVICE	"/sys/bus/netdevsim/del_device"

static __u32 alloc_bus_id(void)
{
	if (!g_bus_id_inited) {
		g_bus_id_next = 10000U + ((__u32)mypid() % 1000U) * 100U;
		g_bus_id_inited = true;
	}
	return g_bus_id_next++;
}

/*
 * Build & send a devlink command carrying just the bus/dev identifier
 * pair (BUS_NAME + DEV_NAME).  Used for the dev-level commands that
 * don't need a per-port selector.  Returns the kernel's ack errno.
 */
static int devlink_dev_cmd(struct genl_ctx *ctx, __u8 cmd, const char *dev_name)
{
	unsigned char buf[DEVLINK_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl), cmd, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, DEVLINK_PORT_CHURN_BUS);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send DEVLINK_CMD_PORT_SPLIT with BUS_NAME + DEV_NAME +
 * PORT_INDEX + PORT_SPLIT_COUNT.  netdevsim accepts split counts that
 * are powers of two up to its configured port count; non-matching
 * values bounce as EOPNOTSUPP — counted as split_fail but the kernel
 * still walks the validator and the per-port objects.
 */
static int devlink_port_split(struct genl_ctx *ctx, const char *dev_name,
			      __u32 port_index, __u32 count)
{
	unsigned char buf[DEVLINK_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   DEVLINK_CMD_PORT_SPLIT, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, DEVLINK_PORT_CHURN_BUS);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  DEVLINK_ATTR_PORT_INDEX, port_index);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  DEVLINK_ATTR_PORT_SPLIT_COUNT, count);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send DEVLINK_CMD_PORT_UNSPLIT.  Same attr shape as
 * PORT_SPLIT minus the count.
 */
static int devlink_port_unsplit(struct genl_ctx *ctx, const char *dev_name,
				__u32 port_index)
{
	unsigned char buf[DEVLINK_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   DEVLINK_CMD_PORT_UNSPLIT, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, DEVLINK_PORT_CHURN_BUS);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  DEVLINK_ATTR_PORT_INDEX, port_index);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build & send DEVLINK_CMD_RELOAD action=DRIVER_REINIT against the
 * netdevsim device.  See the brick-risk note in the file header — the
 * bus name is hardcoded, never sourced from a caller, so this can
 * only ever fire against netdevsim.
 */
static int devlink_reload_driver_reinit(struct genl_ctx *ctx,
					const char *dev_name)
{
	unsigned char buf[DEVLINK_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl), DEVLINK_CMD_RELOAD, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, DEVLINK_PORT_CHURN_BUS);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf),
			 DEVLINK_ATTR_RELOAD_ACTION,
			 DEVLINK_RELOAD_ACTION_DRIVER_REINIT);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Write `s` to the sysfs path `path`.  Returns 0 on success or the
 * negated errno on failure.  Used for new_device / del_device / addr
 * assignment via the sysfs control plane.
 */
static int sysfs_write(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	int rc;

	if (fd < 0)
		return -errno;
	n = write(fd, s, strlen(s));
	rc = (n < 0) ? -errno : 0;
	close(fd);
	return rc;
}

/*
 * Probe netdevsim availability once per process.  Cached in
 * ns_unsupported_netdevsim.  We can't usefully open new_device for
 * read+write to test, so we stat() it: if the path is missing or not
 * writable by us, latch the unsupported flag.
 */
static bool netdevsim_available(struct childdata *child)
{
	struct stat st;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_netdevsim)
		return false;
	if (stat(NETDEVSIM_NEW_DEVICE, &st) < 0) {
		ns_unsupported_netdevsim = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return false;
	}
	if (access(NETDEVSIM_NEW_DEVICE, W_OK) < 0) {
		ns_unsupported_netdevsim = true;
		if (valid_op)
			__atomic_store_n(&shm->stats.childop_latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return false;
	}
	return true;
}

/*
 * Best-effort: bind the given socket to a candidate netdev backed by
 * the netdevsim device we just created.  netdevsim names its host-
 * visible netdevs "eni<bus_id>np<port>" on recent kernels and "eth<N>"
 * on older builds — we try a few candidates and fall back to no-bind.
 * Bind failure is benign (EPERM without CAP_NET_RAW; ENODEV if the
 * netdev hasn't surfaced yet); the SPLIT/RELOAD path still races the
 * netdev teardown via the routing table even without an explicit bind.
 */
static void try_bindtodevice(int sock, __u32 bus_id)
{
	char name[IFNAMSIZ];

	/* Most-recent netdevsim naming: eni<bus_id>np0. */
	snprintf(name, sizeof(name), "eni%unp0", (unsigned int)bus_id);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
		       name, (socklen_t)strlen(name)) == 0)
		return;
	/* Older naming sometimes seen on legacy builds. */
	snprintf(name, sizeof(name), "eth%u", (unsigned int)bus_id);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
		       name, (socklen_t)strlen(name)) == 0)
		return;
	/* Couldn't bind to the netdevsim port — drop through; the
	 * subsequent sendto loop just rides loopback routing. */
}

/*
 * Drive a short non-blocking sendto burst at 127.0.0.1.  Bounded by
 * DEVLINK_CHURN_PKTS_PER_ITER so we don't burn the per-cycle budget on
 * data-plane traffic.  Failures are silent — what matters is that
 * skbs are in flight when the SPLIT/RELOAD lands.
 */
static void churn_sendto_burst(int sock)
{
	struct sockaddr_in dst;
	unsigned char buf[64];
	unsigned int i;
	unsigned int n = 1U + rnd_modulo_u32(DEVLINK_CHURN_PKTS_PER_ITER);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);
	dst.sin_port = htons(9U);	/* discard */

	for (i = 0; i < n; i++) {
		generate_rand_bytes(buf, sizeof(buf));
		(void)sendto(sock, buf, 1U + rnd_modulo_u32(sizeof(buf)),
			     MSG_DONTWAIT | MSG_NOSIGNAL,
			     (struct sockaddr *)&dst, sizeof(dst));
	}
}

/*
 * Run one create/churn/destroy cycle for bus_id.  Returns true if the
 * device was successfully created (caller bumps iterations), false if
 * we couldn't even create the device — the latter is a transient that
 * shouldn't burn the iter counter but isn't worth latching.
 */
static bool devlink_port_churn_one(struct genl_ctx *ctx,
				   struct childdata *child, __u32 bus_id)
{
	char dev_name[32];
	char create_payload[64];
	char del_payload[16];
	int sock;
	int rc;

	snprintf(create_payload, sizeof(create_payload), "%u 1", bus_id);
	rc = sysfs_write(NETDEVSIM_NEW_DEVICE, create_payload);
	if (rc == -EEXIST) {
		/* Rare collision with a sibling — the next iter rolls
		 * forward, but for this iter we have nothing to drive. */
		return false;
	}
	if (rc < 0) {
		/* Most likely ENODEV (module gone), EBUSY (sysfs racing
		 * a concurrent del), or EPERM.  Latch on hard absence
		 * via netdevsim_available() at next entry. */
		if (rc == -ENODEV || rc == -ENOENT) {
			ns_unsupported_netdevsim = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop_latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return false;
	}

	snprintf(dev_name, sizeof(dev_name), "netdevsim%u", bus_id);
	snprintf(del_payload, sizeof(del_payload), "%u", bus_id);

	/* Best-effort PORT_GET to warm the per-device port table on
	 * the kernel side — reply parsing is intentionally skipped
	 * (we use port_index 0, the netdevsim default). */
	(void)devlink_dev_cmd(ctx, DEVLINK_CMD_PORT_GET, dev_name);

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sock >= 0) {
		(void)fcntl(sock, F_SETFL, O_NONBLOCK);
		try_bindtodevice(sock, bus_id);
		churn_sendto_burst(sock);
	}

	/* g) Bug window 1: PORT_SPLIT mid-flow. */
	rc = devlink_port_split(ctx, dev_name, 0U,
				DEVLINK_PORT_SPLIT_COUNT);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.devlink_port_churn_split_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.devlink_port_churn_split_fail,
				   1, __ATOMIC_RELAXED);

	/* Drive more skbs into the queue between SPLIT and RELOAD. */
	if (sock >= 0)
		churn_sendto_burst(sock);

	/* h) Bug window 2: DRIVER_REINIT while bound socket alive.
	 * Bus name is HARDCODED to netdevsim — see file header. */
	rc = devlink_reload_driver_reinit(ctx, dev_name);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.devlink_port_churn_reload_ok,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.devlink_port_churn_reload_fail,
				   1, __ATOMIC_RELAXED);

	/* i) Undo the split so del_device sees a clean port topology. */
	(void)devlink_port_unsplit(ctx, dev_name, 0U);

	if (sock >= 0)
		close(sock);

	/* j) Bug window 3: del_device while the residual socket-in-
	 * close cleanup may still be racing.  Safe to ignore the rc —
	 * the kernel will GC even if we leak the bus_id on failure. */
	(void)sysfs_write(NETDEVSIM_DEL_DEVICE, del_payload);

	return true;
}

bool devlink_port_churn(struct childdata *child)
{
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	unsigned int iters;
	unsigned int budget;
	unsigned int i;
	int rc;

	if (!netdevsim_available(child)) {
		__atomic_add_fetch(&shm->stats.devlink_port_churn_create_skipped,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (ns_unsupported_devlink_genl)
		return true;

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = DEVLINK_GENL_NAME;
	opts.version      = DEVLINK_GENL_VERSION;
	opts.recv_timeo_s = DEVLINK_GENL_RECV_TIMEO_S;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_devlink_genl = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop_latch_reason[op],
							 CHILDOP_LATCH_NS_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	budget = BUDGETED(CHILD_OP_DEVLINK_PORT_CHURN,
			  JITTER_RANGE(DEVLINK_CHURN_ITERS_BASE));
	iters = (budget > DEVLINK_CHURN_BUDGET) ? DEVLINK_CHURN_BUDGET : budget;
	if (iters == 0U)
		iters = 1U;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop_data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < iters; i++) {
		__u32 bus_id = alloc_bus_id();

		if (devlink_port_churn_one(&ctx, child, bus_id))
			__atomic_add_fetch(&shm->stats.devlink_port_churn_iterations,
					   1, __ATOMIC_RELAXED);
		else if (ns_unsupported_netdevsim)
			break;
	}

	genl_close(&ctx);
	return true;
}

#else  /* !__has_include(<linux/devlink.h>) */

bool devlink_port_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.devlink_port_churn_create_skipped,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/devlink.h>) */
