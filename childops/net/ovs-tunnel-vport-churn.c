/*
 * ovs_tunnel_vport_churn - OVS tunnel vport CMD_NEW + CMD_DEL race driver.
 *
 * Open vSwitch's userspace control path lets a single netlink client
 * create a datapath, then attach tunnel vports of GENEVE / VXLAN / GRE
 * type to it.  Each successful CMD_NEW asks the OVS kernel module to
 * register the matching shared "tunnel sys" netdev (geneve_sys_<port>,
 * vxlan_sys_<port>, gre_sys_<port>) on demand, and CMD_DEL tears the
 * vport down with rtnl held while the underlying tunnel driver is
 * still wired into the OVS dispatch tables.
 *
 * Two upstream regression classes hide in that flow:
 *   1) OVS_VPORT_CMD_DEL self-deadlock on tunnel ports -- the
 *      tunnel-vport ->destroy() handler ran call_rcu(...) while the
 *      caller still held rtnl; rcu_barrier() inside the unregister
 *      path then waited for an rtnl_lock-taking callback and
 *      deadlocked the netlink writer.  Fixed upstream by reordering
 *      the ->destroy / rtnl_unlock pair (commit aa69918bd418).
 *   2) OVS_VPORT_CMD_NEW vs RTM_DELLINK / IFLA_IFNAME race on the
 *      shared geneve_sys_<port> / vxlan_sys_<port> / gre_sys_<port>
 *      netdev: a concurrent rtnetlink rename or delete of the helper
 *      netdev while OVS was still finishing its register-vport
 *      handshake left dangling pointers in ovs_net->dps[].  Fixed
 *      upstream by 83861c48ba12.
 *
 * Neither path is reachable from any existing childop: vxlan-encap
 * exercises the rtnl-only tunnel create/destroy edge but never goes
 * through OVS, and genetlink-fuzzer hits the OVS family demuxer with
 * fully random payloads that almost never assemble a structurally-valid
 * tunnel vport message.  This childop closes that gap.
 *
 * Sequence (per child, latched after first successful setup):
 *   1. try_modprobe openvswitch / geneve / vxlan / ip_gre.
 *   2. genl_open("ovs_datapath", ...) and genl_open("ovs_vport", ...) —
 *      a per-ctx CTRL_CMD_GETFAMILY for each family.  Two sockets so
 *      every send/recv stays on the shared genl_send_recv() single-ack
 *      path; the old dump-based two-family resolver went away with the
 *      migration to childops-genl.h.
 *   3. OVS_DP_CMD_NEW with OVS_DP_ATTR_NAME = tcdp_<child_id>,
 *      OVS_DP_ATTR_UPCALL_PID = 0.  Datapath name is per-child so
 *      siblings don't fight over the shared name space at startup.
 *
 * Per iteration:
 *   1. Pick a tunnel kind weighted GENEVE 5 / VXLAN 4 / GRE 3, skipping
 *      kinds whose modprobe / earlier attempt latched as unsupported.
 *   2. Send OVS_VPORT_CMD_NEW on ovs_vport with TYPE = kind, NAME =
 *      tcvp_<child>_<iter> (<= IFNAMSIZ), UPCALL_PID = u32[1]{0}, and
 *      OPTIONS nested with OVS_TUNNEL_ATTR_DST_PORT (random
 *      [20000..30000]) for GENEVE / VXLAN, empty for GRE.
 *   3. With ONE_IN(2): open a separate rtnetlink socket and fire
 *      RTM_DELLINK at the underlying helper netdev (geneve_sys_<port>
 *      / vxlan_sys_<port> / gre_sys_<port>).  Best-effort, no ack
 *      processing.  This is the rename/delete-vs-CMD_NEW race window.
 *   4. Short jitter, then OVS_VPORT_CMD_DEL referencing the same
 *      vport name.  This is the CMD_DEL self-deadlock window -- once
 *      both fixes are in, the path stays warm; without them the
 *      child wedges on the netlink ack and the parent SIGALRMs us.
 *
 * Self-bounding: SO_RCVTIMEO=1s on every netlink socket so an
 * unresponsive OVS family can't wedge us past the SIGALRM(1s) cap
 * inherited from child.c.  All sends use the per-family genl ctx bound
 * to the child's pid; the rtnl racer opens one route socket for its
 * whole bounded-deadline lifetime and fires NLM_F_REQUEST (no ack)
 * each iteration.  Every kind has its own latch so a kernel without
 * GENEVE / VXLAN / GRE pays the EFAIL once and skips that kind on
 * subsequent invocations.
 */

#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-genl.h"
#include "childops-netlink.h"
#include "childops-util.h"
#include "jitter.h"
#include "kernel/openvswitch.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
/* The IFLA_IFNAME-bearing rtnetlink racer is fire-and-forget; we never
 * wait for an ack so we don't need NLM_F_ACK in its flags.  The
 * one-second recv timeout still applies to the genl socket since the
 * CMD_NEW / CMD_DEL ack is what hangs in the deadlock case. */
#define OVS_RECV_TIMEO_S	1
#define OVS_NETLINK_BUF_BYTES	2048

/* DST_PORT range is intentionally narrow but well outside the well-
 * known VXLAN (4789) / GENEVE (6081) defaults so each iteration takes
 * a fresh path through the per-port hash table on the kernel side. */
#define OVS_DST_PORT_MIN	20000
#define OVS_DST_PORT_MAX	30000

/* Per-iteration jitter base for the gap between CMD_NEW + DELLINK race
 * and the trailing CMD_DEL.  BUDGETED scales it, JITTER_RANGE picks
 * the actual delay; the small base keeps us well under SIGALRM(1s). */
#define OVS_DELAY_BASE		2U

/* Latched per-child gates.  Module presence and family registration
 * are static for a child's lifetime; once the EFAIL is paid we stop
 * probing and just bump the runs counter. */
static bool ovs_setup_failed;
static bool ovs_setup_done;
/* Latched when genl_open() for either ovs_datapath or ovs_vport
 * returns -ENOENT — i.e. the kernel doesn't expose the OVS genl
 * surface at all (CONFIG_OPENVSWITCH=n or the families haven't been
 * registered yet).  Distinguished from the generic ovs_setup_failed
 * so the rest of the process can tell "kernel does not expose this
 * surface" from "we tried and the socket setup failed for another
 * reason".  Mirrors ns_unsupported_devlink_genl in
 * devlink-port-churn.c. */
static bool ns_unsupported_ovs_genl;
static bool ovs_kind_unsupported_geneve;
static bool ovs_kind_unsupported_vxlan;
static bool ovs_kind_unsupported_gre;

/* One genl ctx per family: ovs_datapath carries OVS_DP_CMD_*, ovs_vport
 * carries OVS_VPORT_CMD_*.  Each ctx owns its own NETLINK_GENERIC
 * socket + sequence counter.  Sockets stay open for the child's
 * lifetime so we don't re-modprobe / re-create the datapath every
 * invocation. */
static struct genl_ctx ovs_dp_ctx;
static struct genl_ctx ovs_vport_ctx;
static __u32 ovs_iter_id;

enum ovs_tun_kind {
	OVS_TUN_GENEVE = 0,
	OVS_TUN_VXLAN,
	OVS_TUN_GRE,
	OVS_TUN_NR,
};

/* Pick weights mirror the spec: GENEVE 5 / VXLAN 4 / GRE 3.  Sum = 12,
 * picker rolls rnd_modulo_u32(12) and walks the cumulative table.  Weights
 * are intentionally biased toward GENEVE because its sys netdev is the
 * one most often touched by the upstream regression history. */
static const unsigned int ovs_kind_weights[OVS_TUN_NR] = {
	[OVS_TUN_GENEVE] = 5,
	[OVS_TUN_VXLAN]  = 4,
	[OVS_TUN_GRE]    = 3,
};
#define OVS_KIND_WEIGHT_SUM	12U

static __u32 next_ovs_iter_id(void)
{
	return ++ovs_iter_id;
}

static bool *ovs_kind_latch(enum ovs_tun_kind k)
{
	switch (k) {
	case OVS_TUN_GENEVE:	return &ovs_kind_unsupported_geneve;
	case OVS_TUN_VXLAN:	return &ovs_kind_unsupported_vxlan;
	case OVS_TUN_GRE:	return &ovs_kind_unsupported_gre;
	case OVS_TUN_NR:	break;
	}
	return NULL;
}

static __u32 ovs_kind_type_id(enum ovs_tun_kind k)
{
	switch (k) {
	case OVS_TUN_GENEVE:	return OVS_VPORT_TYPE_GENEVE;
	case OVS_TUN_VXLAN:	return OVS_VPORT_TYPE_VXLAN;
	case OVS_TUN_GRE:	return OVS_VPORT_TYPE_GRE;
	case OVS_TUN_NR:	break;
	}
	return 0;
}

/* Compose the helper-netdev name that the kernel registers for each
 * tunnel kind on first vport create: geneve_sys_<port> / vxlan_sys_<port>
 * / gre_sys_<port>.  GRE's helper has no port suffix in older kernels;
 * we stamp "gre_sys_0" which is the canonical fallback name and resolves
 * to the same ip_gre stub regardless. */
static void ovs_fill_helper_netdev(enum ovs_tun_kind k, __u16 port,
				   char *out, size_t cap)
{
	switch (k) {
	case OVS_TUN_GENEVE:
		(void)snprintf(out, cap, "geneve_sys_%u", (unsigned int)port);
		return;
	case OVS_TUN_VXLAN:
		(void)snprintf(out, cap, "vxlan_sys_%u", (unsigned int)port);
		return;
	case OVS_TUN_GRE:
		(void)snprintf(out, cap, "gre_sys_0");
		return;
	case OVS_TUN_NR:
		break;
	}
	if (cap > 0)
		out[0] = '\0';
}

static enum ovs_tun_kind ovs_pick_kind(void)
{
	unsigned int roll = rnd_modulo_u32(OVS_KIND_WEIGHT_SUM);
	unsigned int acc = 0;
	unsigned int i;
	enum ovs_tun_kind picked = OVS_TUN_NR;

	for (i = 0; i < OVS_TUN_NR; i++) {
		acc += ovs_kind_weights[i];
		if (roll < acc) {
			picked = (enum ovs_tun_kind)i;
			break;
		}
	}

	if (picked == OVS_TUN_NR)
		return OVS_TUN_NR;

	if (!*ovs_kind_latch(picked))
		return picked;

	/* Latched: scan forward looking for any non-latched kind so a
	 * single unsupported tunnel module doesn't starve the others. */
	for (i = 1; i < OVS_TUN_NR; i++) {
		enum ovs_tun_kind k =
			(enum ovs_tun_kind)((picked + i) % OVS_TUN_NR);
		if (!*ovs_kind_latch(k))
			return k;
	}
	return OVS_TUN_NR;
}

/*
 * Best-effort modprobe.  Same shape as the vxlan-encap helper: fork +
 * execvp("modprobe -q ..."), redirect stdio to /dev/null, ignore the
 * exit status -- the latch on a subsequent CMD_NEW probe is the real
 * gate.  Static linkage so the wider build doesn't trip the
 * Wmissing-prototypes check on a duplicate name.
 */
static void ovs_try_modprobe(const char *mod)
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
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

/*
 * Build + send OVS_DP_CMD_NEW for tcdp_<child>.  Required attributes
 * per uapi: OVS_DP_ATTR_NAME (string) and OVS_DP_ATTR_UPCALL_PID (u32).
 * UPCALL_PID = 0 means "drop upcalls"; we don't want the kernel to
 * spray packets at us.
 */
static int ovs_create_datapath(struct genl_ctx *ctx, const char *name)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   OVS_DP_CMD_NEW, NLM_F_CREATE | NLM_F_EXCL);
	if (!off)
		return -EIO;

	ovsh = (struct ovs_header *)(buf + off);
	ovsh->dp_ifindex = 0;
	off += NLA_ALIGN(sizeof(*ovsh));

	off = nla_put_str(buf, off, sizeof(buf), OVS_DP_ATTR_NAME, name);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), OVS_DP_ATTR_UPCALL_PID, 0);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build + send OVS_VPORT_CMD_NEW for the requested kind on the cached
 * datapath.  TYPE / NAME / UPCALL_PID are mandatory; OPTIONS is a
 * nested attr carrying OVS_TUNNEL_ATTR_DST_PORT for GENEVE / VXLAN.
 * GRE has no per-port option in the OVS uapi so its OPTIONS nest is
 * left empty (and omitted entirely below to avoid emitting a zero-len
 * nested attr the kernel will reject).
 */
static int ovs_create_vport(struct genl_ctx *ctx, int dp_ifindex,
			    enum ovs_tun_kind kind,
			    const char *vname, __u16 dst_port)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	__u32 upcall_pid = 0;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   OVS_VPORT_CMD_NEW, NLM_F_CREATE | NLM_F_EXCL);
	if (!off)
		return -EIO;

	ovsh = (struct ovs_header *)(buf + off);
	ovsh->dp_ifindex = dp_ifindex;
	off += NLA_ALIGN(sizeof(*ovsh));

	off = nla_put_u32(buf, off, sizeof(buf),
			  OVS_VPORT_ATTR_TYPE, ovs_kind_type_id(kind));
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  OVS_VPORT_ATTR_NAME, vname);
	if (!off)
		return -EIO;

	/* OVS_VPORT_ATTR_UPCALL_PID is a u32[] (one entry per upcall pid).
	 * A single zero pid stamps the "discard upcalls" intent. */
	off = nla_put(buf, off, sizeof(buf),
		      OVS_VPORT_ATTR_UPCALL_PID,
		      &upcall_pid, sizeof(upcall_pid));
	if (!off)
		return -EIO;

	if (kind == OVS_TUN_GENEVE || kind == OVS_TUN_VXLAN) {
		size_t opts_off = off;

		off = nla_nest_start(buf, off, sizeof(buf),
				     OVS_VPORT_ATTR_OPTIONS | NLA_F_NESTED);
		if (!off)
			return -EIO;

		off = nla_put_u16(buf, off, sizeof(buf),
				  OVS_TUNNEL_ATTR_DST_PORT,
				  htons(dst_port));
		if (!off)
			return -EIO;

		nla_nest_end(buf, opts_off, off);
	}

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Build + send OVS_VPORT_CMD_DEL referencing the vport name we just
 * created.  CMD_DEL by name + dp_ifindex is the canonical untrusted-
 * caller path; the kernel resolves the vport from name within the
 * datapath and tears it down with rtnl held -- exactly the path the
 * upstream self-deadlock fix landed on.
 */
static int ovs_delete_vport(struct genl_ctx *ctx, int dp_ifindex,
			    const char *vname)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   OVS_VPORT_CMD_DEL, 0);
	if (!off)
		return -EIO;

	ovsh = (struct ovs_header *)(buf + off);
	ovsh->dp_ifindex = dp_ifindex;
	off += NLA_ALIGN(sizeof(*ovsh));

	off = nla_put_str(buf, off, sizeof(buf),
			  OVS_VPORT_ATTR_NAME, vname);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/*
 * Bounded-deadline RTM_DELLINK racer.  Designed to run in a forked
 * helper that overlaps with the parent's still-in-flight
 * OVS_VPORT_CMD_NEW.  The kernel's CMD_NEW handler drops and reacquires
 * rtnl while registering the shared geneve_sys_<port> / vxlan_sys_<port>
 * / gre_sys_<port> helper netdev; in that window a separate rtnetlink
 * writer can race an unregister against the OVS register-vport path,
 * leaving dangling pointers in ovs_net->dps[] (the bug fixed upstream
 * by 83861c48ba12).  A post-ack racer can't reach that window because
 * the helper netdev has already been linked into ovs_net->dps[] by the
 * time CMD_NEW returns NLM_F_ACK -- the racer has to be in flight
 * during the kernel handler, not after it.
 *
 * One route socket + one RTM_DELLINK envelope are stamped before the
 * loop; the body only re-resolves the helper ifindex, updates
 * nlmsg_seq + ifi_index, and sendmsg(MSG_DONTWAIT)s.  Fire-and-forget:
 * a missing helper / refused ifindex / send failure just costs one
 * wasted iteration.  Exit conditions: deadline reached, hard iteration
 * cap tripped, or clock_gettime failure.  sched_yield() at the tail
 * of each iteration keeps the parent (and the kernel handler)
 * scheduled.
 */
#define OVS_RACE_DELLINK_MAX_ITERS	50U

static void ovs_race_dellink_loop(const char *helper_name,
				  unsigned int deadline_ms)
{
	struct nl_ctx racer_ctx;
	struct nl_open_opts ropts;
	struct sockaddr_nl dst;
	struct timespec start, now;
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct iovec iov;
	struct msghdr mh;
	unsigned int iter;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return;

	memset(&ropts, 0, sizeof(ropts));
	ropts.proto = NETLINK_ROUTE;
	ropts.recv_timeo_s = OVS_RECV_TIMEO_S;
	if (nl_open(&racer_ctx, &ropts) != 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_len   = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = buf;
	iov.iov_len  = nlh->nlmsg_len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	for (iter = 0; iter < OVS_RACE_DELLINK_MAX_ITERS; iter++) {
		long elapsed_ms;
		int ifindex;

		/* Re-resolve every iter: the helper netdev is racing into
		 * existence as the kernel's CMD_NEW handler runs, so a
		 * cached ifindex would skip the registration window. */
		ifindex = (int)if_nametoindex(helper_name);
		if (ifindex > 0) {
			nlh->nlmsg_seq = nl_seq_next(&racer_ctx);
			ifi->ifi_index = ifindex;
			(void)sendmsg(racer_ctx.fd, &mh, MSG_DONTWAIT);
		}

		sched_yield();

		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			break;
		elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L +
			     (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= 0 && (unsigned long)elapsed_ms >= deadline_ms)
			break;
	}

	nl_close(&racer_ctx);
}

/*
 * One-time setup: modprobe the four kernel modules we need, open the
 * cached per-family genl ctxs (each a unicast CTRL_CMD_GETFAMILY by
 * name via genl_open()), and create the per-child datapath.  Latches
 * ovs_setup_failed on any fatal step so subsequent invocations short-
 * circuit to the runs counter without retrying.
 */
static bool ovs_one_time_setup(struct childdata *child)
{
	struct genl_open_opts opts;
	char dpname[32];
	int rc;

	if (ovs_setup_done)
		return true;
	if (ovs_setup_failed)
		return false;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ovs_try_modprobe("openvswitch");
	ovs_try_modprobe("geneve");
	ovs_try_modprobe("vxlan");
	ovs_try_modprobe("ip_gre");

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = "ovs_datapath";
	opts.version      = OVS_DATAPATH_VERSION;
	opts.recv_timeo_s = OVS_RECV_TIMEO_S;
	rc = genl_open(&ovs_dp_ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_ovs_genl = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		ovs_setup_failed = true;
		return false;
	}

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = "ovs_vport";
	opts.version      = OVS_VPORT_VERSION;
	opts.recv_timeo_s = OVS_RECV_TIMEO_S;
	rc = genl_open(&ovs_vport_ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT) {
			ns_unsupported_ovs_genl = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		ovs_setup_failed = true;
		genl_close(&ovs_dp_ctx);
		return false;
	}

	(void)snprintf(dpname, sizeof(dpname), "tcdp_%u",
		       (unsigned int)(child->num & 0xffffu));
	rc = ovs_create_datapath(&ovs_dp_ctx, dpname);
	if (rc != 0 && rc != -EEXIST) {
		/* EOPNOTSUPP / EPROTONOSUPPORT means the kernel is missing
		 * CONFIG_OPENVSWITCH outright; nothing more we can do. */
		ovs_setup_failed = true;
		genl_close(&ovs_vport_ctx);
		genl_close(&ovs_dp_ctx);
		return false;
	}

	ovs_setup_done = true;
	return true;
}

bool ovs_tunnel_vport_churn(struct childdata *child)
{
	char vname[IFNAMSIZ];
	/* Helper netdev name can in principle exceed IFNAMSIZ for large
	 * UDP ports (kernel truncates on register).  Size the local buffer
	 * larger so snprintf doesn't lose digits at the format-truncation
	 * gate; the racer lookup just fails when the kernel-side name is
	 * truncated and that's fine (it just means we miss the window). */
	char helper[32];
	enum ovs_tun_kind kind;
	__u16 dst_port;
	__u32 iter;
	unsigned int spin;
	unsigned int i;
	pid_t racer_pid = 0;
	int rc;

	__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn.runs, 1,
			   __ATOMIC_RELAXED);

	if (ovs_setup_failed)
		return true;

	if (!ovs_one_time_setup(child)) {
		__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	kind = ovs_pick_kind();
	if (kind == OVS_TUN_NR)
		return true;

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

	dst_port = (__u16)RAND_RANGE(OVS_DST_PORT_MIN, OVS_DST_PORT_MAX);
	iter = next_ovs_iter_id();

	(void)snprintf(vname, sizeof(vname), "tcvp_%u_%u",
		       (unsigned int)(child->num & 0xffu),
		       (unsigned int)(iter & 0xffffu));

	/* Pre-CMD_NEW racer fork.  The kernel CMD_NEW handler for tunnel
	 * vports drops and reacquires rtnl while registering the shared
	 * helper netdev; that drop is the bug-2 (83861c48ba12) UAF window.
	 * A post-ack racer can't reach it -- by the time CMD_NEW returns,
	 * the helper netdev is already linked into ovs_net->dps[].  So
	 * fork a short-lived helper that loops RTM_DELLINK at the helper
	 * name across the kernel handler's lifetime; the helper inherits
	 * our netns automatically.  Reaped after CMD_DEL below. */
	if (ONE_IN(2)) {
		ovs_fill_helper_netdev(kind, dst_port, helper, sizeof(helper));
		if (helper[0] != '\0') {
			racer_pid = fork();
			if (racer_pid == 0) {
				ovs_race_dellink_loop(helper, 5);
				_exit(0);
			}
			if (racer_pid < 0)
				racer_pid = 0;
			else
				__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn.race_dellink_attempted,
						   1, __ATOMIC_RELAXED);
		}
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	rc = ovs_create_vport(&ovs_vport_ctx, 0, kind, vname, dst_port);
	if (rc != 0) {
		/* Module-not-loaded / type-not-registered errors latch the
		 * kind off; transient EBUSY / EEXIST / EADDRINUSE leave the
		 * latch alone so the next iteration retries with a fresh
		 * <port, name> pair. */
		if (rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
		    rc == -EPROTONOSUPPORT || rc == -ENOENT) {
			*ovs_kind_latch(kind) = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		if (racer_pid > 0) {
			int wstatus;

			(void)waitpid_eintr(racer_pid, &wstatus, 0);
		}
		return true;
	}
	__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn.create_ok, 1,
			   __ATOMIC_RELAXED);

	/* Short jitter spin between CMD_NEW and the trailing CMD_DEL.
	 * BUDGETED keeps an unproductive run from melting cycles here. */
	spin = BUDGETED(CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
			JITTER_RANGE(OVS_DELAY_BASE));
	for (i = 0; i < spin; i++) {
		__asm__ __volatile__("" ::: "memory");
	}

	if (ovs_delete_vport(&ovs_vport_ctx, 0, vname) == 0)
		__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn.delete_ok,
				   1, __ATOMIC_RELAXED);

	if (racer_pid > 0) {
		int wstatus;

		/* Helper has a bounded ~5ms deadline + 50-iter cap, so this
		 * is fast.  Reap to avoid leaking a zombie back to child.c. */
		(void)waitpid_eintr(racer_pid, &wstatus, 0);
	}

	return true;
}
