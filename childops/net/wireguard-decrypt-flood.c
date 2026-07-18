/*
 * wireguard_decrypt_flood — drive the kernel's wg_packet_decrypt_worker
 * under sustained pps load with syntactically-correct but undecryptable
 * MESSAGE_DATA transport packets.  upstream CI has produced soft-lockup
 * dumps in this worker at high pps; the bug shape lives in the
 * schedule-and-bail path through wg_packet_decrypt_worker, not in the
 * crypto itself, so junk Poly1305 tags are sufficient — the kernel
 * still walks receive_data_packet, dispatches the decrypt to the
 * per-cpu crypt queue, and only then drops on tag verification.  Every
 * dropped packet still costs the worker its fair share of CPU time,
 * and 200 packets per iter at ~50us spacing is enough to keep the
 * worker pinned long enough to surface the lockup window without
 * starving cooperating syscall fuzzer siblings on the box.
 *
 * Sequence (per invocation):
 *   0. userns_run_in_ns(CLONE_NEWNET) forks a transient grandchild
 *      into an owned user namespace + private net namespace.  Steps
 *      1..5 all run inside that grandchild; its _exit() tears both
 *      namespaces down along with wg0, the genl socket, the UDP fd
 *      and any transient state, so no host wireguard configuration
 *      is touched.  The persistent fuzz child keeps the host
 *      credential profile the cap-drop oracle observes.  Helper
 *      -EPERM (hardened userns policy refused CLONE_NEWUSER) latches
 *      ns_unsupported_wireguard_decrypt_flood for the child's
 *      lifetime; -EAGAIN (transient grandchild setup failure) skips
 *      the iteration without latching.
 *   1. (per grandchild) RTM_NEWLINK kind=wireguard creates wg0 in the
 *      grandchild's fresh private netns.  EOPNOTSUPP / ENODEV /
 *      EAFNOSUPPORT latches ns_unsupported_wireguard_decrypt_flood
 *      from inside the grandchild — same shape as the
 *      EPROTONOSUPPORT-latch in atm_vcc_churn.  The write dies with
 *      the grandchild; a wireguard-absent kernel re-discovers the
 *      rejection once per invocation.
 *   2. (per grandchild) Open a NETLINK_GENERIC socket and resolve
 *      the "wireguard" genl family id via the shared genl_open()
 *      helper.  -ENOENT latches ns_unsupported_wireguard_decrypt_flood.
 *   3. (per grandchild) WG_CMD_SET_DEVICE installs an ephemeral
 *      curve25519 private key (32 random bytes — the kernel side
 *      clamps), picks our listen port, and registers one peer with a
 *      random public key, allowed-ips 192.0.2.0/24, and endpoint
 *      127.0.0.1:<peer_port>.  Both ports are derived from mypid() so
 *      concurrent siblings don't collide on bind().  The attribute
 *      tree is the same one walked by the existing genetlink fam-
 *      wireguard grammar, but built inline because we want a peer that
 *      actually parses, not a fuzzed payload.
 *   4. (per grandchild) RTM_SETLINK IFF_UP brings wg0 up; SOCK_DGRAM
 *      is bound to peer_port so any reply traffic terminates cleanly.
 *   5. (per grandchild) Burst loop: build up to 200 MESSAGE_DATA
 *      packets (type=4 LE u32, random key_idx, incrementing counter,
 *      16..1400 random "ciphertext" bytes) and sendto wg0's listen
 *      port on 127.0.0.1.  50us nanosleep between sends keeps pps
 *      tight.
 *
 * Self-bounding: child.c's SIGALRM(1s) wraps each iter; the burst
 * loop is hard-bounded at 200; the grandchild's netns teardown on
 * _exit() reaps wg0 and the UDP socket.  Loopback only, no live wire.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/wireguard.h>)

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>

#include "childops-genl.h"
#include "childops-netlink.h"
#include "random.h"
#include "pids.h"
#include "userns-bootstrap.h"

#include "kernel/socket.h"
#define WGDF_BUF_BYTES		2048
#define WGDF_BURST_MAX		200U
#define WGDF_GAP_NS		50000L		/* 50us between sends */
#define WGDF_PAYLOAD_MIN	16U
#define WGDF_PAYLOAD_MAX	1400U
#define WGDF_RECV_TIMEO_MS	250
#define WGDF_PORT_BASE		32768U		/* high-range, peer/listen derive from pid */
#define WGDF_LO_ADDR		0x0100007fU	/* 127.0.0.1, network order */

/* MESSAGE_DATA == 4 in drivers/net/wireguard/messages.h.  All four
 * type codes are 32-bit little-endian on the wire. */
#define WGDF_MSG_TYPE_DATA	4U

/* Master gate: persistent across iterations in the persistent child.
 * Two writers:
 *
 *   - the wrapper, on userns_run_in_ns() returning -EPERM (hardened
 *     userns policy refused unshare(CLONE_NEWUSER): typically
 *     user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 *     Without a private netns we MUST NOT touch the host's wireguard
 *     configuration, so this write persists across invocations and
 *     short-circuits the op for the remainder of the child's lifetime.
 *
 *   - the in-ns callback, on the first RTM_NEWLINK / genl_open /
 *     WG_CMD_SET_DEVICE structural rejection (EOPNOTSUPP / ENODEV /
 *     EAFNOSUPPORT / ENOENT) observed inside the grandchild -- the
 *     wireguard kernel module absent at runtime.  That write lives in
 *     the grandchild's address space and dies with the grandchild,
 *     so the rejection is re-discovered once per invocation; userns
 *     cannot manufacture an absent kernel module, so cross-invocation
 *     persistence of that path is not in scope. */
static bool ns_unsupported_wireguard_decrypt_flood;

/* Per-grandchild bookkeeping.  Inherited as false / -1 / 0 at grand-
 * child fork time (the persistent child never writes these -- the
 * in-ns callback runs exclusively in transient grandchildren);
 * populated by the grandchild's wgdf_setup() and consumed by the
 * grandchild's burst loop.  Die with the grandchild on _exit(), so
 * each subsequent grandchild re-runs setup once in its own fresh
 * netns. */
static bool g_wgdf_setup_done;
static int g_wgdf_udp_fd = -1;
static int g_wgdf_wg_ifindex;
static __u16 g_wgdf_listen_port;
static __u16 g_wgdf_peer_port;
static __u64 g_wgdf_counter;

/* Called from the wrapper (-EPERM) with LATCH_NS_UNSUPPORTED and from
 * the in-ns callback (config-absent errnos) with LATCH_UNSUPPORTED.
 * Sets the master gate once and stamps the per-op latch reason.  When
 * invoked from a grandchild, the master-gate write dies with the
 * grandchild but the per-op stats slot (in shared memory) still
 * reflects the last observed reason. */
static void wgdf_latch_unsupported(struct childdata *child,
				   enum childop_latch_reason reason)
{
	if (ns_unsupported_wireguard_decrypt_flood)
		return;
	ns_unsupported_wireguard_decrypt_flood = true;
	__atomic_add_fetch(&shm->stats.wgdf.unsupported_latched, 1,
			   __ATOMIC_RELAXED);
	/* child->op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check the snapshot
	 * before indexing the NR_CHILD_OP_TYPES-sized stats arrays, same
	 * pattern the child.c dispatch loop uses for the unguarded write
	 * that motivated this guard. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 reason, __ATOMIC_RELAXED);
	}
}

static bool wgdf_err_unsupported(int rc)
{
	return rc == -EOPNOTSUPP || rc == -ENODEV || rc == -EAFNOSUPPORT;
}

/* Fill @len bytes with rand32() output.  Used for the curve25519
 * privkey, the peer pubkey, and the per-packet ciphertext body — none
 * of which the kernel validates beyond length.  The privkey is clamped
 * by wg_noise_set_static_identity_private_key on install, so passing
 * raw bytes is fine. */
static void wgdf_fill_random(unsigned char *out, size_t len)
{
	size_t i;
	__u32 r;

	for (i = 0; i + sizeof(r) <= len; i += sizeof(r)) {
		r = rand32();
		memcpy(out + i, &r, sizeof(r));
	}
	if (i < len) {
		r = rand32();
		memcpy(out + i, &r, len - i);
	}
}

/* RTM_NEWLINK with IFLA_IFNAME=wg0 + IFLA_LINKINFO/IFLA_INFO_KIND=
 * "wireguard".  The wireguard module supplies its own rtnl_link_ops
 * with .kind = "wireguard", so the kernel routes us straight to
 * wg_newlink().  No IFLA_INFO_DATA is required. */
static int wgdf_create_wg0(struct nl_ctx *rtnl, const char *ifname)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;

	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off) return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "wireguard");
	if (!off) return -EIO;
	nla_nest_end(buf, li_off, off);

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/* RTM_SETLINK to flip IFF_UP on @ifindex. */
static int wgdf_link_up(struct nl_ctx *rtnl, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(rtnl, buf, off);
}

/* Build & send WG_CMD_SET_DEVICE on @ctx to install our private
 * key, listen port, and a single peer with allowed-ips 192.0.2.0/24
 * and endpoint 127.0.0.1:<peer_port>.  The doubly-nested
 * WGDEVICE_A_PEERS / WGPEER_A_ALLOWEDIPS shape is the one
 * net/netlink/genl/wireguard.c documents. */
static int wgdf_set_device(struct genl_ctx *ctx, int ifindex,
			   __u16 listen_port, __u16 peer_port)
{
	unsigned char buf[WGDF_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct sockaddr_in endpoint;
	unsigned char privkey[WG_KEY_LEN];
	unsigned char pubkey[WG_KEY_LEN];
	unsigned char ipaddr[4] = { 192, 0, 2, 0 };
	size_t off, peers_off, peer0_off, aips_off, aip0_off;
	__u32 ifindex_u32 = (__u32)ifindex;

	wgdf_fill_random(privkey, sizeof(privkey));
	wgdf_fill_random(pubkey, sizeof(pubkey));

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   WG_CMD_SET_DEVICE, 0);
	if (!off) return -EIO;

	off = nla_put(buf, off, sizeof(buf), WGDEVICE_A_IFINDEX,
		      &ifindex_u32, sizeof(ifindex_u32));
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), WGDEVICE_A_PRIVATE_KEY,
		      privkey, sizeof(privkey));
	if (!off) return -EIO;
	off = nla_put_u16(buf, off, sizeof(buf), WGDEVICE_A_LISTEN_PORT,
			  listen_port);
	if (!off) return -EIO;

	peers_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), WGDEVICE_A_PEERS);
	if (!off) return -EIO;

	peer0_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 0);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), WGPEER_A_PUBLIC_KEY,
		      pubkey, sizeof(pubkey));
	if (!off) return -EIO;

	memset(&endpoint, 0, sizeof(endpoint));
	endpoint.sin_family = AF_INET;
	endpoint.sin_port   = htons(peer_port);
	endpoint.sin_addr.s_addr = WGDF_LO_ADDR;
	off = nla_put(buf, off, sizeof(buf), WGPEER_A_ENDPOINT,
		      &endpoint, sizeof(endpoint));
	if (!off) return -EIO;

	aips_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), WGPEER_A_ALLOWEDIPS);
	if (!off) return -EIO;
	aip0_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), 0);
	if (!off) return -EIO;
	off = nla_put_u16(buf, off, sizeof(buf), WGALLOWEDIP_A_FAMILY, AF_INET);
	if (!off) return -EIO;
	off = nla_put(buf, off, sizeof(buf), WGALLOWEDIP_A_IPADDR,
		      ipaddr, sizeof(ipaddr));
	if (!off) return -EIO;
	off = nla_put_u8(buf, off, sizeof(buf), WGALLOWEDIP_A_CIDR_MASK, 24);
	if (!off) return -EIO;

	nla_nest_end(buf, aip0_off, off);
	nla_nest_end(buf, aips_off, off);
	nla_nest_end(buf, peer0_off, off);
	nla_nest_end(buf, peers_off, off);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return genl_send_recv(ctx, buf, off);
}

/* Open SOCK_DGRAM and bind to 127.0.0.1:peer_port so wg0 reply
 * traffic terminates locally instead of triggering ICMP unreachables.
 * Returns the bound fd or -1 on failure. */
static int wgdf_open_udp(__u16 peer_port)
{
	struct sockaddr_in sin;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(peer_port);
	sin.sin_addr.s_addr = WGDF_LO_ADDR;
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* One-time per-grandchild setup.  Runs inside the transient userns +
 * netns grandchild forked by userns_run_in_ns(); the wg0 device, the
 * netlink sockets and the UDP fd this creates all die with the
 * grandchild's netns on _exit(), so "one-time per grandchild" is
 * effectively "once per invocation of wireguard_decrypt_flood()".
 * All branches that fail with an unsupported-shaped error latch the
 * whole op off (via the grandchild-local master-gate write; a fresh
 * grandchild rediscovers the rejection because the wireguard module
 * cannot be manufactured by userns); everything else bumps
 * wgdf_setup_failed and returns false so the next iter retries (the
 * failure may be a transient bind() race, etc.).  child is threaded
 * in so the latch-off paths can attribute the CHILDOP_LATCH_UNSUPPORTED
 * reason to the running childop's slot. */
static bool wgdf_setup(struct childdata *child)
{
	pid_t pid = mypid();
	struct genl_ctx ctx;
	struct genl_open_opts opts;
	struct nl_ctx wgdf_rtnl;
	struct nl_open_opts rtnl_opts;
	int rc;

	g_wgdf_listen_port = (__u16)(WGDF_PORT_BASE + ((unsigned)pid & 0x3fff));
	g_wgdf_peer_port   = (__u16)(g_wgdf_listen_port ^ 0x100);

	memset(&rtnl_opts, 0, sizeof(rtnl_opts));
	rtnl_opts.proto         = NETLINK_ROUTE;
	rtnl_opts.recv_timeo_us = WGDF_RECV_TIMEO_MS * 1000;
	if (nl_open(&wgdf_rtnl, &rtnl_opts) < 0)
		return false;

	rc = wgdf_create_wg0(&wgdf_rtnl, "wg0");
	if (rc != 0) {
		if (wgdf_err_unsupported(rc))
			wgdf_latch_unsupported(child, CHILDOP_LATCH_UNSUPPORTED);
		nl_close(&wgdf_rtnl);
		return false;
	}
	g_wgdf_wg_ifindex = (int)if_nametoindex("wg0");
	if (g_wgdf_wg_ifindex <= 0) {
		nl_close(&wgdf_rtnl);
		return false;
	}

	memset(&opts, 0, sizeof(opts));
	opts.family_name  = WG_GENL_NAME;
	opts.version      = WG_GENL_VERSION;
	opts.recv_timeo_s = 1;

	rc = genl_open(&ctx, &opts);
	if (rc != 0) {
		if (rc == -ENOENT || wgdf_err_unsupported(rc))
			wgdf_latch_unsupported(child, CHILDOP_LATCH_UNSUPPORTED);
		nl_close(&wgdf_rtnl);
		return false;
	}

	rc = wgdf_set_device(&ctx, g_wgdf_wg_ifindex,
			     g_wgdf_listen_port, g_wgdf_peer_port);
	genl_close(&ctx);
	if (rc != 0 && rc != -EEXIST) {
		if (wgdf_err_unsupported(rc))
			wgdf_latch_unsupported(child, CHILDOP_LATCH_UNSUPPORTED);
		nl_close(&wgdf_rtnl);
		return false;
	}

	(void)wgdf_link_up(&wgdf_rtnl, g_wgdf_wg_ifindex);
	nl_close(&wgdf_rtnl);

	g_wgdf_udp_fd = wgdf_open_udp(g_wgdf_peer_port);
	if (g_wgdf_udp_fd < 0)
		return false;

	g_wgdf_setup_done = true;
	return true;
}

/* Build one MESSAGE_DATA-shaped UDP payload in-place.  Header layout
 * mirrors drivers/net/wireguard/messages.h struct message_data:
 *   le32 header (low byte == MESSAGE_DATA, upper 3 bytes 0)
 *   le32 key_idx
 *   le64 counter
 *   u8   encrypted_data[..]
 *
 * The kernel's wg_receive_data_packet decoder strips the header,
 * looks up the receiver index against the live keypair table, and
 * dispatches to wg_packet_decrypt_worker on the per-cpu crypt queue.
 * The decrypt-then-bail path is what we're driving. */
static size_t wgdf_build_data_pkt(unsigned char *out, size_t cap)
{
	__u32 hdr = WGDF_MSG_TYPE_DATA;	/* le on x86; htole32 not in libc by default */
	__u32 key_idx;
	__u64 counter;
	size_t payload_len;
	size_t total;

	payload_len = WGDF_PAYLOAD_MIN +
		      rnd_modulo_u32(WGDF_PAYLOAD_MAX - WGDF_PAYLOAD_MIN + 1U);
	total = 16 + payload_len;
	if (total > cap)
		total = cap;
	if (total < 16)
		return 0;

	key_idx = rand32();
	counter = ++g_wgdf_counter;

	memcpy(out + 0, &hdr, sizeof(hdr));
	memcpy(out + 4, &key_idx, sizeof(key_idx));
	memcpy(out + 8, &counter, sizeof(counter));
	wgdf_fill_random(out + 16, total - 16);
	return total;
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.
 */
struct wgdf_iter_ctx {
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so wg0, the
 * genl / rtnl sockets and the UDP fd created by wgdf_setup() are
 * reaped along with the namespace.  Return value is ignored by the
 * helper.
 */
static int wireguard_decrypt_flood_in_ns(void *arg)
{
	struct wgdf_iter_ctx *ictx = (struct wgdf_iter_ctx *)arg;
	struct childdata *child = ictx->child;
	struct sockaddr_in dst;
	struct timespec gap = { .tv_sec = 0, .tv_nsec = WGDF_GAP_NS };
	unsigned char pkt[WGDF_PAYLOAD_MAX + 16];
	unsigned int i;

	if (!g_wgdf_setup_done) {
		if (!wgdf_setup(child)) {
			__atomic_add_fetch(&shm->stats.wgdf.setup_failed, 1,
					   __ATOMIC_RELAXED);
			return 0;
		}
	}
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(g_wgdf_listen_port);
	dst.sin_addr.s_addr = WGDF_LO_ADDR;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < WGDF_BURST_MAX; i++) {
		size_t len;

		/*
		 * Poll the global shutdown gate per-iteration so a Ctrl-C
		 * (shm->exit_reason flips away from STILL_RUNNING) drains
		 * the burst within one sendto+gap instead of running the
		 * full WGDF_BURST_MAX schedule.  Matches the main child
		 * dispatch loop in child.c (while exit_reason ==
		 * STILL_RUNNING).  No local fd/buffer to unwind: the UDP
		 * socket is module-static and pkt is a stack buffer.
		 */
		if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) !=
		    STILL_RUNNING)
			break;

		len = wgdf_build_data_pkt(pkt, sizeof(pkt));

		if (sendto(g_wgdf_udp_fd, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.wgdf.packets_sent, 1,
					   __ATOMIC_RELAXED);
		(void)nanosleep(&gap, NULL);
	}
	return 0;
}

bool wireguard_decrypt_flood(struct childdata *child)
{
	struct wgdf_iter_ctx ictx = { .child = child };
	int rc;

	__atomic_add_fetch(&shm->stats.wgdf.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_wireguard_decrypt_flood)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, wireguard_decrypt_flood_in_ns,
			      &ictx);
	if (rc == -EPERM) {
		wgdf_latch_unsupported(child, CHILDOP_LATCH_NS_UNSUPPORTED);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.wgdf.setup_failed, 1,
				   __ATOMIC_RELAXED);
		return true;
	}

	return true;
}

#else  /* !__has_include(<linux/wireguard.h>) */

bool wireguard_decrypt_flood(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.wgdf.runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.wgdf.unsupported_latched, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/wireguard.h>) */
