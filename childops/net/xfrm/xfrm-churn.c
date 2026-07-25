/*
 * xfrm_churn - XFRM/IPsec SA + SP lifecycle churn under live ESP traffic.
 *
 * Targets "SA refcount unbalanced when UPDSA / DELSA races a live ESP
 * encrypt" -- the CVE-2023-1611 rekey UAF and CVE-2022-36879
 * xfrm_expand_policies KASAN UAF lineage.  Requires the coherent quad flat
 * fuzzing never assembles: a NEWSA, a matching NEWPOLICY, an in-flight UDP
 * burst driving __ip_local_out -> xfrm_output -> esp_output through the
 * bundle, and an UPDSA/DELSA racing that encrypt.
 *
 * Sequence per invocation inside a userns_run_in_ns grandchild (identity
 * userns + CLONE_NEWNET, _exit reaps SAs / SPs / bundle cache / sockets):
 * bring lo up (tunnel-mode outer endpoints stay in 127.0.0.0/8 so the
 * automatic loopback route covers them), open NETLINK_XFRM, XFRM_MSG_NEWSA
 * with algo rotated across xfrm_algos[] (AEAD via XFRMA_ALG_AEAD, legacy
 * AH/ESP via XFRMA_ALG_CRYPT+AUTH, IPCOMP via XFRMA_ALG_COMP), reqid
 * rotated across [1,16] to spread the bundle cache, SPI in [0x100, 0xffffff]
 * (<256 reserved), XFRM_MSG_NEWPOLICY OUT with a matching template and
 * 127.0.0.0/24 selectors, then a BUDGETED+JITTER (base 5, STORM_BUDGET_NS
 * 200 ms wall, 64-frame ceiling) sendto burst on lo, XFRM_MSG_UPDSA
 * mid-flight (rekey or SPI swap -- the rekey race window), another burst,
 * XFRM_MSG_DELSA + XFRM_MSG_DELPOLICY racing the draining encrypt.  1-in-8
 * invocations also open AF_KEY / PF_KEY_V2 and send SADB_FLUSH for ESP/AH
 * to exercise the parallel af_key dispatch on the shared SAD/SPD.
 *
 * Brick-safety: private netns only, loopback only, no host SAD/SPD ever
 * touched; all netlink+socket I/O MSG_DONTWAIT with SO_RCVTIMEO=1s.
 *
 * Latches: userns -EPERM latches the op off for the child's life.  Inside
 * the grandchild: ns_unsupported_xfrm on NETLINK_XFRM EPROTONOSUPPORT
 * (CONFIG_XFRM=n).  Per-algo latches trip on the first EFAIL for a given
 * xfrm_algos[] entry (missing crypto module).  Best-effort modprobe of the
 * named algorithm fires once per algo, latched so missing /sbin/modprobe
 * or lockdown=integrity pays the EFAIL once.
 */

#include "xfrm-churn-internal.h"
#include "userns-bootstrap.h"

#include "kernel/fcntl.h"
#include "kernel/netlink.h"
#include "kernel/socket.h"
#define XFRM_RECV_TIMEO_S	1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it.
 * Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * past the SIGALRM(1s) cap.  XFRM_PACKET_FLOOR is shared with the
 * AH+ESN sub-mode via xfrm-churn-internal.h. */
#define XFRM_PACKET_BASE	5U
#define XFRM_PACKET_CAP		64U

static const struct xfrm_algo_def xfrm_algos[] = {
	{ XFRM_ALG_AEAD,    IPPROTO_ESP, "rfc4106(gcm(aes))",  160, NULL,             0,   0,   128, "esp4" },
	{ XFRM_ALG_ESP_CBC, IPPROTO_ESP, "cbc(aes)",           128, "hmac(sha1)",     160, 96,  0,   "esp4" },
	{ XFRM_ALG_ESP_CBC, IPPROTO_ESP, "cbc(aes)",           256, "hmac(sha256)",   256, 128, 0,   "esp4" },
	{ XFRM_ALG_ESP_NULL,IPPROTO_ESP, "ecb(cipher_null)",   0,   "hmac(sha1)",     160, 96,  0,   "esp4" },
	{ XFRM_ALG_AH,      IPPROTO_AH,  NULL,                 0,   "hmac(sha256)",   256, 128, 0,   "ah4" },
	{ XFRM_ALG_AH,      IPPROTO_AH,  NULL,                 0,   "hmac(sha1)",     160, 96,  0,   "ah4" },
	{ XFRM_ALG_AH_NULL, IPPROTO_AH,  NULL,                 0,   "digest_null",    0,   0,   0,   "ah4" },
	{ XFRM_ALG_COMP,    IPPROTO_COMP,"deflate",            0,   NULL,             0,   0,   0,   "xfrm_ipcomp" },
};
#define NR_XFRM_ALGOS	ARRAY_SIZE(xfrm_algos)

/* Per-grandchild latched gates.  Inherited as false at grandchild
 * fork time (the persistent child never writes them -- the in-ns
 * callback runs exclusively in transient grandchildren) and flipped
 * on the first config-absent rejection from the corresponding
 * subsystem.  Die with the grandchild on _exit(); each subsequent
 * grandchild re-discovers the latch in its own fresh netns.  The
 * EPROTONOSUPPORT / EAFNOSUPPORT detection arms are preserved
 * because a fresh user namespace cannot manufacture an absent kernel
 * CONFIG -- the gate still short-circuits the rest of the
 * grandchild's iteration once it fires. */
static bool ns_unsupported_xfrm;
static bool ns_unsupported_inet;
static bool ns_unsupported_pfkey;

/* Per-algo latches: indexed by xfrm_algos[].  Set on first NEWSA
 * rejection with EOPNOTSUPP / EAFNOSUPPORT / ENOENT — the next
 * iteration skips that algo in the rotation.  Per-grandchild like
 * the gates above; modprobe_tried_algo[] is therefore re-armed in
 * each fresh grandchild and each algo's modname pays at most one
 * try_modprobe() per grandchild. */
static bool ns_unsupported_algo[NR_XFRM_ALGOS];
static bool modprobe_tried_algo[NR_XFRM_ALGOS];

static bool lo_brought_up;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gates
 * above die with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent invocations. */
static bool ns_unsupported_xfrm_churn;

static void warn_once_unsupported_xfrm_churn(const char *reason, int err)
{
	if (ns_unsupported_xfrm_churn)
		return;
	ns_unsupported_xfrm_churn = true;
	/* check-static: child-output-ok */
	outputerr("xfrm_churn: %s failed (errno=%d), latching unsupported_xfrm_churn\n",
		  reason, err);
}

/*
 * Per-child latch for iptfs-mode SA support.  CONFIG_XFRM_IPTFS is
 * compiled out unless CONFIG_XFRM_IPTFS is set; where it is, it
 * lights up and the bursts route through xfrm_iptfs.c
 * (iptfs_output -> iptfs_output_queued -> iptfs_consume_frags) ahead
 * of the ESP encrypt.  First NEWSA rejection sets this latch so
 * subsequent install_sa invocations skip the iptfs coin without
 * re-paying the EFAIL.
 */
static bool ns_unsupported_iptfs;

/*
 * Per-child latch for SO_ZEROCOPY support on the inner UDP socket.
 * setsockopt rejection is static for the kernel's lifetime
 * (CONFIG_MSG_ZEROCOPY off / kernel < 5.0 / lockdown variant) so we
 * pay the EFAIL once and then skip the zerocopy branch entirely.  The
 * regular copying sendto path remains available unchanged.
 */
static bool ns_unsupported_zerocopy;

/*
 * Sequence counter for the PF_KEYv2 alt path only.  PF_KEY is not
 * netlink so the shared nl_ctx counter doesn't apply; this monotonic
 * counter keeps sadb_msg_seq values varying across calls without
 * pretending the kernel needs them to match request/response pairs
 * (we never read the reply).
 */
static __u32 g_pfkey_seq;

static void modprobe_algo(unsigned int idx)
{
	if (modprobe_tried_algo[idx])
		return;
	modprobe_tried_algo[idx] = true;
	if (xfrm_algos[idx].modname)
		try_modprobe(xfrm_algos[idx].modname);
}

/*
 * Bring lo up inside the private netns.  IPsec on lo with transport-
 * or tunnel-mode SAs gives us a self-contained data plane that drives
 * xfrm_lookup_with_ifid -> esp_output without needing explicit
 * routes (tunnel-mode SAs keep outer endpoints on 127.0.0.0/8 and
 * rely on the kernel's automatic loopback route).  Failures are
 * ignored — the rest of the sequence will fail visibly if rtnl is
 * genuinely broken.
 */
/*
 * Pick a random algo index that isn't latched-off.  Returns
 * NR_XFRM_ALGOS if every algo is latched (caller bails out).
 */
static unsigned int pick_algo_idx(void)
{
	unsigned int start = rnd_modulo_u32(NR_XFRM_ALGOS);
	unsigned int i;

	for (i = 0; i < NR_XFRM_ALGOS; i++) {
		unsigned int idx = (start + i) % NR_XFRM_ALGOS;

		if (!ns_unsupported_algo[idx])
			return idx;
	}
	return NR_XFRM_ALGOS;
}

/*
 * Map a kernel error to a "module / config unsupported" verdict.
 * EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT / ENOENT are the
 * typical rejections from the kernel for an unknown crypto module
 * after request_module fails or for a missing CONFIG_XFRM_*.
 * EINVAL is excluded — most algo / template parameter mismatches
 * surface as EINVAL and are not module-missing signals.
 */
static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

/*
 * Build and send one SADB_FLUSH for the given satype on an already-open
 * PF_KEYv2 socket.  PF_KEYv2 is not netlink, so the bumped g_pfkey_seq
 * keeps message seq values varying without pretending to match
 * request/response pairs (we never read the reply).
 */
static void pfkey_flush_one(int s, __u8 satype)
{
	struct sadb_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.sadb_msg_version  = PF_KEY_V2;
	msg.sadb_msg_type     = SADB_FLUSH;
	msg.sadb_msg_satype   = satype;
	msg.sadb_msg_len      = sizeof(msg) / 8;
	msg.sadb_msg_seq      = ++g_pfkey_seq;
	msg.sadb_msg_pid      = (__u32)mypid();
	if (send(s, &msg, sizeof(msg), MSG_DONTWAIT) > 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn.pfkey_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * PF_KEYv2 alt path: open AF_KEY socket and emit a SADB_FLUSH for
 * ESP and AH.  Drives net/key/af_key.c dispatch + flush paths that
 * share the SAD / SPD with the netlink_xfrm side.  Latched on first
 * EAFNOSUPPORT / EPROTONOSUPPORT (kernel without CONFIG_NET_KEY).
 */
static void pfkey_flush_burst(struct childdata *child)
{
	int s;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_pfkey)
		return;

	s = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);
	if (s < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			ns_unsupported_pfkey = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}

	pfkey_flush_one(s, SADB_SATYPE_ESP);
	pfkey_flush_one(s, SADB_SATYPE_AH);

	close(s);
}

/*
 * Per-child latch for the setsockopt(IP_XFRM_POLICY / IPV6_XFRM_POLICY)
 * path.  Both sockopts route through xfrm_user_policy(), which is
 * plumbed through PF_KEYv2's compile_policy for the actual parse; a
 * kernel built without CONFIG_NET_KEY has no compile_policy registered
 * and every attempt returns EINVAL early.  Latched on the first
 * EOPNOTSUPP / EPROTONOSUPPORT / ENOPROTOOPT so subsequent iterations
 * don't burn a socket + connect + setsockopt round for nothing.
 */
static bool ns_unsupported_sk_xfrm_policy;

/* IP_XFRM_POLICY / IPV6_XFRM_POLICY sockopts and the sadb_x_policy
 * IPSEC_* / DIR_* / TYPE_* vocabulary.  UAPI-stable IDs; shims here
 * keep the build working on stripped sysroots without <linux/in.h> or
 * <linux/ipsec.h>. */
#ifndef IP_XFRM_POLICY
#define IP_XFRM_POLICY			17
#endif
#ifndef IPV6_XFRM_POLICY
#define IPV6_XFRM_POLICY		35
#endif
#ifndef SADB_X_EXT_POLICY
#define SADB_X_EXT_POLICY		18
#endif
#define SK_XFRM_IPSEC_DIR_IN		1
#define SK_XFRM_IPSEC_DIR_OUT		2
#define SK_XFRM_IPSEC_DIR_FWD		3
#define SK_XFRM_IPSEC_TYPE_DISCARD	0
#define SK_XFRM_IPSEC_TYPE_NONE		1
#define SK_XFRM_IPSEC_TYPE_BYPASS	4

/* Kernel enforces optlen <= PAGE_SIZE in xfrm_user_policy(); larger
 * blobs short-circuit at the length check before any parse or
 * sk_dst_cache touch.  Cap the buffer at page-plus so an oversized
 * rotation lands the EMSGSIZE reject arm intentionally. */
#define SK_POLICY_BUF_BYTES		(4096U + 64U)

/* sadb_x_policy layout is fixed at 16 bytes since RFC 2367; matches the
 * kernel's struct sadb_x_policy byte-for-byte.  Duplicated as a shim
 * because pfkeyv2.h on stripped sysroots may not carry the packed
 * layout, and pfkey_flush_burst() above only touches struct sadb_msg. */
struct sk_xfrm_sadb_x_policy {
	__u16	len;
	__u16	exttype;
	__u16	type;
	__u8	dir;
	__u8	reserved;
	__u32	id;
	__u32	priority;
};

/*
 * Encode one sadb_x_policy at buf[0].  Returns the number of bytes
 * written -- always 16 for the fixed layout when buf is large enough,
 * 0 otherwise.  Direction / type are rotated by the caller so the
 * kernel-side parse reaches both the accepted (dir in {IN,OUT}, type
 * BYPASS/DISCARD/NONE) and the rejected (dir == 0/5, type garbage)
 * arms of pfkey_compile_policy.
 */
static size_t build_sk_policy_blob(unsigned char *buf, size_t cap,
				   __u8 dir, __u16 type)
{
	struct sk_xfrm_sadb_x_policy *p;

	if (cap < sizeof(*p))
		return 0;

	memset(buf, 0, sizeof(*p));
	p = (struct sk_xfrm_sadb_x_policy *)buf;
	p->len      = sizeof(*p) / 8;	/* pfkey length in 8-octet units */
	p->exttype  = SADB_X_EXT_POLICY;
	p->type     = type;
	p->dir      = dir;
	p->id       = 0;
	p->priority = 0;
	return sizeof(*p);
}

/*
 * Drive the socket-attached xfrm policy path (net/xfrm/xfrm_state.c:
 * xfrm_user_policy) through both the accepted-and-inserted branch and
 * the rejection branches on a UDP socket whose sk_dst_cache has been
 * primed by connect().  Sequence per invocation:
 *
 *   1. Open AF_INET or AF_INET6 UDP socket (rotated).
 *   2. connect() to 127.0.0.1 / ::1 -- kernel resolves and stashes the
 *      dst on sk_dst_cache, so any subsequent policy insert has to
 *      reset it.
 *   3. Rotate several setsockopt(IP_XFRM_POLICY / IPV6_XFRM_POLICY)
 *      calls covering (dir, type, length) triples: well-formed
 *      IN/OUT+BYPASS/DISCARD/NONE (compile succeeds -> insert ->
 *      sk_dst_reset); dir=0/5 or type=99 (compile rejects with EINVAL
 *      after the memdup); optlen=0 and optlen>PAGE_SIZE (rejected at
 *      the sock-layer length check before any parse).  Two cycles per
 *      invocation so the accepted insert -> reject -> replace path
 *      runs at least once per iteration.
 *   4. close() -- runs __sk_destruct -> xfrm_sk_free_policy over any
 *      still-attached policy while the cached dst is stale.
 *
 * All setsockopt calls are best-effort: parse/length rejections are
 * silently absorbed -- the coverage value is in the kernel-side walk
 * they trigger, not the userland verdict.  Only permanent-unsupported
 * errnos flip the latch and skip subsequent iterations.  The (fresh
 * netns, transient socket) frame contains everything this helper
 * touches.
 */
static void xfrm_sk_policy_churn(struct childdata *child)
{
	unsigned char buf[SK_POLICY_BUF_BYTES];
	struct sockaddr_in dst4;
	struct sockaddr_in6 dst6;
	const struct sockaddr *dst;
	socklen_t dstlen;
	int fd, family, level, opt, i;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_sk_xfrm_policy || ns_unsupported_inet)
		return;

	family = ONE_IN(2) ? AF_INET6 : AF_INET;
	fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;

	if (family == AF_INET6) {
		memset(&dst6, 0, sizeof(dst6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_addr   = in6addr_loopback;
		dst6.sin6_port   = htons(XFRM_INNER_PORT);
		dst    = (struct sockaddr *)&dst6;
		dstlen = sizeof(dst6);
		level  = IPPROTO_IPV6;
		opt    = IPV6_XFRM_POLICY;
	} else {
		memset(&dst4, 0, sizeof(dst4));
		dst4.sin_family      = AF_INET;
		dst4.sin_addr.s_addr = XFRM_DADDR_BE;
		dst4.sin_port        = htons(XFRM_INNER_PORT);
		dst    = (struct sockaddr *)&dst4;
		dstlen = sizeof(dst4);
		level  = IPPROTO_IP;
		opt    = IP_XFRM_POLICY;
	}

	/* connect(): populate sk_dst_cache so the subsequent policy
	 * insert has a cached dst to reset.  Ignore return value --
	 * even an ECONNREFUSED-shaped path leaves sk_dst set on the
	 * kernel side. */
	(void)connect(fd, dst, dstlen);

	/* Two setsockopt rotations per invocation.  Independent
	 * (dir, type, length) draws so an accepted insert (which sets
	 * up sk_policy[dir]) can be immediately re-hit with an accepted
	 * replace or a rejected retry against the still-attached
	 * policy. */
	for (i = 0; i < 2; i++) {
		static const __u8  dirs[]  = {
			SK_XFRM_IPSEC_DIR_IN, SK_XFRM_IPSEC_DIR_OUT,
			SK_XFRM_IPSEC_DIR_FWD, 0, 5,
		};
		static const __u16 types[] = {
			SK_XFRM_IPSEC_TYPE_BYPASS,
			SK_XFRM_IPSEC_TYPE_DISCARD,
			SK_XFRM_IPSEC_TYPE_NONE,
			99,
		};
		size_t len;
		int rc;

		switch (rand32() & 7U) {
		case 0:  len = 0; break;
		case 1:  len = sizeof(buf); break;	/* > PAGE_SIZE arm */
		default:
			len = build_sk_policy_blob(buf, sizeof(buf),
						   RAND_ARRAY(dirs),
						   RAND_ARRAY(types));
			break;
		}

		if (len == 0) {
			rc = setsockopt(fd, level, opt, NULL, 0);
		} else {
			if (len > sizeof(buf))
				len = sizeof(buf);
			rc = setsockopt(fd, level, opt, buf, len);
		}

		if (rc == 0) {
			/* Accepted inserts share the xfrm_churn_pol_added
			 * counter with the netlink NEWPOLICY path: both are
			 * an SPD-visible policy install by the time the
			 * kernel returns success. */
			__atomic_add_fetch(&shm->stats.xfrm_churn.pol_added,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
			   errno == ENOPROTOOPT) {
			ns_unsupported_sk_xfrm_policy = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			break;
		}
	}

	close(fd);
}

/*
 * Defensive sweep of the netlink_xfrm opcode space, targeting off-end
 * indexing in net/xfrm/xfrm_compat.c::xfrm_msg_min[] and the broader
 * xfrm_user dispatch.  Pre-fix (upstream 28465227c80f) the compat
 * translation table was sized only through XFRM_MSG_GETAE while the
 * UAPI grew XFRM_MSG_MAPPING; a 32-bit task issuing MAPPING walked
 * off the end reading garbage.  A 64-bit-only fuzz binary doesn't
 * itself enter the compat translator, but iterating the full
 * XFRM_MSG_BASE..XFRM_MSG_MAX range exercises every kernel-side
 * dispatch slot, catching any later off-end index added since.
 *
 * Per-iteration: rebuild a minimal nlmsghdr with a fixed 64-byte
 * payload tail (small enough not to exceed any opcode's max, large
 * enough to satisfy the smaller of the 32-bit / 64-bit struct
 * minimums for most opcodes), sendto the bound NETLINK_XFRM fd
 * MSG_DONTWAIT, drain at most one reply per send.  Most opcodes
 * reject with EINVAL / E2BIG / EOPNOTSUPP — that's fine, the
 * dispatch slot lookup happens before the validation that emits the
 * rejection.  All I/O is non-blocking so the inner loop can't stall
 * past the SIGALRM(1s) cap.
 */
static void xfrm_compat_msg_sweep(struct nl_ctx *ctx)
{
	struct sockaddr_nl dst;
	unsigned char buf[256];
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	unsigned int t;
	size_t off;
	ssize_t n;

	if (ns_unsupported_xfrm)
		return;

	__atomic_add_fetch(&shm->stats.xfrm_compat.sweep_runs,
			   1, __ATOMIC_RELAXED);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	for (t = XFRM_MSG_NEWSA; t <= XFRM_COMPAT_SWEEP_MAX; t++) {
		memset(buf, 0, sizeof(buf));
		nlh = (struct nlmsghdr *)buf;
		nlh->nlmsg_type  = (__u16)t;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		nlh->nlmsg_seq   = nl_seq_next(ctx);
		off = NLMSG_HDRLEN + NLMSG_ALIGN(64);
		nlh->nlmsg_len   = (__u32)off;

		if (sendto(ctx->fd, buf, off, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			__atomic_add_fetch(&shm->stats.xfrm_compat.sends_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}
		__atomic_add_fetch(&shm->stats.xfrm_compat.sends_ok,
				   1, __ATOMIC_RELAXED);

		n = recv(ctx->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n > 0)
			__atomic_add_fetch(&shm->stats.xfrm_compat.replies_seen,
					   1, __ATOMIC_RELAXED);
	}
}

/*
 * Burn-this-netns mode: rare branch (ONE_IN(BURN_GATE_DENOM) at the
 * top of xfrm_churn) that races cleanup_net's xfrm_state_flush against
 * the byseq/byspi chains we just populated.  Mechanics:
 *
 *   1. Open /proc/self/ns/net as the anchor before any unshare.
 *   2. Acquire one ticket from shm->newnet_in_flight under
 *      MAX_CONCURRENT_NEWNET; bail if cap reached (mirrors the
 *      sanitise_unshare bookkeeping in syscalls/unshare.c).
 *   3. unshare(CLONE_NEWNET) into a fresh sub-netns.
 *   4. Open NETLINK_XFRM, install one SA via NEWSA with non-zero
 *      seq + spi (so the SA links onto BOTH byseq and byspi), then
 *      back-to-back fire build_sa_id_msg(GETSA) (drives __xfrm_state_lookup
 *      byspi walker) and build_allocspi (drives __xfrm_find_acq_byseq +
 *      xfrm_state_lookup_byspi during the SPI scan + a larval insert).
 *   5. close(xfrm_fd) so the only remaining sock_net ref drops, then
 *      setns back to the anchor and close it.  With no refs left on
 *      the sub-netns, cleanup_net schedules its workqueue:
 *      xfrm_state_flush walks byseq + byspi while another CPU may
 *      still be in the lookup walker we kicked off.  Race window is
 *      the bug-class fixed by upstream 14acf9652e56.
 *   6. Drop the ticket.
 *
 * On any setup failure past the unshare we still try to setns back so
 * the trinity child isn't stranded in a doomed sub-netns; the ticket
 * is always dropped.  Returns true if the burn attempt was launched
 * (caller should short-circuit), false if we bailed before unshare so
 * caller can fall through to the normal flow.
 */
#define XFRM_BURN_GATE_DENOM	64U

static bool xfrm_burn_netns(void)
{
	struct nl_ctx burn_ctx = { .fd = -1 };
	struct nl_open_opts burn_opts = {
		.proto        = NETLINK_XFRM,
		.recv_timeo_s = XFRM_RECV_TIMEO_S,
	};
	int anchor = -1;
	unsigned int aidx;
	const struct xfrm_algo_def *def;
	__u32 reqid, seq;
	__be32 spi;
	bool ticketed = false;

	__atomic_add_fetch(&shm->stats.xfrm_churn.burn_runs, 1,
			   __ATOMIC_RELAXED);

	aidx = pick_algo_idx();
	if (aidx >= NR_XFRM_ALGOS)
		return false;
	def = &xfrm_algos[aidx];

	anchor = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (anchor < 0)
		return false;

	if (!try_admit_newnet()) {
		__atomic_add_fetch(&shm->stats.xfrm_churn.burn_throttled, 1,
				   __ATOMIC_RELAXED);
		close(anchor);
		return false;
	}
	ticketed = true;

	if (unshare(CLONE_NEWNET) < 0)
		goto out;

	if (nl_open(&burn_ctx, &burn_opts) < 0)
		goto out;

	reqid = (rand32() % XFRM_REQID_RANGE) + 1U;
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
	/* Force seq != 0 in the burn branch -- the whole point is to
	 * have the SA on byseq when xfrm_state_flush runs. */
	seq   = (rand32() & 0xffffU) | 1U;

	modprobe_algo(aidx);
	if (build_sa_msg(&burn_ctx, XFRM_MSG_NEWSA, def, reqid, spi,
			 XFRM_MODE_TRANSPORT, seq) != 0)
		goto out;

	(void)build_sa_id_msg(&burn_ctx, XFRM_MSG_GETSA, def->proto, spi);
	(void)build_allocspi(&burn_ctx, def, reqid, XFRM_MODE_TRANSPORT, seq);

	__atomic_add_fetch(&shm->stats.xfrm_churn.burn_completed, 1,
			   __ATOMIC_RELAXED);

out:
	nl_close(&burn_ctx);
	if (anchor >= 0) {
		(void)setns(anchor, CLONE_NEWNET);
		close(anchor);
	}
	if (ticketed)
		__atomic_fetch_sub(&shm->newnet_in_flight, 1,
				   __ATOMIC_RELAXED);
	return true;
}

/*
 * Per-invocation state for xfrm_churn.  Lifted out so the phase
 * helpers can reach the netlink_xfrm fd, the UDP fd, and the SA
 * descriptor (algo + reqid + spi + mode + seq) without a wide
 * parameter list.
 */
struct xfrm_churn_iter_ctx {
	struct nl_ctx nl;
	int udp;
	unsigned int aidx;
	const struct xfrm_algo_def *def;
	__u32 reqid;
	__be32 spi;
	__u8 mode;
	__u32 seq;
	struct childdata *child;
};

/*
 * Phase: bring lo up and open NETLINK_XFRM inside the grandchild's
 * private netns.  The netns itself is set up by userns_run_in_ns()
 * before the in-ns callback runs, so this helper only has to bring
 * lo up (per-grandchild one-time) and open the netlink_xfrm fd.
 * Latches ns_unsupported_xfrm on the EPROTONOSUPPORT / EAFNOSUPPORT
 * CONFIG_XFRM-absent shape so the rest of the grandchild's iteration
 * pays the EFAIL once.  Returns 0 on success; -1 means caller should
 * return without entering the goto-out cleanup.
 */
static int xfrm_churn_iter_setup_netns(struct xfrm_churn_iter_ctx *ctx)
{
	struct nl_open_opts opts = {
		.proto        = NETLINK_XFRM,
		.recv_timeo_s = XFRM_RECV_TIMEO_S,
	};

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (!lo_brought_up) {
		struct nl_ctx rtnl = { .fd = -1 };
		struct nl_open_opts rtnl_opts = {
			.proto        = NETLINK_ROUTE,
			.recv_timeo_s = XFRM_RECV_TIMEO_S,
		};

		if (nl_open(&rtnl, &rtnl_opts) == 0) {
			rtnl_bring_lo_up(&rtnl);
			nl_close(&rtnl);
		}
		lo_brought_up = true;
	}

	if (nl_open(&ctx->nl, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			ns_unsupported_xfrm = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.xfrm_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}

	return 0;
}

/*
 * Phase: pick an algo + install the SA + matching policy.  Rotates
 * reqid / spi / seq / mode per call, modprobes the named algorithm on
 * first touch, and latches ns_unsupported_algo[aidx] when the kernel
 * doesn't carry the crypto module.  Returns 0 when the SA is live;
 * non-zero means caller should goto out (no SA was installed so the
 * teardown side has nothing useful to do, but the netlink fd still
 * needs closing).
 */
static int xfrm_churn_iter_install_sa(struct xfrm_churn_iter_ctx *ctx)
{
	int rc;

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	ctx->aidx = pick_algo_idx();
	if (ctx->aidx >= NR_XFRM_ALGOS)
		return -1;

	ctx->def   = &xfrm_algos[ctx->aidx];
	ctx->reqid = (rand32() % XFRM_REQID_RANGE) + 1U;
	ctx->spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
	ctx->seq   = pick_sa_seq();
	/* Rotate transport / tunnel mode per iteration.  Tunnel mode
	 * walks a distinct esp_output path: the inner IP header is
	 * encapsulated by xfrm4_tunnel_output / xfrm6_tunnel_output
	 * before the ESP encrypt, exercising the outer-header build,
	 * the per-mode skb_cow/expand-head sizing, and (combined with
	 * the MSG_ZEROCOPY variant) the shared-frag/COW decision under
	 * tunnel encap rather than transport.  Outer SA addresses stay
	 * on 127.0.0.0/8 -- the kernel's automatic loopback route
	 * covers tunnel-mode delivery without needing an explicit
	 * route install.  Tunnel selected ~half the time so transport
	 * coverage is preserved unchanged; build_sa_msg /
	 * build_newpolicy already take mode as a parameter and the
	 * template's tmpl->mode mirrors it. */
	ctx->mode  = ONE_IN(2) ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;

	/* iptfs sub-mode: ~1 in 8 install attempts override the chosen
	 * mode to XFRM_MODE_IPTFS when the picked algo is AEAD (iptfs
	 * SAs only accept AEAD constructions and EINVAL otherwise).
	 * iptfs lives in xfrm_iptfs.c -- iptfs_output_queued aggregates
	 * multiple inner packets' frags into one outer ESP skb, and
	 * iptfs_consume_frags is the exact site upstream e9096a5a170e
	 * patches for SKBFL_SHARED_FRAG-loss on frag merge.  Reachable
	 * only when CONFIG_XFRM_IPTFS is on (absent on kernels built
	 * without it; present where it is enabled).  Latched per
	 * child on first rejection so the EFAIL is paid once. */
	if (ctx->def->kind == XFRM_ALG_AEAD &&
	    !ns_unsupported_iptfs && ONE_IN(8))
		ctx->mode = XFRM_MODE_IPTFS;

	modprobe_algo(ctx->aidx);
	rc = build_sa_msg(&ctx->nl, XFRM_MSG_NEWSA, ctx->def, ctx->reqid,
			  ctx->spi, ctx->mode, ctx->seq);
	if (rc != 0) {
		if (ctx->mode == XFRM_MODE_IPTFS) {
			/* iptfs reject says nothing about the AEAD algo's
			 * availability -- only that this kernel doesn't
			 * carry CONFIG_XFRM_IPTFS or that iptfs_create_state
			 * rejected our SA shape.  Latch the iptfs branch
			 * off, leave the algo latch alone so transport /
			 * tunnel AEAD installs keep working. */
			ns_unsupported_iptfs = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
			return -1;
		}
		if (is_unsupported_err(rc))
			ns_unsupported_algo[ctx->aidx] = true;
		return -1;
	}
	__atomic_add_fetch(&shm->stats.xfrm_churn.sa_added,
			   1, __ATOMIC_RELAXED);
	if (ctx->mode == XFRM_MODE_TUNNEL)
		__atomic_add_fetch(&shm->stats.xfrm_churn.tunnel_sa_added,
				   1, __ATOMIC_RELAXED);
	else if (ctx->mode == XFRM_MODE_IPTFS)
		__atomic_add_fetch(&shm->stats.xfrm_churn.iptfs_sa_added,
				   1, __ATOMIC_RELAXED);

	rc = build_newpolicy(&ctx->nl, ctx->def, ctx->reqid, ctx->spi,
			     ctx->mode);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.xfrm_churn.pol_added,
				   1, __ATOMIC_RELAXED);
	}

	return 0;
}

/*
 * Phase: open the inner-traffic UDP socket on 127.0.0.1.  Latches
 * ns_unsupported_inet on EAFNOSUPPORT / EPROTONOSUPPORT so the rest
 * of the child's lifetime skips the socket() syscall.  Best-effort:
 * a failed bind leaves ctx->udp open with an ephemeral source so the
 * caller can still drive sendto bursts through the SA.
 */
static void xfrm_churn_iter_setup_udp(struct xfrm_churn_iter_ctx *ctx)
{
	struct sockaddr_in src;
	int one = 1;

	/* Snapshot ctx->child->op_type once and bounds-check before
	 * indexing the per-op latch slot.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; the child.c dispatch loop already gates its dispatch
	 * + alt-op accounting on the same valid_op snapshot.  Skip the
	 * latch store entirely when the snapshot is out of range. */
	const enum child_op_type op = ctx->child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_inet)
		return;

	ctx->udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ctx->udp < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			ns_unsupported_inet = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}

	memset(&src, 0, sizeof(src));
	src.sin_family      = AF_INET;
	src.sin_addr.s_addr = XFRM_SADDR_BE;
	(void)bind(ctx->udp, (struct sockaddr *)&src, sizeof(src));

	/* Arm the socket for MSG_ZEROCOPY so drive_inner_traffic_zc can
	 * pin payload pages into skb frags (sets SKBFL_SHARED_FRAG on
	 * the inner skb, the precondition for the shared-frag/COW
	 * branch in esp_output).  EOPNOTSUPP / ENOPROTOOPT here means
	 * the kernel doesn't carry MSG_ZEROCOPY on UDP — pre-v5.0 or
	 * built-out config.  Latch per-child so subsequent iterations
	 * keep this fd as copying-sendto only without re-paying the
	 * EFAIL; the burst dispatcher checks the latch before rolling
	 * the zerocopy coin. */
	if (!ns_unsupported_zerocopy &&
	    setsockopt(ctx->udp, SOL_SOCKET, SO_ZEROCOPY,
		       &one, sizeof(one)) < 0)
		ns_unsupported_zerocopy = true;
}

/*
 * Phase: drive one BUDGETED + JITTER + cap-clamped sendto burst
 * through the live SA on the UDP socket.  No-op when the UDP socket
 * never came up.  Each call captures its own CLOCK_MONOTONIC anchor
 * for drive_inner_traffic's STORM_BUDGET_NS wall-cap; the second
 * call rolls a fresh iters count so the post-rekey burst doesn't
 * inherit the first burst's size.
 */
static void xfrm_churn_iter_drive_burst(struct xfrm_churn_iter_ctx *ctx)
{
	struct timespec t0;
	unsigned int iters, sent;

	if (ctx->udp < 0)
		return;

	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	iters = BUDGETED(CHILD_OP_XFRM_CHURN,
			 JITTER_RANGE(XFRM_PACKET_BASE));
	if (iters < XFRM_PACKET_FLOOR)
		iters = XFRM_PACKET_FLOOR;
	if (iters > XFRM_PACKET_CAP)
		iters = XFRM_PACKET_CAP;

	/* Predominantly copying-sendto (preserves the proven UPDSA/DELSA
	 * race timing the op exists for); ~1 in 8 bursts switches to
	 * MSG_ZEROCOPY so the inner skb carries SKBFL_SHARED_FRAG and
	 * esp_output enters the skb_cow_data() branch (esp4.c:876) that
	 * the copying path never reaches.  Two burst calls per
	 * invocation roll the coin independently, so effective coverage
	 * is ~1 in 4 iterations per child — sparse enough that the
	 * zerocopy errqueue drain can't perturb the rekey race window,
	 * dense enough that the COW branch is reached steadily. */
	if (!ns_unsupported_zerocopy && ONE_IN(8))
		sent = drive_inner_traffic_zc(ctx->udp, iters, &t0);
	else
		sent = drive_inner_traffic(ctx->udp, iters, &t0);
	if (sent)
		__atomic_add_fetch(&shm->stats.xfrm_churn.esp_sent,
				   sent, __ATOMIC_RELAXED);
}

/*
 * Phase: mid-flow rekey -- rotate the SA's key + SPI on the same
 * (reqid, spi, proto) shell racing the in-flight encrypt from the
 * preceding burst.  ONE_IN(8) GETSA-by-SPI + ONE_IN(8) ALLOCSPI prep
 * the byseq / byspi reader windows; UPDSA is the actual rotation
 * (CVE-2023-1611 family target).
 */
static void xfrm_churn_iter_rekey(struct xfrm_churn_iter_ctx *ctx)
{
	int rc;

	/*
	 * Lookup-side reader: GETSA-by-SPI walks
	 * __xfrm_state_lookup -> byspi while the SA is live.  ONE_IN(8)
	 * keeps the netlink chatter bounded; the kernel-side hash walk
	 * happens before the reply is composed so even a recv() short-
	 * read still drives the bug-class window.
	 */
	if (ONE_IN(8))
		(void)build_sa_id_msg(&ctx->nl, XFRM_MSG_GETSA,
				      ctx->def->proto, ctx->spi);

	/*
	 * Second writer onto byspi: ALLOCSPI on a half-built SA with the
	 * same rotated reqid + seq.  Walks __xfrm_find_acq_byseq +
	 * xfrm_state_lookup_byspi during the SPI scan, then inserts a
	 * larval SA onto byspi.  ONE_IN(8) bounds cost and keeps the
	 * larval-SA accumulator from saturating the per-netns table.
	 */
	if (ONE_IN(8))
		(void)build_allocspi(&ctx->nl, ctx->def, ctx->reqid,
				     ctx->mode, ctx->seq);

	rc = build_sa_msg(&ctx->nl, XFRM_MSG_UPDSA, ctx->def, ctx->reqid,
			  ctx->spi, ctx->mode, ctx->seq);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.xfrm_churn.sa_updated,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: SA + policy teardown, then the rare side-path syscalls.
 * DELSA + DELPOLICY race the in-flight encrypt still draining from
 * the post-rekey burst (CVE-2022-36879 lineage).  The three
 * sub-mode gates after that exercise distinct codepaths sharing the
 * SAD/SPD with the netlink_xfrm dispatch we just used: AH+ESN+async
 * (~1/4), PF_KEYv2 flush (~1/8), compat-table opcode sweep (~1/8).
 */
static void xfrm_churn_iter_teardown_sa(struct xfrm_churn_iter_ctx *ctx)
{
	/*
	 * Tear the SA down racing the in-flight encrypt still draining
	 * from the second burst.  Cascades cleanup of the bundle cache
	 * via xfrm_state_delete -> __xfrm_state_destroy — the primary
	 * teardown-vs-traffic window the op exists to open.
	 */
	if (build_sa_id_msg(&ctx->nl, XFRM_MSG_DELSA,
			    ctx->def->proto, ctx->spi) == 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn.sa_deleted,
				   1, __ATOMIC_RELAXED);

	if (build_delpolicy(&ctx->nl) == 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn.pol_deleted,
				   1, __ATOMIC_RELAXED);

	/* AH+ESN+async-hash sub-mode: ~1 in 4 invocations installs an
	 * AH SA with the (XFRM_STATE_ESN | replay-window | async-friendly
	 * auth name) trifecta required to reach the codepath upstream
	 * commit ec54093e6a8f patches. */
	if ((rand32() & 3U) == 0)
		install_ah_esn_async_sa(&ctx->nl, ctx->udp, ctx->child);

	/* PF_KEYv2 alt path: ~1 in 8 invocations exercises the parallel
	 * af_key dispatch + flush paths that share the SAD/SPD with
	 * netlink_xfrm. */
	if ((rand32() & 7U) == 0)
		pfkey_flush_burst(ctx->child);

	/* Per-sk xfrm policy path: ~1 in 8 invocations opens a fresh UDP
	 * sock, connects to prime sk_dst_cache, walks setsockopt(
	 * IP_XFRM_POLICY / IPV6_XFRM_POLICY) through both accepted and
	 * rejected (dir, type, length) triples so xfrm_user_policy's
	 * memdup / compile / insert / sk_dst_reset arms all take turns,
	 * then close()s while dst is stale.  Cheap; no shared state with
	 * the netlink-visible SAD/SPD side. */
	if ((rand32() & 7U) == 0)
		xfrm_sk_policy_churn(ctx->child);

	/* Compat-table off-end-read sweep: ~1 in 8 invocations iterates
	 * the full XFRM_MSG_BASE..XFRM_MSG_MAX opcode range against the
	 * already-open netlink_xfrm fd.  Targets the bug class fixed by
	 * upstream 28465227c80f (missing xfrm_msg_min[] entry for
	 * XFRM_MSG_MAPPING) and any later off-end indices added since. */
	if (ONE_IN(8))
		xfrm_compat_msg_sweep(&ctx->nl);
}

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so any SA, SP,
 * bundle-cache entry, dummy / veth link and socket left behind is
 * reaped along with the namespace.  Explicit DELSA / DELPOLICY /
 * close() calls are still issued so the in-ns stats counters
 * (xfrm_churn_sa_deleted etc.) move on the success path; correctness
 * does not depend on them.  Per-grandchild latches set inside this
 * callback die with the grandchild and the per-grandchild gates above
 * are re-discovered on the next invocation -- helper-EPERM in the
 * wrapper is the only signal that survives across iterations.  Return
 * value is ignored by the helper.
 */
static int xfrm_churn_in_ns(void *arg)
{
	struct xfrm_churn_iter_ctx *ctx = (struct xfrm_churn_iter_ctx *)arg;
	struct childdata *child = ctx->child;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_xfrm)
		return 0;

	/*
	 * Burn-this-netns mode: rare branch that races cleanup_net's
	 * xfrm_state_flush against in-flight byseq/byspi readers
	 * (Phase 1 reader paths populate the chains).  Bug class fixed
	 * by upstream 14acf9652e56.  Self-contained sub-netns + setns
	 * back to anchor (the anchor here is the grandchild's own netns,
	 * not the persistent child's host netns); if launched, the rest
	 * of xfrm_churn_in_ns is skipped this invocation to avoid
	 * running the normal flow on the just-burned ns.  The
	 * grandchild's _exit() afterwards still tears down its outer
	 * netns, so cleanup_net runs once for the inner sub-netns at
	 * setns-back and again for the grandchild's netns at exit.
	 */
	if (ONE_IN(XFRM_BURN_GATE_DENOM) && xfrm_burn_netns())
		return 0;

	if (xfrm_churn_iter_setup_netns(ctx) != 0)
		return 0;

	if (xfrm_churn_iter_install_sa(ctx) != 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	xfrm_churn_iter_setup_udp(ctx);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	xfrm_churn_iter_drive_burst(ctx);
	xfrm_churn_iter_rekey(ctx);
	xfrm_churn_iter_drive_burst(ctx);
	xfrm_churn_iter_teardown_sa(ctx);

out:
	if (ctx->udp >= 0)
		close(ctx->udp);
	nl_close(&ctx->nl);

	return 0;
}

bool xfrm_churn(struct childdata *child)
{
	struct xfrm_churn_iter_ctx ctx = {
		.nl    = { .fd = -1 },
		.udp   = -1,
		.child = child,
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

	__atomic_add_fetch(&shm->stats.xfrm_churn.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_xfrm_churn)
		return true;

	rc = userns_run_in_ns(CLONE_NEWNET, xfrm_churn_in_ns, &ctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_xfrm_churn("userns_run_in_ns(CLONE_NEWNET)",
						 EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.xfrm_churn.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
