/*
 * xfrm_churn - XFRM/IPsec SA + SP lifecycle churn under live ESP traffic.
 *
 * Per-syscall fuzzing rolls a fresh netlink_xfrm message every call
 * and never assembles a coherent (SA, matching SP, traffic that hits
 * the SPD lookup) triple: XFRM_MSG_NEWSA without a matching policy is
 * inert (no output path consumes it), XFRM_MSG_NEWPOLICY without a
 * matching SA bounces off __xfrm_policy_check / xfrm_resolve_and_create_bundle
 * before any commit-time work runs, and even when both land the random
 * picker can't drive any traffic through the bundle so xfrm_state_find,
 * esp_output, xfrm_lookup_with_ifid, xfrm_state_delete-vs-lookup races
 * stay cold.  The CVE class this op exists to expose is
 * "SA refcount unbalanced when UPDSA / DELSA races a live ESP encrypt"
 * — that requires a coherent SA + matching SP + an in-flight UDP burst
 * driving the bundle + a UPDSA / DELSA racing the encrypt.  Random
 * fuzzing assembles that set ~never.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host SAD / SPD entry is touched.  Failure
 *      latches the whole op off.
 *   2. Bring lo up inside the netns (one-time).  IPsec on lo with
 *      transport-mode SAs gives us a self-contained data plane that
 *      drives xfrm_lookup_with_ifid -> esp_output without needing any
 *      routes beyond the kernel's automatic 127.0.0.0/8 entry.
 *   3. Open a NETLINK_XFRM socket.  Failure with EPROTONOSUPPORT
 *      latches ns_unsupported_xfrm — a kernel without CONFIG_XFRM
 *      pays the EFAIL once and skips for the child's lifetime.
 *   4. XFRM_MSG_NEWSA, algorithm rotated per iteration across the
 *      xfrm_algos[] table.  XFRMA_ALG_AEAD for AEAD constructions
 *      (rfc4106(gcm(aes))), XFRMA_ALG_CRYPT + XFRMA_ALG_AUTH for
 *      legacy AH/ESP, XFRMA_ALG_COMP for IPCOMP.  reqid rotates
 *      across [1, 16] to spread the per-reqid bundle cache.  random
 *      256-bit key per iteration.  random SPI in the [0x100, 0xffffff]
 *      range (kernel reserves SPI < 256).  Per-algo latches so the
 *      kernel without a particular crypto module pays the EFAIL once.
 *      A best-effort modprobe of the named algorithm fires the first
 *      time each algo is touched, latched so a missing /sbin/modprobe
 *      / no modules / lockdown=integrity costs the EFAIL once.
 *   5. XFRM_MSG_NEWPOLICY OUT direction with a matching template
 *      (xfrm_user_tmpl pointing at the SA we just installed via
 *      reqid + spi + proto + daddr).  Selector matches 127.0.0.0/24
 *      both ends so any UDP we send through lo trips the SPD lookup.
 *   6. socket(AF_INET, SOCK_DGRAM); bind to 127.0.0.1; sendto
 *      127.0.0.2 a small payload BUDGETED+JITTER times around base 5.
 *      STORM_BUDGET_NS 200 ms wall-clock cap.  Each send walks
 *      __ip_local_out -> xfrm_output -> esp_output through the freshly
 *      installed SA + SP bundle; the encrypt + ICV computation +
 *      replay-window stamp + bundle-cache update is the codepath the
 *      CVE class lives in.
 *   7. XFRM_MSG_UPDSA mid-flight: rotate the algorithm key OR change
 *      the SPI on the same SA.  This is the targeted rekey race
 *      window (CVE-2023-1611 family) — the old key's encrypt is still
 *      in flight when the UPDSA pulls it out from under any skb
 *      mid-encrypt.
 *   8. Another sendto burst — may hit stale-key encrypt path.
 *   9. XFRM_MSG_DELSA, racing the in-flight encrypt still draining
 *      from step 8.  Cascades cleanup of the bundle cache via
 *      xfrm_state_delete -> __xfrm_state_destroy.  This is the
 *      primary teardown-vs-traffic window the op exists to open
 *      (CVE-2022-36879 xfrm_expand_policies UAF lineage).
 *  10. XFRM_MSG_DELPOLICY OUT — racing the same in-flight skbs.
 *  11. PF_KEYv2 alt path (1 in 8 invocations): socket(AF_KEY,
 *      SOCK_RAW, PF_KEY_V2); send a minimal SADB_FLUSH for ESP and
 *      AH satypes.  Drives the parallel net/key/af_key.c lookup +
 *      flush paths that share the SAD / SPD with the netlink_xfrm
 *      side.  No matching SA payload — SADB_FLUSH is the smallest
 *      message that exercises the af_key dispatch and dispatcher
 *      lookup gates without needing a full SADB_ADD assembly.
 *
 * CVE class: CVE-2023-1611 (XFRM SA refcount UAF — concurrent UPDSA
 * + DELSA), CVE-2022-36879 (xfrm_expand_policies KASAN UAF — policy
 * rotation race), broader xfrm_state_find UAF family, PF_KEYv2
 * sadb_msg parsing edges in net/key/af_key.c.  Subsystems reached:
 * net/xfrm/xfrm_state.c (state add/delete/update, replay window),
 * net/xfrm/xfrm_policy.c (SPD insert/delete, bundle cache),
 * net/xfrm/xfrm_user.c (netlink_xfrm dispatch + attribute parsing),
 * net/xfrm/xfrm_output.c (output dispatch), net/ipv4/esp4.c
 * (ESP encrypt + ICV), net/ipv4/ah4.c (AH digest), net/xfrm/xfrm_ipcomp.c,
 * net/key/af_key.c (PF_KEYv2 dispatch).
 *
 * Self-bounding: one full create/encrypt/update/delete cycle per
 * invocation, packet burst BUDGETED+JITTER around base 5 with a
 * STORM_BUDGET_NS 200 ms wall-clock cap and a 64-frame ceiling on
 * the inner send loop.  All netlink and socket I/O is MSG_DONTWAIT;
 * SO_RCVTIMEO=1s on the netlink_xfrm ack socket so an unresponsive
 * kernel can't wedge us past the SIGALRM(1s) cap inherited from
 * child.c.  Loopback only (private netns).  Per-algo latches so a
 * kernel without a given crypto module pays the EFAIL once and skips
 * that algo permanently.
 */

#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif
#if __has_include(<linux/pfkeyv2.h>)
#include <linux/pfkeyv2.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * UAPI fallbacks.  xfrm.h on stripped sysroots may be absent; the
 * IDs and structure layouts are stable in the kernel UAPI.  If the
 * header is missing entirely the __has_include gate above keeps
 * compilation working and these defines fill in.  Layouts are kept
 * in sync with linux/xfrm.h as of Linux 6.18 (no breaking changes
 * since the UAPI stabilised in 2.6.x).
 */
#ifndef NETLINK_XFRM
#define NETLINK_XFRM		6
#endif

#ifndef XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSA		0x10
#define XFRM_MSG_DELSA		0x11
#define XFRM_MSG_NEWPOLICY	0x13
#define XFRM_MSG_DELPOLICY	0x14
#define XFRM_MSG_UPDSA		0x1f
#endif

#ifndef XFRMA_ALG_AUTH
#define XFRMA_ALG_AUTH		1
#define XFRMA_ALG_CRYPT		2
#define XFRMA_ALG_COMP		3
#define XFRMA_TMPL		5
#define XFRMA_ALG_AEAD		18
#endif

#ifndef XFRM_POLICY_OUT
#define XFRM_POLICY_OUT		1
#endif

#ifndef XFRM_MODE_TRANSPORT
#define XFRM_MODE_TRANSPORT	0
#define XFRM_MODE_TUNNEL	1
#endif

#ifndef XFRM_POLICY_ALLOW
#define XFRM_POLICY_ALLOW	0
#endif

#ifndef XFRM_SHARE_ANY
#define XFRM_SHARE_ANY		0
#endif

#ifndef PF_KEY_V2
#define PF_KEY_V2		2
#endif

#ifndef SADB_FLUSH
#define SADB_FLUSH		9
#endif

#ifndef SADB_SATYPE_AH
#define SADB_SATYPE_AH		2
#define SADB_SATYPE_ESP		3
#endif

/* xfrm UAPI structure layouts.  Only redefined when linux/xfrm.h is
 * absent on the build sysroot — matches the kernel layout exactly.
 * The __has_include guard above prevents redefinition when the real
 * header is present, so these are pure compile-time fallbacks. */
#if !__has_include(<linux/xfrm.h>)
typedef union {
	__be32			a4;
	__be32			a6[4];
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t		daddr;
	__be32			spi;
	__u8			proto;
};

struct xfrm_selector {
	xfrm_address_t		daddr;
	xfrm_address_t		saddr;
	__be16			dport;
	__be16			dport_mask;
	__be16			sport;
	__be16			sport_mask;
	__u16			family;
	__u8			prefixlen_d;
	__u8			prefixlen_s;
	__u8			proto;
	int			ifindex;
	__u32			user;
};

struct xfrm_lifetime_cfg {
	__u64			soft_byte_limit;
	__u64			hard_byte_limit;
	__u64			soft_packet_limit;
	__u64			hard_packet_limit;
	__u64			soft_add_expires_seconds;
	__u64			hard_add_expires_seconds;
	__u64			soft_use_expires_seconds;
	__u64			hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64			bytes;
	__u64			packets;
	__u64			add_time;
	__u64			use_time;
};

struct xfrm_stats {
	__u32			replay_window;
	__u32			replay;
	__u32			integrity_failed;
};

struct xfrm_algo {
	char			alg_name[64];
	unsigned int		alg_key_len;
	char			alg_key[];
};

struct xfrm_algo_auth {
	char			alg_name[64];
	unsigned int		alg_key_len;
	unsigned int		alg_trunc_len;
	char			alg_key[];
};

struct xfrm_algo_aead {
	char			alg_name[64];
	unsigned int		alg_key_len;
	unsigned int		alg_icv_len;
	char			alg_key[];
};

struct xfrm_usersa_info {
	struct xfrm_selector		sel;
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	struct xfrm_stats		stats;
	__u32				seq;
	__u32				reqid;
	__u16				family;
	__u8				mode;
	__u8				replay_window;
	__u8				flags;
};

struct xfrm_usersa_id {
	xfrm_address_t			daddr;
	__be32				spi;
	__u16				family;
	__u8				proto;
};

struct xfrm_userpolicy_info {
	struct xfrm_selector		sel;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	__u32				priority;
	__u32				index;
	__u8				dir;
	__u8				action;
	__u8				flags;
	__u8				share;
};

struct xfrm_userpolicy_id {
	struct xfrm_selector		sel;
	__u32				index;
	__u8				dir;
};

struct xfrm_user_tmpl {
	struct xfrm_id		id;
	__u16			family;
	xfrm_address_t		saddr;
	__u32			reqid;
	__u8			mode;
	__u8			share;
	__u8			optional;
	__u32			aalgos;
	__u32			ealgos;
	__u32			calgos;
};
#endif /* !__has_include(<linux/xfrm.h>) */

/* PF_KEYv2 sadb_msg fallback layout — stable since RFC 2367. */
#if !__has_include(<linux/pfkeyv2.h>)
struct sadb_msg {
	__u8			sadb_msg_version;
	__u8			sadb_msg_type;
	__u8			sadb_msg_errno;
	__u8			sadb_msg_satype;
	__u16			sadb_msg_len;
	__u16			sadb_msg_reserved;
	__u32			sadb_msg_seq;
	__u32			sadb_msg_pid;
};
#endif

#define XFRM_BUF_BYTES		2048
#define XFRM_RECV_TIMEO_S	1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it.
 * Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * past the SIGALRM(1s) cap. */
#define XFRM_PACKET_BASE	5U
#define XFRM_PACKET_FLOOR	16U
#define XFRM_PACKET_CAP		64U
#define STORM_BUDGET_NS		200000000L

/* UDP destination port for the inner traffic.  Loopback-only inside
 * a private netns; value functionally arbitrary; a fixed
 * non-privileged port keeps any escaped packet trivially identifiable
 * in a tcpdump trace during triage. */
#define XFRM_INNER_PORT		34571

/* Bounded retries on EAGAIN/EBUSY/ENOMEM for the netlink_xfrm
 * config plane.  XFRM commits can briefly return ENOMEM under memory
 * pressure or EBUSY while a sibling iteration is mid-teardown —
 * bounded retry rides through it instead of giving up the iteration. */
#define XFRM_RETRY_MAX		8

/* SA reqid rotation range.  Kernel uses reqid as a per-policy bundle
 * cache key — rotating across [1, 16] spreads the bundle cache
 * without exhausting the kernel's reqid allocator. */
#define XFRM_REQID_RANGE	16U

/* SPI rotation range.  Kernel reserves SPI < 256 for ISAKMP; we
 * stay clear of that range and rotate within [0x100, 0xffffff]. */
#define XFRM_SPI_MIN		0x100U
#define XFRM_SPI_RANGE		0xfff000U

/* Loopback addresses used for the SA selector and inner UDP traffic.
 * 127.0.0.1 -> 127.0.0.2 keeps everything on lo, no routes needed. */
#define XFRM_SADDR_BE		(__be32)__builtin_bswap32(0x7f000001U)
#define XFRM_DADDR_BE		(__be32)__builtin_bswap32(0x7f000002U)

/*
 * XFRM algorithm rotation.  Each entry is one transform the kernel
 * can install via XFRM_MSG_NEWSA.  proto picks the IPPROTO (ESP/AH/
 * IPCOMP), and the attr_kind tag picks which XFRMA_ALG_* attribute
 * carries the key material — AEAD goes in XFRMA_ALG_AEAD, classic
 * AH auth-only goes in XFRMA_ALG_AUTH, classic ESP enc+auth goes in
 * paired XFRMA_ALG_CRYPT + XFRMA_ALG_AUTH, IPCOMP goes in
 * XFRMA_ALG_COMP.  modname is the kernel crypto module to modprobe
 * (best-effort) the first time the algo is touched.
 */
enum xfrm_alg_kind {
	XFRM_ALG_AEAD,		/* XFRMA_ALG_AEAD only */
	XFRM_ALG_ESP_CBC,	/* XFRMA_ALG_CRYPT + XFRMA_ALG_AUTH */
	XFRM_ALG_ESP_NULL,	/* XFRMA_ALG_CRYPT (cipher_null) + XFRMA_ALG_AUTH */
	XFRM_ALG_AH,		/* XFRMA_ALG_AUTH only */
	XFRM_ALG_AH_NULL,	/* XFRMA_ALG_AUTH digest_null */
	XFRM_ALG_COMP,		/* XFRMA_ALG_COMP only */
};

struct xfrm_algo_def {
	enum xfrm_alg_kind	kind;
	__u8			proto;		/* IPPROTO_ESP/AH/COMP */
	const char		*enc_name;	/* NULL when kind has no enc */
	unsigned int		enc_key_bits;
	const char		*auth_name;	/* NULL when kind has no auth */
	unsigned int		auth_key_bits;
	unsigned int		auth_trunc_bits;
	unsigned int		aead_icv_bits;	/* AEAD only */
	const char		*modname;	/* best-effort modprobe target */
};

#ifndef IPPROTO_ESP
#define IPPROTO_ESP		50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH		51
#endif
#ifndef IPPROTO_COMP
#define IPPROTO_COMP		108
#endif

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

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations. */
static bool ns_unsupported_xfrm;
static bool ns_unsupported_inet;
static bool ns_unsupported_pfkey;

/* Per-algo latches: indexed by xfrm_algos[].  Set on first NEWSA
 * rejection with EOPNOTSUPP / EAFNOSUPPORT / ENOENT — the next
 * iteration skips that algo in the rotation. */
static bool ns_unsupported_algo[NR_XFRM_ALGOS];
static bool modprobe_tried_algo[NR_XFRM_ALGOS];

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

static int rtnl_route_open(void)
{
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int xfrm_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = XFRM_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

/*
 * Send via NETLINK_XFRM and consume one ack.  Returns 0 on a positive
 * ack (nlmsgerr.error == 0), the negated kernel errno on a rejection,
 * and -EIO on local sendmsg / recv failure.
 */
static int xfrm_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return -EIO;
}

/*
 * Wrap xfrm_send_recv with bounded retry on EAGAIN / EBUSY / ENOMEM
 * so a sibling iteration mid-teardown or a transient memory squeeze
 * doesn't waste this iteration's config-plane work.  Other errnos
 * pass through unchanged.
 */
static int xfrm_send_recv_retry(int fd, void *msg, size_t len)
{
	int rc = -EIO;
	int i;

	for (i = 0; i < XFRM_RETRY_MAX; i++) {
		rc = xfrm_send_recv(fd, msg, len);
		if (rc != -EAGAIN && rc != -EBUSY && rc != -ENOMEM)
			return rc;
	}
	return rc;
}

/*
 * Best-effort modprobe.  fork+execvp; child redirects stdio to
 * /dev/null so any module-load chatter doesn't pollute trinity's
 * output.  Ignore the exit status — modprobe failures (no module,
 * no permission, no /sbin/modprobe, lockdown=integrity) are exactly
 * the cases the per-algo latch will catch on the subsequent
 * XFRM_MSG_NEWSA probe.
 */
static void try_modprobe(const char *mod)
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
	(void)waitpid(pid, &status, 0);
}

static void modprobe_algo(unsigned int idx)
{
	if (modprobe_tried_algo[idx])
		return;
	modprobe_tried_algo[idx] = true;
	if (xfrm_algos[idx].modname)
		try_modprobe(xfrm_algos[idx].modname);
}

/*
 * Bring lo up inside the private netns.  IPsec on lo with transport
 * mode SAs gives us a self-contained data plane that drives
 * xfrm_lookup_with_ifid -> esp_output without needing routes.
 * Failures are ignored — the rest of the sequence will fail visibly
 * if rtnl is genuinely broken.
 */
static void bring_lo_up(int rtnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len  = nlh->nlmsg_len;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
	(void)sendmsg(rtnl, &mh, 0);

	/* Drain the ack — best effort. */
	{
		unsigned char ack[256];
		(void)recv(rtnl, ack, sizeof(ack), MSG_DONTWAIT);
	}
}

/* Build the SA selector matching 127.0.0.1 -> 127.0.0.2 UDP, both
 * sides /32.  Same shape used for the policy selector so the SPD
 * lookup at output time finds our SA cleanly. */
static void fill_selector(struct xfrm_selector *sel, __u8 proto)
{
	memset(sel, 0, sizeof(*sel));
	sel->saddr.a4    = XFRM_SADDR_BE;
	sel->daddr.a4    = XFRM_DADDR_BE;
	sel->family      = AF_INET;
	sel->prefixlen_s = 32;
	sel->prefixlen_d = 32;
	sel->proto       = proto;	/* 0 = any */
}

static void fill_lifetime(struct xfrm_lifetime_cfg *lft)
{
	memset(lft, 0, sizeof(*lft));
	lft->soft_byte_limit            = (__u64)~0ULL;
	lft->hard_byte_limit            = (__u64)~0ULL;
	lft->soft_packet_limit          = (__u64)~0ULL;
	lft->hard_packet_limit          = (__u64)~0ULL;
	lft->soft_add_expires_seconds   = 0;
	lft->hard_add_expires_seconds   = 0;
	lft->soft_use_expires_seconds   = 0;
	lft->hard_use_expires_seconds   = 0;
}

/*
 * Append the algorithm key material attribute(s) appropriate for the
 * given algo definition.  AEAD goes in XFRMA_ALG_AEAD with a single
 * combined key + ICV length.  Classic ESP CBC pairs XFRMA_ALG_CRYPT
 * (enc) + XFRMA_ALG_AUTH (HMAC).  ESP-NULL is the same shape with a
 * zero-length cipher_null key.  AH-only carries XFRMA_ALG_AUTH.
 * IPCOMP carries XFRMA_ALG_COMP.  Returns the new offset, or 0 on
 * buffer overflow (caller must check).
 */
static size_t append_algo_attrs(unsigned char *buf, size_t off, size_t cap,
				const struct xfrm_algo_def *def)
{
	unsigned char keymat[64];
	unsigned int enc_key_bytes  = def->enc_key_bits / 8;
	unsigned int auth_key_bytes = def->auth_key_bits / 8;

	if (def->kind == XFRM_ALG_AEAD) {
		struct xfrm_algo_aead *aead;
		unsigned char abuf[sizeof(*aead) + sizeof(keymat)];

		if (enc_key_bytes > sizeof(keymat))
			enc_key_bytes = sizeof(keymat);

		generate_rand_bytes(keymat, enc_key_bytes);

		memset(abuf, 0, sizeof(abuf));
		aead = (struct xfrm_algo_aead *)abuf;
		strncpy(aead->alg_name, def->enc_name,
			sizeof(aead->alg_name) - 1);
		aead->alg_key_len = def->enc_key_bits;
		aead->alg_icv_len = def->aead_icv_bits;
		memcpy(aead->alg_key, keymat, enc_key_bytes);

		return nla_put(buf, off, cap, XFRMA_ALG_AEAD, abuf,
			       sizeof(*aead) + enc_key_bytes);
	}

	if (def->enc_name) {
		struct xfrm_algo *enc;
		unsigned char ebuf[sizeof(*enc) + sizeof(keymat)];

		if (enc_key_bytes > sizeof(keymat))
			enc_key_bytes = sizeof(keymat);

		if (enc_key_bytes)
			generate_rand_bytes(keymat, enc_key_bytes);

		memset(ebuf, 0, sizeof(ebuf));
		enc = (struct xfrm_algo *)ebuf;
		strncpy(enc->alg_name, def->enc_name,
			sizeof(enc->alg_name) - 1);
		enc->alg_key_len = def->enc_key_bits;
		if (enc_key_bytes)
			memcpy(enc->alg_key, keymat, enc_key_bytes);

		off = nla_put(buf, off, cap,
			      def->kind == XFRM_ALG_COMP ? XFRMA_ALG_COMP
							 : XFRMA_ALG_CRYPT,
			      ebuf, sizeof(*enc) + enc_key_bytes);
		if (!off)
			return 0;
	}

	if (def->auth_name) {
		struct xfrm_algo_auth *au;
		unsigned char abuf[sizeof(*au) + sizeof(keymat)];

		if (auth_key_bytes > sizeof(keymat))
			auth_key_bytes = sizeof(keymat);

		if (auth_key_bytes)
			generate_rand_bytes(keymat, auth_key_bytes);

		memset(abuf, 0, sizeof(abuf));
		au = (struct xfrm_algo_auth *)abuf;
		strncpy(au->alg_name, def->auth_name,
			sizeof(au->alg_name) - 1);
		au->alg_key_len   = def->auth_key_bits;
		au->alg_trunc_len = def->auth_trunc_bits;
		if (auth_key_bytes)
			memcpy(au->alg_key, keymat, auth_key_bytes);

		off = nla_put(buf, off, cap, XFRMA_ALG_AUTH, abuf,
			      sizeof(*au) + auth_key_bytes);
		if (!off)
			return 0;
	}

	return off;
}

/*
 * XFRM_MSG_NEWSA carrying a fully-populated xfrm_usersa_info plus
 * one or more XFRMA_ALG_* attributes appropriate for the algo.
 * reqid + spi + proto are captured by the caller for the matching
 * policy template and the later UPDSA / DELSA.
 */
static int build_newsa(int fd, const struct xfrm_algo_def *def,
		       __u32 reqid, __be32 spi, __u8 mode)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, IPPROTO_UDP);
	sa->id.daddr.a4    = XFRM_DADDR_BE;
	sa->id.spi         = spi;
	sa->id.proto       = def->proto;
	sa->saddr.a4       = XFRM_SADDR_BE;
	fill_lifetime(&sa->lft);
	sa->reqid          = reqid;
	sa->family         = AF_INET;
	sa->mode           = mode;
	sa->replay_window  = 32;
	sa->flags          = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = append_algo_attrs(buf, off, sizeof(buf), def);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv_retry(fd, buf, off);
}

/*
 * XFRM_MSG_UPDSA: rebuild the same SA shell with a fresh random key
 * (and same SPI by default).  Drives the UPDSA-vs-encrypt rekey race
 * — the in-flight encrypt may still be holding the old key.
 */
static int build_updsa(int fd, const struct xfrm_algo_def *def,
		       __u32 reqid, __be32 spi, __u8 mode)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_UPDSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	sa = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	fill_selector(&sa->sel, IPPROTO_UDP);
	sa->id.daddr.a4    = XFRM_DADDR_BE;
	sa->id.spi         = spi;
	sa->id.proto       = def->proto;
	sa->saddr.a4       = XFRM_SADDR_BE;
	fill_lifetime(&sa->lft);
	sa->reqid          = reqid;
	sa->family         = AF_INET;
	sa->mode           = mode;
	sa->replay_window  = 32;
	sa->flags          = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*sa));

	off = append_algo_attrs(buf, off, sizeof(buf), def);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv_retry(fd, buf, off);
}

/*
 * XFRM_MSG_DELSA via xfrm_usersa_id (daddr + spi + proto + family).
 * Races the in-flight encrypt still draining from the post-UPDSA
 * sendto burst; the SA refcount UAF window opens here.
 */
static int build_delsa(int fd, __u8 proto, __be32 spi)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	uid->daddr.a4 = XFRM_DADDR_BE;
	uid->spi      = spi;
	uid->family   = AF_INET;
	uid->proto    = proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * XFRM_MSG_NEWPOLICY OUT direction with XFRMA_TMPL pointing at the
 * SA we just installed.  Selector matches the inner UDP traffic so
 * the SPD lookup at xfrm_output time resolves to our SA bundle.
 */
static int build_newpolicy(int fd, const struct xfrm_algo_def *def,
			   __u32 reqid, __be32 spi, __u8 mode)
{
	unsigned char buf[XFRM_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_info *pol;
	struct xfrm_user_tmpl tmpl;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	pol = (struct xfrm_userpolicy_info *)NLMSG_DATA(nlh);
	fill_selector(&pol->sel, IPPROTO_UDP);
	fill_lifetime(&pol->lft);
	pol->priority = 1024;
	pol->index    = 0;
	pol->dir      = XFRM_POLICY_OUT;
	pol->action   = XFRM_POLICY_ALLOW;
	pol->flags    = 0;
	pol->share    = XFRM_SHARE_ANY;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pol));

	memset(&tmpl, 0, sizeof(tmpl));
	tmpl.id.daddr.a4 = XFRM_DADDR_BE;
	tmpl.id.spi      = spi;
	tmpl.id.proto    = def->proto;
	tmpl.family      = AF_INET;
	tmpl.saddr.a4    = XFRM_SADDR_BE;
	tmpl.reqid       = reqid;
	tmpl.mode        = mode;
	tmpl.share       = XFRM_SHARE_ANY;
	tmpl.optional    = 0;
	tmpl.aalgos      = (__u32)~0U;
	tmpl.ealgos      = (__u32)~0U;
	tmpl.calgos      = (__u32)~0U;

	off = nla_put(buf, off, sizeof(buf), XFRMA_TMPL, &tmpl, sizeof(tmpl));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv_retry(fd, buf, off);
}

/*
 * XFRM_MSG_DELPOLICY OUT via xfrm_userpolicy_id.  Races the in-flight
 * skbs still draining from the post-UPDSA sendto burst.
 */
static int build_delpolicy(int fd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_userpolicy_id *pid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELPOLICY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	pid = (struct xfrm_userpolicy_id *)NLMSG_DATA(nlh);
	fill_selector(&pid->sel, IPPROTO_UDP);
	pid->dir = XFRM_POLICY_OUT;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

/*
 * Pick a random algo index that isn't latched-off.  Returns
 * NR_XFRM_ALGOS if every algo is latched (caller bails out).
 */
static unsigned int pick_algo_idx(void)
{
	unsigned int start = rand32() % NR_XFRM_ALGOS;
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
 * Drive the SPD-resolved bundle with loopback UDP traffic.  Each
 * send walks ip_local_out -> xfrm_output -> esp_output (or ah_output
 * / ipcomp_output) through the freshly-installed SA + SP bundle.
 * Returns the number of successful sends so the caller can roll
 * stats.
 */
static unsigned int drive_inner_traffic(int udp, unsigned int iters,
					const struct timespec *t0)
{
	struct sockaddr_in dst;
	unsigned int i, ok = 0;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(XFRM_INNER_PORT);
	dst.sin_addr.s_addr = XFRM_DADDR_BE;

	for (i = 0; i < iters; i++) {
		unsigned char payload[64];
		ssize_t n;

		if (ns_since(t0) >= STORM_BUDGET_NS)
			break;

		generate_rand_bytes(payload, sizeof(payload));
		n = sendto(udp, payload, sizeof(payload), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n > 0)
			ok++;
	}
	return ok;
}

/*
 * PF_KEYv2 alt path: open AF_KEY socket and emit a SADB_FLUSH for
 * ESP and AH.  Drives net/key/af_key.c dispatch + flush paths that
 * share the SAD / SPD with the netlink_xfrm side.  Latched on first
 * EAFNOSUPPORT / EPROTONOSUPPORT (kernel without CONFIG_NET_KEY).
 */
static void pfkey_flush_burst(void)
{
	struct sadb_msg msg;
	int s;

	if (ns_unsupported_pfkey)
		return;

	s = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);
	if (s < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			ns_unsupported_pfkey = true;
		return;
	}

	memset(&msg, 0, sizeof(msg));
	msg.sadb_msg_version  = PF_KEY_V2;
	msg.sadb_msg_type     = SADB_FLUSH;
	msg.sadb_msg_satype   = SADB_SATYPE_ESP;
	msg.sadb_msg_len      = sizeof(msg) / 8;
	msg.sadb_msg_seq      = next_seq();
	msg.sadb_msg_pid      = (__u32)getpid();
	if (send(s, &msg, sizeof(msg), MSG_DONTWAIT) > 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn_pfkey_send_ok,
				   1, __ATOMIC_RELAXED);

	memset(&msg, 0, sizeof(msg));
	msg.sadb_msg_version  = PF_KEY_V2;
	msg.sadb_msg_type     = SADB_FLUSH;
	msg.sadb_msg_satype   = SADB_SATYPE_AH;
	msg.sadb_msg_len      = sizeof(msg) / 8;
	msg.sadb_msg_seq      = next_seq();
	msg.sadb_msg_pid      = (__u32)getpid();
	if (send(s, &msg, sizeof(msg), MSG_DONTWAIT) > 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn_pfkey_send_ok,
				   1, __ATOMIC_RELAXED);

	close(s);
}

bool xfrm_churn(struct childdata *child)
{
	int xfrm = -1;
	int rtnl = -1;
	int udp = -1;
	unsigned int aidx;
	const struct xfrm_algo_def *def;
	__u32 reqid;
	__be32 spi;
	__u8 mode;
	struct timespec t0;
	unsigned int iters, sent;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.xfrm_churn_runs, 1, __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_xfrm)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.xfrm_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	if (!lo_brought_up) {
		rtnl = rtnl_route_open();
		if (rtnl >= 0) {
			bring_lo_up(rtnl);
			close(rtnl);
		}
		lo_brought_up = true;
	}

	xfrm = xfrm_open();
	if (xfrm < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_xfrm = true;
		__atomic_add_fetch(&shm->stats.xfrm_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	aidx = pick_algo_idx();
	if (aidx >= NR_XFRM_ALGOS)
		goto out;

	def   = &xfrm_algos[aidx];
	reqid = (rand32() % XFRM_REQID_RANGE) + 1U;
	spi   = htonl((rand32() % XFRM_SPI_RANGE) + XFRM_SPI_MIN);
	mode  = (rand32() & 1U) ? XFRM_MODE_TRANSPORT : XFRM_MODE_TRANSPORT;
	/* TUNNEL mode requires routes to the inner addresses; staying
	 * in TRANSPORT keeps the data plane self-contained on lo.
	 * Knob preserved as a no-op so the rotation can be widened
	 * later without restructuring this caller. */

	modprobe_algo(aidx);
	rc = build_newsa(xfrm, def, reqid, spi, mode);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_algo[aidx] = true;
		goto out;
	}
	__atomic_add_fetch(&shm->stats.xfrm_churn_sa_added,
			   1, __ATOMIC_RELAXED);

	rc = build_newpolicy(xfrm, def, reqid, spi, mode);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.xfrm_churn_pol_added,
				   1, __ATOMIC_RELAXED);
	}

	if (!ns_unsupported_inet) {
		struct sockaddr_in src;

		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		} else {
			memset(&src, 0, sizeof(src));
			src.sin_family      = AF_INET;
			src.sin_addr.s_addr = XFRM_SADDR_BE;
			(void)bind(udp, (struct sockaddr *)&src, sizeof(src));
		}
	}

	if (udp >= 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_XFRM_CHURN,
				 JITTER_RANGE(XFRM_PACKET_BASE));
		if (iters < XFRM_PACKET_FLOOR)
			iters = XFRM_PACKET_FLOOR;
		if (iters > XFRM_PACKET_CAP)
			iters = XFRM_PACKET_CAP;

		sent = drive_inner_traffic(udp, iters, &t0);
		if (sent)
			__atomic_add_fetch(&shm->stats.xfrm_churn_esp_sent,
					   sent, __ATOMIC_RELAXED);
	}

	/*
	 * Mid-flow rekey: rebuild the SA on the same (reqid, spi,
	 * proto) shell with a fresh random key.  The in-flight encrypt
	 * from the burst above may still be holding the old key —
	 * CVE-2023-1611 family lives in this window.
	 */
	rc = build_updsa(xfrm, def, reqid, spi, mode);
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.xfrm_churn_sa_updated,
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Second send burst — encrypt path may walk the freshly-rotated
	 * key, or hit the stale-key window mid-rotation.
	 */
	if (udp >= 0) {
		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_XFRM_CHURN,
				 JITTER_RANGE(XFRM_PACKET_BASE));
		if (iters < XFRM_PACKET_FLOOR)
			iters = XFRM_PACKET_FLOOR;
		if (iters > XFRM_PACKET_CAP)
			iters = XFRM_PACKET_CAP;

		sent = drive_inner_traffic(udp, iters, &t0);
		if (sent)
			__atomic_add_fetch(&shm->stats.xfrm_churn_esp_sent,
					   sent, __ATOMIC_RELAXED);
	}

	/*
	 * Tear the SA down racing the in-flight encrypt still draining
	 * from the second burst.  Cascades cleanup of the bundle cache
	 * via xfrm_state_delete -> __xfrm_state_destroy — the primary
	 * teardown-vs-traffic window the op exists to open.
	 */
	if (build_delsa(xfrm, def->proto, spi) == 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn_sa_deleted,
				   1, __ATOMIC_RELAXED);

	if (build_delpolicy(xfrm) == 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn_pol_deleted,
				   1, __ATOMIC_RELAXED);

	/* PF_KEYv2 alt path: ~1 in 8 invocations exercises the parallel
	 * af_key dispatch + flush paths that share the SAD/SPD with
	 * netlink_xfrm. */
	if ((rand32() & 7U) == 0)
		pfkey_flush_burst();

out:
	if (udp >= 0)
		close(udp);
	if (xfrm >= 0)
		close(xfrm);

	return true;
}
