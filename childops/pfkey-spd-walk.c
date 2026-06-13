/*
 * pfkey_spd_walk - race PF_KEYv2 SADB_X_SPDDUMP against concurrent
 * SADB_X_SPDADD / SADB_X_SPDGET mutators on a per-netns Security
 * Policy Database (SPD).  Drives net/key/af_key.c's pfkey_spd_dump
 * walk against pfkey_spdadd / pfkey_spdget on the same xfrm_policy
 * list under spd_hmask / xfrm_policy_byidx.
 *
 * Background.  PF_KEYv2 is the legacy IPsec keying interface (RFC
 * 2367); Linux exposes it as AF_KEY SOCK_RAW PF_KEY_V2 from
 * CONFIG_NET_KEY=m.  Userland sends self-describing SADB messages
 * (sadb_msg header + a chain of TLV extensions terminated by total
 * length).  The KAME-derived extensions SADB_X_SPDADD / SPDGET /
 * SPDUPDATE / SPDDELETE / SPDDUMP manipulate the SPD; SPDDUMP walks
 * the per-net xfrm_policy_inexact_table and the per-direction
 * xfrm_policy_byidx hash, serialising each entry back to userland
 * one message at a time.  SPDADD inserts a new entry into the same
 * lists.  Random per-syscall sendmsg fuzzing over AF_KEY never
 * assembles the concurrent walk-vs-mutate shape; this childop drives
 * it directly.
 *
 * Bug-class targets (non-exhaustive):
 *   - parser:  TLV length field arithmetic / extension overrun in
 *              pfkey_spdadd / parse_exthdrs (sadb_ext_len in 8-byte
 *              units; a fuzzed extension that strides past sadb_msg_len
 *              has historically reached an uninitialised stack slot).
 *   - walker:  SPDDUMP iterates the list with a saved cursor; an
 *              SPDADD that re-buckets the byidx hash mid-walk can
 *              produce duplicate emit / skip / use-after-free of the
 *              dying xfrm_policy.
 *   - state:   SPDGET resolves a policy id (auto-assigned on SPDADD);
 *              racing SPDGET with SPDADD of the same id walks the
 *              ID hash while another task is splicing into it.
 *
 * Shape (per outer iteration, BUDGETED+capped):
 *   1.  Pick a policy variant: direction (IN/OUT/FWD), type
 *       (DISCARD/BYPASS/NONE), priority (rotating 32-bit), and
 *       src/dst prefixlen (varies the SPD bucket the entry hashes
 *       to).  Source / destination are loopback so no host-visible
 *       routing leak even if the netns unshare failed.
 *   2.  fork() a "walker" sibling: opens its own PF_KEY socket,
 *       tight-loops SADB_X_SPDADD with rotating TLVs (the per-iter
 *       variant plus a small per-iter offset for prefixlen / id
 *       rotation), draining replies non-blocking.
 *   3.  fork() a "racer" sibling: opens its own PF_KEY socket,
 *       tight-loops SADB_X_SPDDUMP alternated with SADB_X_SPDGET
 *       against a small set of policy ids the walker is expected
 *       to be churning.  Both children share the parent's unshared
 *       netns (forks inherit the netns) so they hammer the same
 *       per-net spd_hmask + xfrm_policy_byidx the walker mutates.
 *   4.  Parent reaps both via waitpid_eintr().  WIFSIGNALED on
 *       either bumps the forensic crashed counter -- the bug
 *       surface is exactly the one-sided crash where one task
 *       frees an xfrm_policy the other is mid-walk through.
 *   5.  Parent issues a best-effort SADB_X_SPDFLUSH to drain its
 *       own per-netns SPD before the next iter so accumulated
 *       entries don't balloon kernel memory across an outer-loop
 *       burn.  Failure (e.g. socket closed by alarm) is benign.
 *
 * Self-gating.  Two latches.
 *   - ns_unsupported_pfkey_spd_walk: first invocation per process
 *     probes socket(AF_KEY, SOCK_RAW, PF_KEY_V2).  Any failure
 *     (EAFNOSUPPORT, EPROTONOSUPPORT, EACCES) latches the op off
 *     for the rest of this child's life -- typical when
 *     CONFIG_NET_KEY=n or the af_key module isn't loaded.  Same
 *     shape as the qrtr / af_unix peek / netns_teardown latches.
 *   - ns_unshare_failed_pfkey_spd_walk: first invocation also
 *     issues unshare(CLONE_NEWNET) once per child so every SPD
 *     mutation stays in a private netns the kernel destroys when
 *     this trinity child exits.  EPERM (no CAP_SYS_ADMIN) latches
 *     the op off uniformly.
 *
 * Brick-safety.  All SPD writes land in a freshly-unshared netns
 * (and SADB_X_SPDFLUSH between iters drains it anyway); on failure
 * to unshare we latch off rather than mutate the host SPD.  No
 * module load, no rtnetlink, no globally-reachable resource.
 * Bounded outer loop with a hard wall-clock cap.
 *
 * Header compat.  AF_KEY landed in mainline as 15 (RFC 2367).  The
 * sadb_msg / sadb_ext / sadb_address / sadb_x_policy layouts are
 * frozen UAPI; <linux/pfkeyv2.h> ships them.  Stripped sysroots get
 * the fallback structs at the bottom of the file.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "child.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/pfkeyv2.h>)
#include <linux/pfkeyv2.h>
#endif

#ifndef AF_KEY
#define AF_KEY				15
#endif
#ifndef PF_KEY
#define PF_KEY				AF_KEY
#endif
#ifndef PF_KEY_V2
#define PF_KEY_V2			2
#endif

/* SADB message types.  Numbering matches Linux's <linux/pfkeyv2.h>
 * (the KAME-derived X_SPD* extensions are stable in the UAPI). */
#ifndef SADB_X_SPDADD
#define SADB_X_SPDADD			14
#endif
#ifndef SADB_X_SPDDELETE
#define SADB_X_SPDDELETE		15
#endif
#ifndef SADB_X_SPDGET
#define SADB_X_SPDGET			16
#endif
#ifndef SADB_X_SPDDUMP
#define SADB_X_SPDDUMP			18
#endif
#ifndef SADB_X_SPDFLUSH
#define SADB_X_SPDFLUSH			19
#endif

#ifndef SADB_SATYPE_UNSPEC
#define SADB_SATYPE_UNSPEC		0
#endif

#ifndef SADB_EXT_ADDRESS_SRC
#define SADB_EXT_ADDRESS_SRC		5
#define SADB_EXT_ADDRESS_DST		6
#endif

#ifndef SADB_X_EXT_POLICY
#define SADB_X_EXT_POLICY		18
#endif

/* IPSEC policy direction + type.  RFC 2367 + KAME.  Linux mirrors
 * IPSEC_DIR_INBOUND=1 / OUTBOUND=2 / FWD=3, and policy types
 * IPSEC_POLICY_DISCARD=0 / NONE=1 / IPSEC=2 / BYPASS=4. */
#ifndef IPSEC_DIR_INBOUND
#define IPSEC_DIR_INBOUND		1
#define IPSEC_DIR_OUTBOUND		2
#define IPSEC_DIR_FWD			3
#endif

#ifndef IPSEC_POLICY_DISCARD
#define IPSEC_POLICY_DISCARD		0
#define IPSEC_POLICY_NONE		1
#define IPSEC_POLICY_IPSEC		2
#define IPSEC_POLICY_BYPASS		4
#endif

/* Fallback layouts.  Pulled in only when <linux/pfkeyv2.h> is absent
 * on the build sysroot.  Field names/sizes match the kernel UAPI
 * (frozen since 2.6.x); the existing xfrm-churn.c uses an equivalent
 * sadb_msg fallback under the same gate. */
#if !__has_include(<linux/pfkeyv2.h>)
struct sadb_msg {
	uint8_t		sadb_msg_version;
	uint8_t		sadb_msg_type;
	uint8_t		sadb_msg_errno;
	uint8_t		sadb_msg_satype;
	uint16_t	sadb_msg_len;
	uint16_t	sadb_msg_reserved;
	uint32_t	sadb_msg_seq;
	uint32_t	sadb_msg_pid;
};

struct sadb_ext {
	uint16_t	sadb_ext_len;
	uint16_t	sadb_ext_type;
};

struct sadb_address {
	uint16_t	sadb_address_len;
	uint16_t	sadb_address_exttype;
	uint8_t		sadb_address_proto;
	uint8_t		sadb_address_prefixlen;
	uint16_t	sadb_address_reserved;
};

struct sadb_x_policy {
	uint16_t	sadb_x_policy_len;
	uint16_t	sadb_x_policy_exttype;
	uint16_t	sadb_x_policy_type;
	uint8_t		sadb_x_policy_dir;
	uint8_t		sadb_x_policy_reserved;
	uint32_t	sadb_x_policy_id;
	uint32_t	sadb_x_policy_priority;
};
#endif /* !__has_include(<linux/pfkeyv2.h>) */

/* Outer-loop sizing.  Per-iter cost is two fork/exit pairs plus a
 * burst of SADB sends inside each; cap mirrors qrtr-bind-race's
 * outer cap so steady-state load is comparable. */
#define PFKEY_SPD_OUTER_BASE		3U
#define PFKEY_SPD_OUTER_CAP		16U
#define PFKEY_SPD_WALL_CAP_NS		(250ULL * 1000ULL * 1000ULL)

/* Per-sibling inner send cap.  Both siblings honour their own
 * wall-clock budget below; this cap is the absolute ceiling so a
 * fast kernel can't loop indefinitely. */
#define PFKEY_INNER_BURST_CAP		64U
#define PFKEY_INNER_WALL_NS		(150ULL * 1000ULL * 1000ULL)

/* Per-netns + per-process latches.  Same shape as qrtr-bind-race and
 * netns-teardown-churn: the AF_KEY socket probe runs once; the
 * netns unshare runs once.  Either latch makes the op a silent
 * no-op for the rest of the child's life. */
static bool pfkey_probed;
static bool ns_unsupported_pfkey_spd_walk;
static bool ns_unshared_pfkey_spd_walk;
static bool ns_unshare_failed_pfkey_spd_walk;

/*
 * Probe AF_KEY availability once per process.  Open succeeds on hosts
 * with the af_key module loaded; everything else
 * (EAFNOSUPPORT / EPROTONOSUPPORT / EACCES) latches the op off.
 */
static void probe_pfkey(void)
{
	int fd;

	pfkey_probed = true;
	fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd < 0) {
		ns_unsupported_pfkey_spd_walk = true;
		return;
	}
	close(fd);
}

/*
 * Per-child netns unshare.  All SPD writes land in this private
 * netns so we never touch the host SPD even if the kernel happens
 * to accept the message.  EPERM (no CAP_SYS_ADMIN) latches the
 * op off uniformly.
 */
static void unshare_netns_once(void)
{
	if (ns_unshared_pfkey_spd_walk || ns_unshare_failed_pfkey_spd_walk)
		return;
	if (unshare(CLONE_NEWNET) < 0) {
		ns_unshare_failed_pfkey_spd_walk = true;
		return;
	}
	ns_unshared_pfkey_spd_walk = true;
}

/*
 * Per-iter rotation knobs.  Each call picks one direction / type /
 * priority / prefixlen combination; the walker's inner loop then
 * varies the per-message id offset on top so consecutive sends land
 * in different SPD buckets.
 */
struct spd_variant {
	uint8_t		dir;
	uint16_t	type;
	uint32_t	priority;
	uint8_t		prefixlen_s;
	uint8_t		prefixlen_d;
};

static void pick_variant(struct spd_variant *v)
{
	static const uint8_t dirs[] = {
		IPSEC_DIR_INBOUND, IPSEC_DIR_OUTBOUND, IPSEC_DIR_FWD,
	};
	static const uint16_t types[] = {
		IPSEC_POLICY_DISCARD, IPSEC_POLICY_NONE, IPSEC_POLICY_BYPASS,
	};

	v->dir = dirs[rnd_modulo_u32((unsigned int)(sizeof(dirs) / sizeof(dirs[0])))];
	v->type = types[rnd_modulo_u32((unsigned int)(sizeof(types) / sizeof(types[0])))];
	v->priority = rnd_u32();
	/* Spread the destination prefixlen across /8../32 so the SPD
	 * inexact-tree hashes entries into a range of buckets rather
	 * than collapsing every walker insertion onto one slot. */
	v->prefixlen_s = (uint8_t)(8U + rnd_modulo_u32(25U));
	v->prefixlen_d = (uint8_t)(8U + rnd_modulo_u32(25U));
}

/*
 * Build a SADB_X_SPDADD message into `buf` and return its byte
 * length (also written into sadb_msg_len in 8-byte units).
 *
 * Layout:
 *   struct sadb_msg                                       (16 B)
 *   struct sadb_x_policy                                  (16 B)
 *   struct sadb_address SRC + sockaddr_in (padded to 8)   (24 B)
 *   struct sadb_address DST + sockaddr_in (padded to 8)   (24 B)
 *
 * Loopback addresses keep the message routable-looking without
 * needing any interface setup inside the fresh netns; the kernel
 * does not actually transmit on SPDADD.
 */
static size_t build_spdadd(uint8_t *buf, size_t cap,
			   const struct spd_variant *v,
			   uint32_t policy_id, uint32_t seq, uint32_t pid)
{
	struct sadb_msg *msg;
	struct sadb_x_policy *pol;
	struct sadb_address *addr;
	struct sockaddr_in *sin;
	size_t off = 0;
	size_t need = sizeof(*msg) + sizeof(*pol) +
		      2U * (sizeof(*addr) + 8U + 8U);

	if (cap < need)
		return 0;

	memset(buf, 0, need);

	msg = (struct sadb_msg *)(buf + off);
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_X_SPDADD;
	msg->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg->sadb_msg_seq = seq;
	msg->sadb_msg_pid = pid;
	off += sizeof(*msg);

	pol = (struct sadb_x_policy *)(buf + off);
	pol->sadb_x_policy_len = (uint16_t)(sizeof(*pol) / 8U);
	pol->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	pol->sadb_x_policy_type = v->type;
	pol->sadb_x_policy_dir = v->dir;
	pol->sadb_x_policy_id = policy_id;
	pol->sadb_x_policy_priority = v->priority;
	off += sizeof(*pol);

	/* SRC address: sadb_address (8 B) + sockaddr_in (16 B padded
	 * to next 8 = 16 B).  Total 24 B = 3 units. */
	addr = (struct sadb_address *)(buf + off);
	addr->sadb_address_len = (uint16_t)((sizeof(*addr) + 16U) / 8U);
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addr->sadb_address_proto = 0;
	addr->sadb_address_prefixlen = v->prefixlen_s;
	off += sizeof(*addr);
	sin = (struct sockaddr_in *)(buf + off);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(0x7f000001U);
	off += 16U;

	/* DST address: same shape. */
	addr = (struct sadb_address *)(buf + off);
	addr->sadb_address_len = (uint16_t)((sizeof(*addr) + 16U) / 8U);
	addr->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	addr->sadb_address_proto = 0;
	addr->sadb_address_prefixlen = v->prefixlen_d;
	off += sizeof(*addr);
	sin = (struct sockaddr_in *)(buf + off);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(0x7f000002U);
	off += 16U;

	msg->sadb_msg_len = (uint16_t)(off / 8U);
	return off;
}

/*
 * Build a header-only SADB message (no extensions).  Used for
 * SPDDUMP / SPDFLUSH where the kernel only needs the sadb_msg
 * header to drive the operation.
 */
static size_t build_header_only(uint8_t *buf, size_t cap,
				uint8_t type, uint32_t seq, uint32_t pid)
{
	struct sadb_msg *msg;

	if (cap < sizeof(*msg))
		return 0;

	memset(buf, 0, sizeof(*msg));
	msg = (struct sadb_msg *)buf;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = type;
	msg->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg->sadb_msg_len = (uint16_t)(sizeof(*msg) / 8U);
	msg->sadb_msg_seq = seq;
	msg->sadb_msg_pid = pid;
	return sizeof(*msg);
}

/*
 * Build a SADB_X_SPDGET targeting a specific policy id.  The kernel
 * expects sadb_msg + sadb_x_policy (with the id filled in); the
 * direction is required to resolve which list head to walk.
 */
static size_t build_spdget(uint8_t *buf, size_t cap, uint8_t dir,
			   uint32_t policy_id, uint32_t seq, uint32_t pid)
{
	struct sadb_msg *msg;
	struct sadb_x_policy *pol;
	size_t need = sizeof(*msg) + sizeof(*pol);

	if (cap < need)
		return 0;

	memset(buf, 0, need);

	msg = (struct sadb_msg *)buf;
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = SADB_X_SPDGET;
	msg->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg->sadb_msg_len = (uint16_t)(need / 8U);
	msg->sadb_msg_seq = seq;
	msg->sadb_msg_pid = pid;

	pol = (struct sadb_x_policy *)(buf + sizeof(*msg));
	pol->sadb_x_policy_len = (uint16_t)(sizeof(*pol) / 8U);
	pol->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	pol->sadb_x_policy_dir = dir;
	pol->sadb_x_policy_id = policy_id;
	return need;
}

/*
 * Drain replies non-blocking.  PF_KEY broadcasts SPDADD acks /
 * SPDDUMP entries; if we never read them the socket buffer fills
 * and subsequent sends start returning ENOBUFS.  We don't need the
 * payload -- the bug surface is the kernel-side walk -- so a fixed
 * burst of MSG_DONTWAIT recvs is enough.
 */
static void drain_replies(int fd)
{
	uint8_t buf[2048];
	unsigned int i;

	for (i = 0; i < 16U; i++) {
		ssize_t r = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (r < 0)
			break;
	}
}

/*
 * Walker child: open PF_KEY socket, tight-loop SADB_X_SPDADD with
 * a rotating per-message id so consecutive entries hash into
 * different SPD buckets.  Each iter also rotates the priority by a
 * small offset to further diffuse bucket pressure.  Sends are
 * blocking; the inner loop is capped by wall clock + burst count.
 */
static __attribute__((noreturn)) void spd_walker_child(struct spd_variant base)
{
	uint8_t buf[256];
	struct spd_variant v;
	struct timespec t0;
	int fd;
	uint32_t pid;
	unsigned int i;

	fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd < 0)
		_exit(0);

	pid = (uint32_t)getpid();
	v = base;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < PFKEY_INNER_BURST_CAP; i++) {
		size_t len;
		uint32_t id = (uint32_t)i + 1U;

		/* Cycle the priority on each send so the new entry
		 * is unlikely to collide with the previous insertion
		 * point in the priority-ordered SPD list. */
		v.priority = base.priority + (uint32_t)i * 1024U;
		v.prefixlen_d = (uint8_t)(8U + ((base.prefixlen_d + i) % 25U));

		len = build_spdadd(buf, sizeof(buf), &v, id,
				   (uint32_t)i + 1U, pid);
		if (len == 0)
			break;
		(void)send(fd, buf, len, 0);
		drain_replies(fd);

		if (budget_elapsed_ns(&t0, (long)PFKEY_INNER_WALL_NS))
			break;
	}

	close(fd);
	_exit(0);
}

/*
 * Racer child: open PF_KEY socket, alternate SADB_X_SPDDUMP (walk
 * every entry in the SPD) with SADB_X_SPDGET (resolve one specific
 * policy id from the byidx hash).  Both operations walk the same
 * lists the walker is mutating; the bug surface is precisely the
 * mid-walk reshape.
 */
static __attribute__((noreturn)) void spd_racer_child(uint8_t walker_dir)
{
	uint8_t buf[256];
	struct timespec t0;
	int fd;
	uint32_t pid;
	unsigned int i;

	fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd < 0)
		_exit(0);

	pid = (uint32_t)getpid();

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	for (i = 0; i < PFKEY_INNER_BURST_CAP; i++) {
		size_t len;
		uint32_t id;

		if ((i & 1U) == 0U) {
			len = build_header_only(buf, sizeof(buf),
						SADB_X_SPDDUMP,
						(uint32_t)i + 1U, pid);
		} else {
			/* Target an id the walker is plausibly mid-
			 * insertion on.  Walker uses ids [1, BURST_CAP];
			 * sample uniformly across that range. */
			id = 1U + rnd_modulo_u32(PFKEY_INNER_BURST_CAP);
			len = build_spdget(buf, sizeof(buf), walker_dir,
					   id, (uint32_t)i + 1U, pid);
		}
		if (len == 0)
			break;
		(void)send(fd, buf, len, 0);
		drain_replies(fd);

		if (budget_elapsed_ns(&t0, (long)PFKEY_INNER_WALL_NS))
			break;
	}

	close(fd);
	_exit(0);
}

/*
 * Reap one forked sibling.  WIFSIGNALED bumps the forensic counter
 * -- the bug surface is precisely the one-sided crash where one
 * task frees an xfrm_policy the other is mid-walk through.
 */
static void reap_sibling(pid_t pid)
{
	int status;

	if (pid <= 0)
		return;
	if (waitpid_eintr(pid, &status, 0) != pid)
		return;
	if (WIFSIGNALED(status))
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_sibling_crashed,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_sibling_reaped_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * Per-iter SPDFLUSH: best-effort drain of the per-netns SPD so
 * accumulated walker insertions don't balloon kernel memory across
 * an outer-loop burn.  Failure (socket close, ENOBUFS, kernel
 * refusal) is benign -- the netns itself is reaped when this
 * trinity child exits.
 */
static void spdflush_best_effort(void)
{
	uint8_t buf[64];
	size_t len;
	int fd;

	fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
	if (fd < 0)
		return;
	len = build_header_only(buf, sizeof(buf), SADB_X_SPDFLUSH,
				1U, (uint32_t)getpid());
	if (len > 0)
		(void)send(fd, buf, len, 0);
	drain_replies(fd);
	close(fd);
}

/*
 * One outer iteration: pick a policy variant, fork walker + racer,
 * reap both, flush the SPD.  Coverage bumps live on each successful
 * step so a child that latches off mid-run still leaves a forensic
 * trail in the per-op stats.
 */
static void iter_one(void)
{
	struct spd_variant v;
	pid_t walker, racer;

	pick_variant(&v);

	__atomic_add_fetch(&shm->stats.pfkey_spd_walk_iter,
			   1, __ATOMIC_RELAXED);

	walker = fork();
	if (walker < 0) {
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_fork_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
	if (walker == 0)
		spd_walker_child(v);

	racer = fork();
	if (racer < 0) {
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_fork_failed,
				   1, __ATOMIC_RELAXED);
		/* walker already in flight; reap it so we don't leave
		 * a zombie behind when the outer loop continues. */
		reap_sibling(walker);
		return;
	}
	if (racer == 0)
		spd_racer_child(v.dir);

	__atomic_add_fetch(&shm->stats.pfkey_spd_walk_spawn_pair_ok,
			   1, __ATOMIC_RELAXED);

	reap_sibling(walker);
	reap_sibling(racer);

	spdflush_best_effort();
}

bool pfkey_spd_walk(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.pfkey_spd_walk_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_pfkey_spd_walk ||
	    ns_unshare_failed_pfkey_spd_walk) {
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!pfkey_probed) {
		probe_pfkey();
		if (ns_unsupported_pfkey_spd_walk) {
			__atomic_add_fetch(&shm->stats.pfkey_spd_walk_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	unshare_netns_once();
	if (ns_unshare_failed_pfkey_spd_walk) {
		__atomic_add_fetch(&shm->stats.pfkey_spd_walk_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_PFKEY_SPD_WALK, PFKEY_SPD_OUTER_BASE);
	if (outer_iters == 0U)
		outer_iters = 1U;
	if (outer_iters > PFKEY_SPD_OUTER_CAP)
		outer_iters = PFKEY_SPD_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if (budget_elapsed_ns(&t_outer, (long)PFKEY_SPD_WALL_CAP_NS))
			break;
		iter_one();
	}

	return true;
}
