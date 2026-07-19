/*
 * genetlink_fuzzer - structurally-valid generic netlink fuzzing.
 *
 * Generic netlink families are the fastest-growing kernel attack surface.
 * nl80211 alone has accumulated 15+ public CVEs, most rooted in incorrect
 * or missing per-attribute validation in deep parser paths.  Trinity's
 * existing general netlink path (net/netlink/msg.c) constructs
 * NETLINK_GENERIC messages with random nlmsg_type and random genlmsghdr.cmd,
 * which is useful for exercising the unknown-family fast-reject path but
 * almost never lines up with a real registered family ID, so the actual
 * per-family parsers — where the bugs live — stay cold.
 *
 * This childop closes the gap.  The per-invocation shape is:
 *   1. In the persistent fuzz child, in the HOST net namespace,
 *      enumerate the registered families via
 *      CTRL_CMD_GETFAMILY/NLM_F_DUMP and build a small catalog of
 *      {family_id, name, version, ops[]}.  This MUST happen before the
 *      grandchild's unshare(CLONE_NEWNET) -- a freshly-unshared netns
 *      starts out with essentially no registered families (only the
 *      always-present GENL_ID_CTRL), so dumping the controller from
 *      inside the fresh netns produces an empty catalog and the op
 *      silently bails without ever sending fuzz traffic.
 *   2. Enter a private net namespace via userns_run_in_ns(): a
 *      transient grandchild fork installs an identity user namespace
 *      plus a fresh CLONE_NEWNET, runs the body below, and _exit()s so
 *      the kernel reaps the genetlink socket along with the
 *      grandchild's netns.  The persistent fuzz child never changes
 *      its own credentials or namespace stack, so the cap-drop oracle
 *      keeps observing the host credential profile.
 *   3. Inside the grandchild, pick a random family from the
 *      parent-built catalog + a random op from its registered command
 *      list, and construct a message with the matching nlmsghdr type
 *      and genlmsghdr cmd.  Family IDs are kernel-global -- routing on
 *      type=family_id reaches the family's dispatch code from any
 *      netns, and per-netns presence is enforced inside the family
 *      handlers, which is precisely the surface we want to fuzz.  The
 *      kernel's family demuxer accepts the type, the version check
 *      passes, and we land directly in the family's command dispatch
 *      table -- exactly the surface trinity has historically missed.
 *
 * Important families this catches automatically when present:
 *   nl80211 (WiFi config), devlink, ethtool, dpll, mptcp_pm, ovs (OVS),
 *   nbd, TIPC, taskstats, NET_DM, ...
 *
 * Future enhancements (not implemented here):
 *   - Per-family attribute policy inspection: use the registered policy
 *     (CTRL_CMD_GETPOLICY) to construct mostly-valid messages with one
 *     mutated attribute, instead of fully random nested attrs.
 *   - Stateful sequences within a family (e.g. nl80211: phy index → vif
 *     config → trigger scan).
 *   - Multicast group membership + listening for family broadcasts.
 */

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <string.h>

#include "child.h"
#include "childops-netlink.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "utils.h"

/*
 * 96 families is comfortably above what a typical Linux box registers
 * (usually 25-50).  128 ops per family is enough for nl80211, the
 * worst offender at ~100 ops; anything beyond is dropped silently and
 * the random-cmd fallback can still reach it.
 */
#define MAX_FAMILIES		96
#define MAX_OPS_PER_FAMILY	128

struct genl_family_entry {
	uint16_t id;
	uint8_t version;
	uint8_t op_count;
	char name[GENL_NAMSIZ];
	uint8_t ops[MAX_OPS_PER_FAMILY];
};

/*
 * Per-invocation discovery scratch.  Stack-allocated in the persistent
 * fuzz child's genetlink_fuzzer() frame and inherited by the
 * userns_run_in_ns() grandchild via the post-fork CoW address space, so
 * the grandchild reads the catalog the parent built in the HOST netns
 * without re-running CTRL_CMD_GETFAMILY against the fresh netns (where
 * the result would be essentially empty).
 */
struct genl_catalog {
	struct genl_family_entry entries[MAX_FAMILIES];
	unsigned int count;
};

/*
 * Latched per-process: userns_run_in_ns() reported -EPERM, meaning the
 * grandchild's unshare(CLONE_NEWUSER) was refused by a hardened policy
 * (user.max_user_namespaces=0 or kernel.unprivileged_userns_clone=0).
 * Without a private netns we can't safely enumerate families against
 * the host, so the op stays disabled for the remainder of this child's
 * lifetime.  Transient setup failures (helper return < 0 but not
 * -EPERM) do not set this — they may not recur on the next iteration.
 */
static bool ns_unsupported_genetlink_fuzzer;

/*
 * One-shot outputerr on the userns latch transition false->true.
 */
static void warn_once_unsupported_userns(const char *reason, int err)
{
	if (ns_unsupported_genetlink_fuzzer)
		return;
	ns_unsupported_genetlink_fuzzer = true;
	/* check-static: child-output-ok */
	outputerr("genetlink_fuzzer: %s failed (errno=%d), latching unsupported_userns\n",
		  reason, err);
}

/* Strip the NLA_F_NESTED / NLA_F_NET_BYTEORDER flag bits from nla_type. */
static unsigned short nla_type_id(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

/*
 * Walk the CTRL_ATTR_OPS nested container and append each op's
 * CTRL_ATTR_OP_ID into entry->ops.  The container layout is:
 *   [bucket nlattr][CTRL_ATTR_OP_ID u32][CTRL_ATTR_OP_FLAGS u32]
 *   [bucket nlattr][...]
 * where bucket->nla_type is an unnamed index (1, 2, 3, ...).
 */
static void parse_ops_container(struct genl_family_entry *entry,
				const unsigned char *base, size_t len)
{
	size_t off = 0;

	while (off + NLA_HDRLEN <= len &&
	       entry->op_count < MAX_OPS_PER_FAMILY) {
		const struct nlattr *bucket = (const struct nlattr *)(base + off);
		size_t bucket_len = bucket->nla_len;
		size_t ioff;

		if (bucket_len < NLA_HDRLEN || bucket_len > len - off)
			break;

		for (ioff = NLA_HDRLEN; ioff + NLA_HDRLEN <= bucket_len; ) {
			const struct nlattr *inner =
				(const struct nlattr *)((const unsigned char *)bucket + ioff);
			size_t inner_len = inner->nla_len;

			if (inner_len < NLA_HDRLEN || inner_len > bucket_len - ioff)
				break;

			if (nla_type_id(inner) == CTRL_ATTR_OP_ID &&
			    inner_len >= NLA_HDRLEN + sizeof(uint32_t)) {
				uint32_t op;

				memcpy(&op, (const unsigned char *)inner + NLA_HDRLEN,
				       sizeof(op));
				if (entry->op_count < MAX_OPS_PER_FAMILY)
					entry->ops[entry->op_count++] =
						(uint8_t)(op & 0xff);
			}
			ioff += NLA_ALIGN(inner_len);
		}
		off += NLA_ALIGN(bucket_len);
	}
}

/*
 * Parse one CTRL_CMD_NEWFAMILY response and append it to the catalog.
 * The kernel emits one such message per registered family in response to
 * our CTRL_CMD_GETFAMILY/NLM_F_DUMP request.  Skips the entry if the
 * mandatory ID/name fields are missing.
 */
static void parse_family_response(struct genl_catalog *cat,
				  const struct nlmsghdr *nlh)
{
	struct genl_family_entry entry;
	const struct genlmsghdr *genl;
	const unsigned char *attrs;
	size_t attrs_off;
	size_t attrs_len;

	if (cat->count >= MAX_FAMILIES)
		return;
	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return;

	memset(&entry, 0, sizeof(entry));
	genl = (const struct genlmsghdr *)NLMSG_DATA(nlh);
	entry.version = genl->version;

	attrs = (const unsigned char *)nlh + NLMSG_HDRLEN + GENL_HDRLEN;
	attrs_len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	for (attrs_off = 0; attrs_off + NLA_HDRLEN <= attrs_len; ) {
		const struct nlattr *nla = (const struct nlattr *)(attrs + attrs_off);
		size_t nla_len = nla->nla_len;
		const unsigned char *payload;
		size_t payload_len;

		if (nla_len < NLA_HDRLEN || nla_len > attrs_len - attrs_off)
			break;

		payload = (const unsigned char *)nla + NLA_HDRLEN;
		payload_len = nla_len - NLA_HDRLEN;

		switch (nla_type_id(nla)) {
		case CTRL_ATTR_FAMILY_ID:
			if (payload_len >= sizeof(uint16_t))
				memcpy(&entry.id, payload, sizeof(uint16_t));
			break;
		case CTRL_ATTR_FAMILY_NAME: {
			size_t copy = payload_len;

			if (copy >= sizeof(entry.name))
				copy = sizeof(entry.name) - 1;
			memcpy(entry.name, payload, copy);
			entry.name[copy] = '\0';
			break;
		}
		case CTRL_ATTR_VERSION:
			if (payload_len >= sizeof(uint32_t)) {
				uint32_t v;

				memcpy(&v, payload, sizeof(v));
				entry.version = (uint8_t)v;
			}
			break;
		case CTRL_ATTR_OPS:
			parse_ops_container(&entry, payload, payload_len);
			break;
		default:
			break;
		}
		attrs_off += NLA_ALIGN(nla_len);
	}

	/* Drop entries that lack the required fields. */
	if (entry.id == 0 || entry.name[0] == '\0')
		return;

	cat->entries[cat->count++] = entry;
}

/*
 * Callback for nl_send_recv_dump_cb(): forward every CTRL_CMD_NEWFAMILY
 * response to parse_family_response().  Returns 0 unconditionally so
 * the helper walks the whole dump; we want every family the kernel is
 * willing to emit, and the parser drops malformed entries on its own.
 */
static int parse_family_cb(const struct nlmsghdr *nlh, void *arg)
{
	struct genl_catalog *cat = (struct genl_catalog *)arg;

	if (nlh->nlmsg_type == GENL_ID_CTRL)
		parse_family_response(cat, nlh);
	return 0;
}

/*
 * Send CTRL_CMD_GETFAMILY/NLM_F_DUMP and let nl_send_recv_dump_cb()
 * walk the responses, feeding each NEWFAMILY to parse_family_response()
 * via parse_family_cb().  Returns the helper's return code verbatim so
 * the caller can tell a clean walk (0; cat->count==0 then means a
 * genuinely empty registry) from a mid-dump NLMSG_ERROR (negated errno)
 * and from a local I/O failure (-EIO, which also covers recv timeout).
 * The previous (void)-cast collapsed all three cases into a single
 * silent return path -- without the rc the empty-catalog stat could
 * not distinguish transport breakage from a real empty registry.
 */
static int do_discovery(struct nl_ctx *ctx, struct genl_catalog *cat)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = nl_seq_next(ctx);
	req.nlh.nlmsg_pid = 0;
	req.genl.cmd = CTRL_CMD_GETFAMILY;
	req.genl.version = 1;

	return nl_send_recv_dump_cb(ctx, &req, req.nlh.nlmsg_len,
				    parse_family_cb, cat);
}

/*
 * Per-NLMSG_ERROR callback for nl_send_drain_errors(): bump the
 * genetlink_eperm stat when the kernel rejects an op with -EPERM /
 * -EACCES.  arg is unused — each grandchild only sends one message, so
 * there is no cross-message family-needs-priv state to maintain.
 */
static void genl_on_err(int err, void *arg)
{
	(void)arg;

	if (err == -EPERM || err == -EACCES)
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.eperm, 1,
				   __ATOMIC_RELAXED);
}

/*
 * Build and send one structurally-valid genetlink message for the given
 * family.  Header type is the family's real ID and the genlmsghdr.cmd is
 * drawn from the family's registered op list (with a small chance of a
 * random cmd to probe the family's unknown-cmd path).  Random nlattrs
 * follow — mostly garbage payloads, but sized correctly so the parser
 * walks them rather than rejecting on the first NLA_HDRLEN check.
 *
 * The post-send drain (NLMSG_ERROR inspection + receive-queue cleanup)
 * lives in nl_send_drain_errors(); genl_on_err() bumps the EPERM stat.
 */
static void send_fuzzed_msg(struct nl_ctx *ctx, const struct genl_family_entry *fam)
{
	unsigned char buf[2048];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *genl;
	size_t off;
	int num_attrs;
	uint8_t cmd;
	__u32 seq;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);

	if (fam->op_count > 0 && !ONE_IN(8))
		cmd = fam->ops[rnd_modulo_u32(fam->op_count)];
	else
		cmd = (uint8_t)(rnd_u32() & 0xff);

	seq = nl_seq_next(ctx);
	nlh->nlmsg_type = fam->id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (RAND_BOOL())
		nlh->nlmsg_flags |= NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = 0;

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = cmd;
	genl->version = fam->version > 0 ? fam->version : 1;
	genl->reserved = 0;

	off = NLMSG_HDRLEN + GENL_HDRLEN;

	num_attrs = rnd_modulo_u32(6);
	while (num_attrs-- > 0 && off + NLA_HDRLEN + 64 <= sizeof(buf)) {
		struct nlattr *nla = (struct nlattr *)(buf + off);
		size_t payload_len = RAND_RANGE(0, 48);

		nla->nla_type = (unsigned short)(rnd_u32() & NLA_TYPE_MASK);
		if (ONE_IN(4))
			nla->nla_type |= NLA_F_NESTED;
		nla->nla_len = NLA_HDRLEN + payload_len;
		if (payload_len > 0)
			generate_rand_bytes(buf + off + NLA_HDRLEN, payload_len);
		off += NLA_ALIGN(nla->nla_len);
	}

	nlh->nlmsg_len = off;

	if (nl_send_drain_errors(ctx, buf, off, seq, genl_on_err, NULL) < 0) {
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.send_drain_fail,
				   1, __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.genetlink_fuzzer.msgs_sent, 1, __ATOMIC_RELAXED);
}

/*
 * Per-invocation state handed to the in-ns callback so it can keep
 * accounting against the right childop slot.  The parent fills in
 * @cat in the host net namespace before forking the grandchild; the
 * grandchild reads it without re-running CTRL_CMD_GETFAMILY -- the
 * fresh netns it runs in would return an essentially empty catalog
 * and the op would silently bail.
 */
struct genetlink_fuzzer_ctx {
	struct childdata *child;
	const struct genl_catalog *cat;
};

/*
 * Per-invocation body that must run inside the private user + net
 * namespace.  Executed in a transient grandchild forked by
 * userns_run_in_ns(); the grandchild's userns + netns are torn down on
 * _exit() so the genetlink socket is reaped by the kernel along with
 * the namespace.  The catalog itself is built by the parent (in the
 * host netns) and read here through cctx->cat; we do NOT redo
 * CTRL_CMD_GETFAMILY in the fresh netns, since that registry is
 * effectively empty and the dump would silently fail us out.
 *
 * Setup accounting (childop_setup_accepted / genetlink_families_
 * discovered) is bumped by the parent right after build_catalog()
 * succeeds; this body only bumps childop_data_path once we are about
 * to send.  A grandchild-side nl_open() failure -- for any errno --
 * is logged via outputerr, but is treated as a data-path miss rather
 * than a setup miss: the setup gate (discovery) has already passed.
 * Return value is ignored by the helper.
 */
static int genetlink_fuzzer_in_ns(void *arg)
{
	struct genetlink_fuzzer_ctx *cctx = (struct genetlink_fuzzer_ctx *)arg;
	struct childdata *child = cctx->child;
	const struct genl_catalog *cat = cctx->cat;
	static const struct nl_open_opts opts = {
		.proto         = NETLINK_GENERIC,
		.recv_timeo_us = 250000,
	};
	struct nl_ctx ctx = { .fd = -1 };
	const struct genl_family_entry *fam;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nl_open(&ctx, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.in_ns_open_fail,
				   1, __ATOMIC_RELAXED);
		/* check-static: child-output-ok */
		outputerr("genetlink_fuzzer: nl_open(NETLINK_GENERIC) failed in fresh netns (errno=%d)\n",
			  errno);
		return 0;
	}

	fam = &cat->entries[rnd_modulo_u32(cat->count)];

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	send_fuzzed_msg(&ctx, fam);

	nl_close(&ctx);
	return 0;
}

/*
 * Build a catalog of registered genetlink families by talking to the
 * controller from the persistent fuzz child, in the host net
 * namespace.  Returns true with @cat populated (count > 0) on success;
 * otherwise bumps the appropriate diagnostic counter and returns false
 * so the caller can skip the grandchild fork entirely.  Splitting the
 * empty-catalog cause across three counters
 * (missing_producer / discovery_io_err / discovery_nlerr) keeps a
 * genuinely empty kernel registry separable from a recv timeout and
 * from a controller-side NLMSG_ERROR -- previously all three collapsed
 * into a single silent return and showed only as derived setup_fail.
 */
static bool build_catalog(struct genl_catalog *cat)
{
	static const struct nl_open_opts opts = {
		.proto         = NETLINK_GENERIC,
		.recv_timeo_us = 250000,
	};
	struct nl_ctx ctx = { .fd = -1 };
	int rc;

	memset(cat, 0, sizeof(*cat));

	if (nl_open(&ctx, &opts) < 0)
		return false;

	rc = do_discovery(&ctx, cat);
	nl_close(&ctx);

	if (cat->count > 0)
		return true;

	if (rc == -EIO)
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.discovery_io_err,
				   1, __ATOMIC_RELAXED);
	else if (rc < 0)
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.discovery_nlerr,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.missing_producer,
				   1, __ATOMIC_RELAXED);
	return false;
}

bool genetlink_fuzzer(struct childdata *child)
{
	struct genl_catalog cat;
	struct genetlink_fuzzer_ctx cctx = { .child = child, .cat = &cat };
	int rc;
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch_reason array.  The field lives in shared
	 * memory and can be scribbled by a poisoned-arena write from a
	 * sibling; skip the latch write entirely when the snapshot is
	 * out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_genetlink_fuzzer)
		return true;

	/* Discovery runs HERE -- in the persistent fuzz child, in the
	 * host net namespace -- so the catalog is non-empty before the
	 * grandchild's unshare(CLONE_NEWNET).  The fresh netns would
	 * report essentially no registered families, so dumping the
	 * controller inside it (the prior shape) produced an empty
	 * catalog and bailed silently. */
	if (!build_catalog(&cat))
		return true;

	/* Discovery is the real setup gate: once build_catalog() returns
	 * with count > 0 we have a family registry the fuzzer can drive
	 * against, and everything downstream (grandchild fork, userns +
	 * netns bootstrap, in-ns nl_open, send) is data-path.  Bumping
	 * childop_setup_accepted here rather than after the grandchild's
	 * nl_open keeps a per-iteration hiccup inside the grandchild
	 * (a transient EMFILE from an inherited fd table, an LSM refusal,
	 * anything past discovery) from stalling the counter at zero and
	 * tripping the canary's setup_broken early-bail even though the
	 * dispatch boundary the check is meant to detect is clean.  The
	 * families_discovered diagnostic follows the same logic: it counts
	 * successful discovery cycles, which happen in this frame. */
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.genetlink_fuzzer.families_discovered,
			   cat.count, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.genetlink_fuzzer.discovery_cycles,
			   1, __ATOMIC_RELAXED);

	rc = userns_run_in_ns(CLONE_NEWNET, genetlink_fuzzer_in_ns, &cctx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.userns_run_fail,
				   1, __ATOMIC_RELAXED);
		warn_once_unsupported_userns("userns_run_in_ns(CLONE_NEWNET)", EPERM);
		return true;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without latching
		 * -- the failure is not policy and may not recur. */
		__atomic_add_fetch(&shm->stats.genetlink_fuzzer.userns_run_fail,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	return true;
}
