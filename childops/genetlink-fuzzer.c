/*
 * genetlink_fuzzer - structurally-valid generic netlink fuzzing.
 *
 * Generic netlink families are the fastest-growing kernel attack surface.
 * nl80211 alone has accumulated 15+ public CVEs, most rooted in incorrect
 * or missing per-attribute validation in deep parser paths.  Trinity's
 * existing general netlink path (net/netlink-msg.c) constructs
 * NETLINK_GENERIC messages with random nlmsg_type and random genlmsghdr.cmd,
 * which is useful for exercising the unknown-family fast-reject path but
 * almost never lines up with a real registered family ID, so the actual
 * per-family parsers — where the bugs live — stay cold.
 *
 * This childop closes the gap.  At the first invocation per child we
 * enumerate the registered families via CTRL_CMD_GETFAMILY/NLM_F_DUMP and
 * cache a small catalog of {family_id, name, version, ops[]}.  Each
 * subsequent call picks a random family, a random op from its registered
 * command list, and constructs a message with the matching nlmsghdr type
 * and genlmsghdr cmd.  The kernel's family demuxer accepts the type, the
 * version check passes, and we land directly in the family's command
 * dispatch table — exactly the surface trinity has historically missed.
 *
 * Important families this catches automatically when present:
 *   nl80211 (WiFi config), devlink, ethtool, dpll, mptcp_pm, ovs (OVS),
 *   nbd, TIPC, taskstats, NET_DM, ...
 *
 * Trinity-todo top-10 #6.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
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
	bool needs_priv;	/* set when the family rejected us with EPERM/EACCES */
	char name[GENL_NAMSIZ];
	uint8_t ops[MAX_OPS_PER_FAMILY];
};

/*
 * Per-child static state.  Each trinity child does its own discovery
 * because it may have unshared into its own netns (see init_child:
 * unshare(CLONE_NEWNET)) where a different set of families is visible.
 * The catalog lives in BSS; ~15KB per child is cheap.
 */
static struct genl_family_entry catalog[MAX_FAMILIES];
static unsigned int catalog_count;
static struct nl_ctx genl_ctx;
static bool genl_ctx_open;
static bool discovery_done;
static bool discovery_failed;
static bool warned_unsupported;

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
static void parse_family_response(const struct nlmsghdr *nlh)
{
	struct genl_family_entry entry;
	const struct genlmsghdr *genl;
	const unsigned char *attrs;
	size_t attrs_off;
	size_t attrs_len;

	if (catalog_count >= MAX_FAMILIES)
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

	catalog[catalog_count++] = entry;
}

/*
 * Callback for nl_send_recv_dump_cb(): forward every CTRL_CMD_NEWFAMILY
 * response to parse_family_response().  Returns 0 unconditionally so
 * the helper walks the whole dump; we want every family the kernel is
 * willing to emit, and the parser drops malformed entries on its own.
 */
static int parse_family_cb(const struct nlmsghdr *nlh, void *arg)
{
	(void)arg;
	if (nlh->nlmsg_type == GENL_ID_CTRL)
		parse_family_response(nlh);
	return 0;
}

/*
 * Send CTRL_CMD_GETFAMILY/NLM_F_DUMP and let nl_send_recv_dump_cb()
 * walk the responses, feeding each NEWFAMILY to parse_family_response()
 * via parse_family_cb().  The helper returns 0 on NLMSG_DONE, the
 * negated NLMSG_ERROR errno on a mid-dump error, and -EIO on local I/O
 * failure (including recv timeout).  We ignore the return value: the
 * downstream catalog_count > 0 check in ensure_discovery() is the
 * single source of truth for "do we have a usable catalog", same as
 * the prior open-coded loop which also treated NLMSG_ERROR and recv
 * timeout as clean walks.
 */
static int do_discovery(struct nl_ctx *ctx)
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

	(void)nl_send_recv_dump_cb(ctx, &req, req.nlh.nlmsg_len,
				   parse_family_cb, NULL);
	return 0;
}

/*
 * One-shot setup: open the socket via the shared scaffolding (which
 * applies the 250ms recv timeout so a misbehaving kernel can't wedge
 * us), run discovery, latch the result.  On any failure we set
 * discovery_failed and become a noop forever for this child.  Returns
 * true if the catalog is usable.
 */
static bool ensure_discovery(void)
{
	static const struct nl_open_opts opts = {
		.proto         = NETLINK_GENERIC,
		.recv_timeo_us = 250000,
	};

	if (discovery_failed)
		return false;
	if (discovery_done)
		return true;

	if (!genl_ctx_open) {
		if (nl_open(&genl_ctx, &opts) < 0) {
			discovery_failed = true;
			if (!warned_unsupported) {
				warned_unsupported = true;
				outputerr("genetlink_fuzzer: nl_open(NETLINK_GENERIC) failed (errno=%d), disabling\n",
				          errno);
			}
			return false;
		}
		genl_ctx_open = true;
	}

	(void)do_discovery(&genl_ctx);
	if (catalog_count == 0) {
		discovery_failed = true;
		nl_close(&genl_ctx);
		genl_ctx_open = false;
		if (!warned_unsupported) {
			warned_unsupported = true;
			outputerr("genetlink_fuzzer: GETFAMILY discovery yielded %u families, disabling\n",
			          catalog_count);
		}
		return false;
	}

	/* genl_ctx stays open for this child's lifetime; send_fuzzed_msg()
	 * uses it on every subsequent call. */
	discovery_done = true;
	__atomic_add_fetch(&shm->stats.genetlink_families_discovered,
			   catalog_count, __ATOMIC_RELAXED);
	return true;
}

/*
 * Per-NLMSG_ERROR callback for nl_send_drain_errors().  Latches
 * fam->needs_priv when the kernel rejects an op with -EPERM/-EACCES so
 * the picker in genetlink_fuzzer() stops choosing that family.
 */
static void genl_on_err(int err, void *arg)
{
	struct genl_family_entry *fam = arg;

	if (err == -EPERM || err == -EACCES) {
		fam->needs_priv = true;
		__atomic_add_fetch(&shm->stats.genetlink_eperm, 1,
				   __ATOMIC_RELAXED);
	}
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
 * lives in nl_send_drain_errors(); genl_on_err() latches
 * fam->needs_priv on -EPERM/-EACCES.
 */
static void send_fuzzed_msg(struct nl_ctx *ctx, struct genl_family_entry *fam)
{
	unsigned char buf[2048];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *genl;
	size_t off;
	int num_attrs;
	uint8_t cmd;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);

	if (fam->op_count > 0 && !ONE_IN(8))
		cmd = fam->ops[rnd_modulo_u32(fam->op_count)];
	else
		cmd = (uint8_t)(rnd_u32() & 0xff);

	nlh->nlmsg_type = fam->id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (RAND_BOOL())
		nlh->nlmsg_flags |= NLM_F_DUMP;
	nlh->nlmsg_seq = nl_seq_next(ctx);
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

	if (nl_send_drain_errors(ctx, buf, off, genl_on_err, fam) < 0)
		return;

	__atomic_add_fetch(&shm->stats.genetlink_msgs_sent, 1, __ATOMIC_RELAXED);
}

bool genetlink_fuzzer(struct childdata *child)
{
	struct genl_family_entry *fam;
	int idx = 0;
	int attempts;

	(void)child;

	if (!ensure_discovery())
		return true;

	/* Pick a non-priv family.  After a few attempts, give up rather
	 * than spinning in a kernel that has marked everything priv-only. */
	for (attempts = 0; attempts < 8; attempts++) {
		idx = (int)rnd_modulo_u32(catalog_count);
		if (!catalog[idx].needs_priv)
			break;
	}
	fam = &catalog[idx];
	if (fam->needs_priv)
		return true;

	send_fuzzed_msg(&genl_ctx, fam);
	return true;
}
