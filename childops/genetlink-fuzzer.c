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
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "child.h"
#include "random.h"
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
static int genl_sock = -1;
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
 * Send CTRL_CMD_GETFAMILY/NLM_F_DUMP and consume responses until we see
 * NLMSG_DONE, an NLMSG_ERROR, or recv() times out.  Each NEWFAMILY
 * response gets passed to parse_family_response() which appends it to
 * the catalog.  Returns 0 on a clean walk (regardless of how many
 * families we found), -1 on send failure.
 */
static int do_discovery(int sock)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
	} req;
	unsigned char buf[16384];
	ssize_t n;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.nlh.nlmsg_pid = 0;
	req.genl.cmd = CTRL_CMD_GETFAMILY;
	req.genl.version = 1;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0)
		return -1;

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(sock, buf, sizeof(buf), 0);
		if (n <= 0)
			return 0;	/* timeout or EOF — done */

		nlh = (struct nlmsghdr *)buf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR)
				return 0;
			if (nlh->nlmsg_type == GENL_ID_CTRL)
				parse_family_response(nlh);
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
}

/*
 * One-shot setup: open the socket, set a short recv timeout so a
 * misbehaving kernel can't wedge us, run discovery, latch the result.
 * On any failure we set discovery_failed and become a noop forever for
 * this child.  Returns true if the catalog is usable.
 */
static bool ensure_discovery(void)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };

	if (discovery_failed)
		return false;
	if (discovery_done)
		return true;

	if (genl_sock < 0) {
		genl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
		if (genl_sock < 0) {
			discovery_failed = true;
			if (!warned_unsupported) {
				warned_unsupported = true;
				output(0, "genetlink_fuzzer: socket(NETLINK_GENERIC) failed (errno=%d), disabling\n",
				       errno);
			}
			return false;
		}
		(void)setsockopt(genl_sock, SOL_SOCKET, SO_RCVTIMEO,
				 &tv, sizeof(tv));
	}

	if (do_discovery(genl_sock) < 0 || catalog_count == 0) {
		discovery_failed = true;
		if (!warned_unsupported) {
			warned_unsupported = true;
			output(0, "genetlink_fuzzer: GETFAMILY discovery yielded %u families, disabling\n",
			       catalog_count);
		}
		return false;
	}

	discovery_done = true;
	__atomic_add_fetch(&shm->stats.genetlink_families_discovered,
			   catalog_count, __ATOMIC_RELAXED);
	return true;
}

/*
 * Build and send one structurally-valid genetlink message for the given
 * family.  Header type is the family's real ID and the genlmsghdr.cmd is
 * drawn from the family's registered op list (with a small chance of a
 * random cmd to probe the family's unknown-cmd path).  Random nlattrs
 * follow — mostly garbage payloads, but sized correctly so the parser
 * walks them rather than rejecting on the first NLA_HDRLEN check.
 *
 * If the kernel rejects with EPERM/EACCES (either at send-time or via an
 * NLMSG_ERROR ack), latch fam->needs_priv so the caller stops picking it.
 */
static void send_fuzzed_msg(int sock, struct genl_family_entry *fam)
{
	unsigned char buf[2048];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *genl;
	size_t off;
	int num_attrs;
	uint8_t cmd;
	ssize_t sent;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);

	if (fam->op_count > 0 && !ONE_IN(8))
		cmd = fam->ops[rand() % fam->op_count];
	else
		cmd = (uint8_t)(rand() & 0xff);

	nlh->nlmsg_type = fam->id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (RAND_BOOL())
		nlh->nlmsg_flags |= NLM_F_DUMP;
	nlh->nlmsg_seq = rand32();
	nlh->nlmsg_pid = 0;

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = cmd;
	genl->version = fam->version > 0 ? fam->version : 1;
	genl->reserved = 0;

	off = NLMSG_HDRLEN + GENL_HDRLEN;

	num_attrs = rand() % 6;
	while (num_attrs-- > 0 && off + NLA_HDRLEN + 64 <= sizeof(buf)) {
		struct nlattr *nla = (struct nlattr *)(buf + off);
		size_t payload_len = RAND_RANGE(0, 48);

		nla->nla_type = (unsigned short)(rand() & NLA_TYPE_MASK);
		if (ONE_IN(4))
			nla->nla_type |= NLA_F_NESTED;
		nla->nla_len = NLA_HDRLEN + payload_len;
		if (payload_len > 0)
			generate_rand_bytes(buf + off + NLA_HDRLEN, payload_len);
		off += NLA_ALIGN(nla->nla_len);
	}

	nlh->nlmsg_len = off;

	sent = send(sock, buf, off, 0);
	if (sent < 0) {
		if (errno == EPERM || errno == EACCES) {
			fam->needs_priv = true;
			__atomic_add_fetch(&shm->stats.genetlink_eperm, 1,
					   __ATOMIC_RELAXED);
		}
		return;
	}

	__atomic_add_fetch(&shm->stats.genetlink_msgs_sent, 1, __ATOMIC_RELAXED);

	/*
	 * Drain any pending NLMSG_ERROR / ACK so the kernel's send queue
	 * doesn't back up.  A non-blocking recv() returns immediately if
	 * nothing is queued, and our SO_RCVTIMEO bounds blocking otherwise.
	 * If we see -EPERM / -EACCES, mark the family priv-only.
	 */
	{
		unsigned char rbuf[1024];
		ssize_t r = recv(sock, rbuf, sizeof(rbuf), MSG_DONTWAIT);

		if (r >= (ssize_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr))) {
			const struct nlmsghdr *rnlh = (const struct nlmsghdr *)rbuf;

			if (rnlh->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *err =
					(const struct nlmsgerr *)NLMSG_DATA(rnlh);

				if (err->error == -EPERM ||
				    err->error == -EACCES) {
					fam->needs_priv = true;
					__atomic_add_fetch(&shm->stats.genetlink_eperm,
							   1, __ATOMIC_RELAXED);
				}
			}
		}
	}
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
		idx = (int)(rand() % catalog_count);
		if (!catalog[idx].needs_priv)
			break;
	}
	fam = &catalog[idx];
	if (fam->needs_priv)
		return true;

	send_fuzzed_msg(genl_sock, fam);
	return true;
}
