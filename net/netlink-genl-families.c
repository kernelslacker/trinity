/*
 * Generic netlink runtime family resolver and registry.
 *
 * Per-family grammar tables (net/netlink-genl-fam-*.c) declare their
 * commands and attribute kinds statically; this file walks that
 * registry on first use, asks the kernel for each family's
 * dynamically-assigned family_id via CTRL_CMD_GETFAMILY/NLM_F_DUMP,
 * and exposes lookup helpers used by the netlink message generator
 * to send structurally-valid messages addressed to specific families.
 *
 * A registered family's cmds[] + attrs[] table is what unlocks fuzz
 * coverage of that family's per-command parsers: the kernel's family
 * demuxer accepts the family_id, the version check passes, and the
 * message lands directly in the family's command dispatch table where
 * bugs actually live, instead of bouncing off an unknown-family
 * fast-reject as the legacy random-id path does.
 *
 * The runtime-discovery childop in childops/genetlink-fuzzer.c does
 * its own discovery for the ops list it caches per family; that path
 * is intentionally separate so the two don't share fragile state and
 * each can evolve at its own pace.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "netlink-genl-families.h"
#include "random.h"
#include "trinity.h"
#include "utils.h"

extern struct genl_family_grammar fam_devlink;
extern struct genl_family_grammar fam_nl80211;
extern struct genl_family_grammar fam_taskstats;
extern struct genl_family_grammar fam_ethtool;

/*
 * Per-family grammar definitions live in net/netlink-genl-fam-*.c;
 * each new family adds an extern declaration above and a pointer
 * here.  Lookups skip NULL entries so a temporary placeholder is
 * harmless if a family ever needs to be ifdef'd out.
 */
static struct genl_family_grammar *registry[] = {
	&fam_devlink,
	&fam_nl80211,
	&fam_taskstats,
	&fam_ethtool,
};

static int discovery_done;

static unsigned int registry_real_count(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < ARRAY_SIZE(registry); i++)
		if (registry[i] != NULL)
			n++;
	return n;
}

static unsigned short nla_type_id(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

/*
 * Match a NEWFAMILY response to a registered grammar by name.  Sets
 * the family_id and clears unavailable when found.  The kernel
 * zero-pads CTRL_ATTR_FAMILY_NAME so a strcmp against the registry
 * name is safe as long as parse_family_response() NUL-terminated the
 * scratch buffer it passes in.
 */
static void match_response(const char *name, unsigned short id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL)
			continue;
		if (strcmp(registry[i]->name, name) != 0)
			continue;
		registry[i]->family_id = id;
		registry[i]->resolved = 1;
		registry[i]->unavailable = 0;
		return;
	}
}

/*
 * Walk a single CTRL_CMD_NEWFAMILY response, extract FAMILY_NAME +
 * FAMILY_ID, and dispatch to match_response().  Skips entries lacking
 * either field.  Mirrors the parser in childops/genetlink-fuzzer.c —
 * intentionally separate so the two paths don't share fragile state.
 */
static void parse_family_response(const struct nlmsghdr *nlh)
{
	const unsigned char *attrs;
	size_t attrs_off;
	size_t attrs_len;
	char name[GENL_NAMSIZ];
	unsigned short id = 0;
	int have_name = 0;
	int have_id = 0;

	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return;

	memset(name, 0, sizeof(name));
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
			if (payload_len >= sizeof(unsigned short)) {
				memcpy(&id, payload, sizeof(unsigned short));
				have_id = 1;
			}
			break;
		case CTRL_ATTR_FAMILY_NAME: {
			size_t copy = payload_len;

			if (copy >= sizeof(name))
				copy = sizeof(name) - 1;
			memcpy(name, payload, copy);
			name[copy] = '\0';
			have_name = 1;
			break;
		}
		default:
			break;
		}
		attrs_off += NLA_ALIGN(nla_len);
	}

	if (have_name && have_id && id != 0)
		match_response(name, id);
}

/*
 * Send CTRL_CMD_GETFAMILY/NLM_F_DUMP and consume responses until we
 * see NLMSG_DONE / NLMSG_ERROR / recv() timeout.  Each NEWFAMILY
 * message gets passed to parse_family_response() which stamps the
 * matching registry entry's family_id.
 */
static int do_dump(int sock)
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
			return 0; /* timeout / EOF — done */

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

void genl_resolve_families(void)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };
	unsigned int i;
	int sock;

	if (discovery_done)
		return;
	discovery_done = 1;

	if (registry_real_count() == 0)
		return;	/* no families registered yet — nothing to ask about */

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0)
		return; /* leave every family unavailable; lookups become noops */
	(void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	(void)do_dump(sock);
	close(sock);

	/* Anything we didn't hear back about is missing from this kernel. */
	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL)
			continue;
		if (!registry[i]->resolved)
			registry[i]->unavailable = 1;
	}
}

struct genl_family_grammar *genl_pick_resolved_family(void)
{
	unsigned int resolved_count = 0;
	unsigned int i;
	unsigned int pick;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] != NULL && registry[i]->resolved)
			resolved_count++;
	}
	if (resolved_count == 0)
		return NULL;

	pick = rand() % resolved_count;
	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL || !registry[i]->resolved)
			continue;
		if (pick-- == 0)
			return registry[i];
	}
	return NULL;
}

const struct genl_family_grammar *genl_lookup_by_id(unsigned short family_id)
{
	unsigned int i;

	if (family_id == 0)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL || !registry[i]->resolved)
			continue;
		if (registry[i]->family_id == family_id)
			return registry[i];
	}
	return NULL;
}

unsigned char genl_pick_cmd(const struct genl_family_grammar *fam)
{
	if (!fam || fam->n_cmds == 0)
		return 0;
	return fam->cmds[rand() % fam->n_cmds].cmd;
}
