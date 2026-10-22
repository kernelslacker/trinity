/*
 * Generic netlink runtime family resolver and registry.
 *
 * Per-family grammar tables (net/netlink/genl/<family>.c) declare their
 * commands and attribute kinds statically; this file walks that
 * registry on first use, asks the kernel for each family's
 * dynamically-assigned family_id and the doit/dumpit shape of its ops
 * via CTRL_CMD_GETFAMILY/NLM_F_DUMP, and exposes lookup helpers used
 * by the netlink message generator to send structurally-valid
 * messages addressed to specific families.
 *
 * A registered family's cmds[] + attrs[] table is what unlocks fuzz
 * coverage of that family's per-command parsers: the kernel's family
 * demuxer accepts the family_id and the message lands directly in the
 * family's command dispatch table where bugs actually live, instead of
 * bouncing off an unknown-family fast-reject as the legacy random-id
 * path does.
 */

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <string.h>

#include "netlink-genl-families.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"
#include "rnd.h"

#include "kernel/socket.h"
extern struct genl_family_grammar fam_devlink;
extern struct genl_family_grammar fam_nl80211;
extern struct genl_family_grammar fam_taskstats;
#if __has_include(<linux/ethtool_netlink_generated.h>)
extern struct genl_family_grammar fam_ethtool;
#endif
#if __has_include(<linux/netdev.h>)
extern struct genl_family_grammar fam_netdev;
#endif
#if __has_include(<linux/mptcp_pm.h>)
extern struct genl_family_grammar fam_mptcp_pm;
#endif
#if __has_include(<linux/tipc_netlink.h>)
extern struct genl_family_grammar fam_tipc;
#endif
#if __has_include(<linux/wireguard.h>)
extern struct genl_family_grammar fam_wireguard;
#endif
#if __has_include(<linux/openvswitch.h>)
extern struct genl_family_grammar fam_ovs_datapath;
extern struct genl_family_grammar fam_ovs_vport;
extern struct genl_family_grammar fam_ovs_flow;
extern struct genl_family_grammar fam_ovs_packet;
extern struct genl_family_grammar fam_ovs_meter;
extern struct genl_family_grammar fam_ovs_ct_limit;
#endif
#if __has_include(<linux/l2tp.h>)
extern struct genl_family_grammar fam_l2tp;
#endif
#if __has_include(<linux/gtp.h>)
extern struct genl_family_grammar fam_gtp;
#endif
#if __has_include(<linux/if_macsec.h>)
extern struct genl_family_grammar fam_macsec;
#endif
#if __has_include(<linux/if_team.h>)
extern struct genl_family_grammar fam_team;
#endif
#if __has_include(<linux/hsr_netlink.h>)
extern struct genl_family_grammar fam_hsr;
#endif
#if __has_include(<linux/fou.h>)
extern struct genl_family_grammar fam_fou;
#endif
#if __has_include(<linux/psample.h>)
extern struct genl_family_grammar fam_psample;
#endif
#if __has_include(<linux/ncsi.h>)
extern struct genl_family_grammar fam_ncsi;
#endif
#if __has_include(<linux/target_core_user.h>)
extern struct genl_family_grammar fam_tcmu;
#endif
#if __has_include(<linux/nfsd_netlink.h>)
extern struct genl_family_grammar fam_nfsd;
#endif
#if __has_include(<linux/sunrpc_netlink.h>)
extern struct genl_family_grammar fam_sunrpc;
#endif
/* psp consumes include/kernel/psp.h, whose own <linux/psp.h> include is
 * __has_include-guarded with per-symbol shims for every PSP_CMD_ and
 * PSP_A_ id the grammar uses -- so fam_psp builds (and registers) on
 * stripped sysroots that lack the upstream uapi header. */
extern struct genl_family_grammar fam_psp;
#if __has_include(<linux/net_dropmon.h>)
extern struct genl_family_grammar fam_net_dm;
#endif
#if __has_include(<linux/smc.h>)
extern struct genl_family_grammar fam_smc_pnetid;
extern struct genl_family_grammar fam_smc_gen;
#endif
#if __has_include(<linux/ila.h>)
extern struct genl_family_grammar fam_ila;
#endif
#if __has_include(<linux/ioam6_genl.h>)
extern struct genl_family_grammar fam_ioam6;
#endif
#if __has_include(<linux/seg6_genl.h>)
extern struct genl_family_grammar fam_seg6;
#endif
#if __has_include(<linux/thermal.h>)
extern struct genl_family_grammar fam_thermal;
#endif
#if __has_include(<linux/ip_vs.h>)
extern struct genl_family_grammar fam_ipvs;
#endif
#if __has_include(<linux/batman_adv.h>)
extern struct genl_family_grammar fam_batadv;
#endif
#if __has_include(<linux/tcp_metrics.h>)
extern struct genl_family_grammar fam_tcp_metrics;
#endif
#if __has_include(<linux/ovpn.h>)
extern struct genl_family_grammar fam_ovpn;
#endif
#if __has_include(<linux/net_shaper.h>)
extern struct genl_family_grammar fam_net_shaper;
#endif
#if __has_include(<linux/nbd-netlink.h>)
extern struct genl_family_grammar fam_nbd;
#endif
#if __has_include(<linux/nfc.h>)
extern struct genl_family_grammar fam_nfc;
#endif
#if __has_include(<linux/dpll.h>)
extern struct genl_family_grammar fam_dpll;
#endif
#if __has_include(<linux/handshake.h>)
extern struct genl_family_grammar fam_handshake;
#endif
#if __has_include(<linux/vdpa.h>)
extern struct genl_family_grammar fam_vdpa;
#endif
#if __has_include(<linux/cifs/cifs_netlink.h>)
extern struct genl_family_grammar fam_cifs;
#endif
extern struct genl_family_grammar fam_nlbl_mgmt;
extern struct genl_family_grammar fam_nlbl_cipsov4;
extern struct genl_family_grammar fam_nlbl_unlabel;
extern struct genl_family_grammar fam_nlbl_calipso;
#if __has_include(<linux/lockd_netlink.h>)
extern struct genl_family_grammar fam_lockd;
#endif
#if __has_include(<linux/dev_energymodel.h>)
extern struct genl_family_grammar fam_dev_energymodel;
#endif
#if __has_include(<drm/drm_ras.h>)
extern struct genl_family_grammar fam_drm_ras;
#endif
/* nl802154 vendors its CMD/ATTR ids in include/kernel/nl802154.h
 * because the kernel-side enum (include/net/nl802154.h) is not
 * shipped via uapi; the grammar registers unconditionally and
 * runtime CTRL_CMD_GETFAMILY decides whether the running kernel
 * carries the family. */
extern struct genl_family_grammar fam_nl802154;
/* The legacy "802.15.4 MAC" family (kernel net/ieee802154/netlink.c)
 * is a distinct genl family from the modern nl802154 above; its CMD/
 * ATTR enum lives in include/linux/nl802154.h which is also not
 * shipped via uapi, so the grammar vendors its ids in
 * include/kernel/ieee802154.h and registers unconditionally. */
extern struct genl_family_grammar fam_ieee802154;
/* Binder genl family carries every id via include/kernel/binder_netlink.h
 * #ifndef shims, so the grammar builds and registers unconditionally on
 * hosts whose uapi predates the mainlined <linux/android/binder_netlink.h>. */
extern struct genl_family_grammar fam_binder;

/*
 * Per-family grammar definitions live in net/netlink/genl/<family>.c;
 * each new family adds an extern declaration above and a pointer
 * here.  Lookups skip NULL entries so a temporary placeholder is
 * harmless if a family ever needs to be ifdef'd out.
 */
static struct genl_family_grammar *registry[] = {
	&fam_devlink,
	&fam_nl80211,
	&fam_taskstats,
#if __has_include(<linux/ethtool_netlink_generated.h>)
	&fam_ethtool,
#endif
#if __has_include(<linux/netdev.h>)
	&fam_netdev,
#endif
#if __has_include(<linux/mptcp_pm.h>)
	&fam_mptcp_pm,
#endif
#if __has_include(<linux/tipc_netlink.h>)
	&fam_tipc,
#endif
#if __has_include(<linux/wireguard.h>)
	&fam_wireguard,
#endif
#if __has_include(<linux/openvswitch.h>)
	&fam_ovs_datapath,
	&fam_ovs_vport,
	&fam_ovs_flow,
	&fam_ovs_packet,
	&fam_ovs_meter,
	&fam_ovs_ct_limit,
#endif
#if __has_include(<linux/l2tp.h>)
	&fam_l2tp,
#endif
#if __has_include(<linux/gtp.h>)
	&fam_gtp,
#endif
#if __has_include(<linux/if_macsec.h>)
	&fam_macsec,
#endif
#if __has_include(<linux/if_team.h>)
	&fam_team,
#endif
#if __has_include(<linux/hsr_netlink.h>)
	&fam_hsr,
#endif
#if __has_include(<linux/fou.h>)
	&fam_fou,
#endif
#if __has_include(<linux/psample.h>)
	&fam_psample,
#endif
#if __has_include(<linux/ncsi.h>)
	&fam_ncsi,
#endif
#if __has_include(<linux/target_core_user.h>)
	&fam_tcmu,
#endif
#if __has_include(<linux/nfsd_netlink.h>)
	&fam_nfsd,
#endif
#if __has_include(<linux/sunrpc_netlink.h>)
	&fam_sunrpc,
#endif
	&fam_psp,
#if __has_include(<linux/net_dropmon.h>)
	&fam_net_dm,
#endif
#if __has_include(<linux/smc.h>)
	&fam_smc_pnetid,
	&fam_smc_gen,
#endif
#if __has_include(<linux/ila.h>)
	&fam_ila,
#endif
#if __has_include(<linux/ioam6_genl.h>)
	&fam_ioam6,
#endif
#if __has_include(<linux/seg6_genl.h>)
	&fam_seg6,
#endif
#if __has_include(<linux/thermal.h>)
	&fam_thermal,
#endif
#if __has_include(<linux/ip_vs.h>)
	&fam_ipvs,
#endif
#if __has_include(<linux/batman_adv.h>)
	&fam_batadv,
#endif
#if __has_include(<linux/tcp_metrics.h>)
	&fam_tcp_metrics,
#endif
#if __has_include(<linux/ovpn.h>)
	&fam_ovpn,
#endif
#if __has_include(<linux/net_shaper.h>)
	&fam_net_shaper,
#endif
#if __has_include(<linux/nbd-netlink.h>)
	&fam_nbd,
#endif
#if __has_include(<linux/nfc.h>)
	&fam_nfc,
#endif
#if __has_include(<linux/dpll.h>)
	&fam_dpll,
#endif
#if __has_include(<linux/handshake.h>)
	&fam_handshake,
#endif
#if __has_include(<linux/vdpa.h>)
	&fam_vdpa,
#endif
#if __has_include(<linux/cifs/cifs_netlink.h>)
	&fam_cifs,
#endif
	&fam_nlbl_mgmt,
	&fam_nlbl_cipsov4,
	&fam_nlbl_unlabel,
	&fam_nlbl_calipso,
#if __has_include(<linux/lockd_netlink.h>)
	&fam_lockd,
#endif
#if __has_include(<linux/dev_energymodel.h>)
	&fam_dev_energymodel,
#endif
#if __has_include(<drm/drm_ras.h>)
	&fam_drm_ras,
#endif
	&fam_nl802154,
	&fam_ieee802154,
	&fam_binder,
};

static int discovery_done;

/*
 * Per-family stats counter offsets.  Kept here (instead of carried by
 * the per-family grammar files) so the family files don't have to
 * pull in stats.h — adding a counter for a new family is a one-line
 * append below paired with a one-line addition in struct stats_s.
 * Walk the table at resolve time and stamp registry[i]->call_counter
 * for any family whose name matches.  Families absent from this table
 * (or whose grammar is ifdef'd out at the registry level) get a NULL
 * call_counter; the bump helper degrades to a no-op for them.
 */
static const struct {
	const char *name;
	size_t off;
} family_calls_off[] = {
	{ "devlink",   offsetof(struct stats_s, genl_family_calls_devlink) },
	{ "nl80211",   offsetof(struct stats_s, genl_family_calls_nl80211) },
	{ "TASKSTATS", offsetof(struct stats_s, genl_family_calls_taskstats) },
	{ "ethtool",   offsetof(struct stats_s, genl_family_calls_ethtool) },
	{ "mptcp_pm",  offsetof(struct stats_s, genl_family_calls_mptcp_pm) },
	{ "TIPCv2",    offsetof(struct stats_s, genl_family_calls_tipc) },
	{ "wireguard", offsetof(struct stats_s, genl_family_calls_wireguard) },
	{ "l2tp",      offsetof(struct stats_s, genl_family_calls_l2tp) },
	{ "gtp",       offsetof(struct stats_s, genl_family_calls_gtp) },
	{ "macsec",    offsetof(struct stats_s, genl_family_calls_macsec) },
	/* All four NetLabel families share a single bundled counter so the
	 * end-of-run stats line carries one row covering CALIPSO + CIPSOv4
	 * + UNLBL + MGMT traffic together; the spec-driven dispatcher's
	 * per-family resolution is preserved (each family has its own
	 * family_id and grammar), only the diagnostic counter is bundled. */
	{ "NLBL_MGMT",     offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "NLBL_CIPSOv4",  offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "NLBL_UNLBL",    offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "NLBL_CALIPSO",  offsetof(struct stats_s, genl_family_calls_netlabel) },
	{ "team",          offsetof(struct stats_s, genl_family_calls_team) },
	{ "HSR",           offsetof(struct stats_s, genl_family_calls_hsr) },
	{ "fou",           offsetof(struct stats_s, genl_family_calls_fou) },
	{ "psample",       offsetof(struct stats_s, genl_family_calls_psample) },
	{ "NCSI",          offsetof(struct stats_s, genl_family_calls_ncsi) },
	{ "TCM-USER",      offsetof(struct stats_s, genl_family_calls_tcmu) },
	{ "nfsd",          offsetof(struct stats_s, genl_family_calls_nfsd) },
	{ "ila",           offsetof(struct stats_s, genl_family_calls_ila) },
	{ "IOAM6",         offsetof(struct stats_s, genl_family_calls_ioam6) },
	{ "SEG6",          offsetof(struct stats_s, genl_family_calls_seg6) },
	{ "thermal",       offsetof(struct stats_s, genl_family_calls_thermal) },
	{ "IPVS",          offsetof(struct stats_s, genl_family_calls_ipvs) },
};

static void stamp_call_counters(void)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL || registry[i]->call_counter != NULL)
			continue;
		for (j = 0; j < ARRAY_SIZE(family_calls_off); j++) {
			if (strcmp(registry[i]->name, family_calls_off[j].name) != 0)
				continue;
			registry[i]->call_counter = (unsigned long *)
				((char *)&shm->stats + family_calls_off[j].off);
			break;
		}
	}
}

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
 * Return the attribute at *off in the len bytes at buf and step *off
 * past it, or NULL once no whole attribute is left.  An nla_len below
 * the header or past the end of the run counts as none: the lengths in
 * a reply are checked against the run that encloses them, never
 * against anything beyond it.
 */
static const struct nlattr *next_nla(const unsigned char *buf, size_t len,
				     size_t *off)
{
	const struct nlattr *nla;
	size_t nla_len;

	if (*off + NLA_HDRLEN > len)
		return NULL;
	nla = (const struct nlattr *)(buf + *off);
	nla_len = nla->nla_len;
	if (nla_len < NLA_HDRLEN || nla_len > len - *off)
		return NULL;
	*off += NLA_ALIGN(nla_len);
	return nla;
}

/*
 * Record one op nest from CTRL_ATTR_OPS: its CTRL_ATTR_OP_ID and
 * CTRL_ATTR_OP_FLAGS, both u32.  The flags are ORed in, not assigned,
 * so a repeated id cannot erase what its first entry said.
 * genlmsghdr.cmd is a u8, so an id past the table names no command we
 * could send.
 */
static void parse_op(const unsigned char *op, size_t op_len,
		     struct genl_family_grammar *fam)
{
	const struct nlattr *nla;
	unsigned int id = 0;
	unsigned int flags = 0;
	int have_id = 0;
	size_t off = 0;

	while ((nla = next_nla(op, op_len, &off)) != NULL) {
		const unsigned char *payload = (const unsigned char *)nla + NLA_HDRLEN;
		size_t payload_len = nla->nla_len - NLA_HDRLEN;

		if (payload_len < sizeof(id))
			continue;
		switch (nla_type_id(nla)) {
		case CTRL_ATTR_OP_ID:
			memcpy(&id, payload, sizeof(id));
			have_id = 1;
			break;
		case CTRL_ATTR_OP_FLAGS:
			memcpy(&flags, payload, sizeof(flags));
			break;
		default:
			break;
		}
	}

	if (have_id && id < ARRAY_SIZE(fam->cmd_caps))
		fam->cmd_caps[id] |= flags & (GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP);
}

/* Walk CTRL_ATTR_OPS, the nest the controller lists a family's ops in. */
static void parse_ops(const unsigned char *ops, size_t ops_len,
		      struct genl_family_grammar *fam)
{
	const struct nlattr *op;
	size_t off = 0;

	while ((op = next_nla(ops, ops_len, &off)) != NULL)
		parse_op((const unsigned char *)op + NLA_HDRLEN,
			 op->nla_len - NLA_HDRLEN, fam);
}

/*
 * Match a NEWFAMILY response to a registered grammar by name.  Sets
 * the family_id and clears unavailable when found, and returns the
 * grammar; NULL when the name is not registered.  The kernel
 * zero-pads CTRL_ATTR_FAMILY_NAME so a strcmp against the registry
 * name is safe as long as parse_family_response() NUL-terminated the
 * scratch buffer it passes in.
 */
static struct genl_family_grammar *match_response(const char *name,
						  unsigned short id)
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
		return registry[i];
	}
	return NULL;
}

/*
 * Walk a single CTRL_CMD_NEWFAMILY response, extract FAMILY_NAME +
 * FAMILY_ID, and dispatch to match_response().  Skips entries lacking
 * either field.  A family we register also gets the ops it lists
 * recorded, after the match, because the list can precede the name.
 */
static void parse_family_response(const struct nlmsghdr *nlh)
{
	struct genl_family_grammar *fam;
	const struct nlattr *nla;
	const unsigned char *attrs;
	const unsigned char *ops = NULL;
	size_t ops_len = 0;
	size_t attrs_off = 0;
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

	while ((nla = next_nla(attrs, attrs_len, &attrs_off)) != NULL) {
		const unsigned char *payload = (const unsigned char *)nla + NLA_HDRLEN;
		size_t payload_len = nla->nla_len - NLA_HDRLEN;

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
		case CTRL_ATTR_OPS:
			ops = payload;
			ops_len = payload_len;
			break;
		default:
			break;
		}
	}

	if (!have_name || !have_id || id == 0)
		return;
	fam = match_response(name, id);
	if (fam != NULL && ops != NULL)
		parse_ops(ops, ops_len, fam);
}

/*
 * Send CTRL_CMD_GETFAMILY/NLM_F_DUMP and consume responses until we
 * see NLMSG_DONE / NLMSG_ERROR / recv() timeout.  Each NEWFAMILY
 * message gets passed to parse_family_response() which stamps the
 * matching registry entry's family_id and cmd_caps.
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

/*
 * Must stay lazy and per-child, after init_child_setup_sandbox() has
 * settled the child's netns.  Outside init_net the kernel's
 * ctrl_dumpfamily() omits every family registered without netnsok
 * (Documentation/params-cgroup.md lists ours), so dumping from the
 * child's own netns is what keeps those families out of a netns'd
 * child's picks.  A resolve in the parent before fork runs in init_net
 * on any non-isolated run and would hand them to children that then
 * unshare into their own netns.
 */
void genl_resolve_families(void)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };
	unsigned int i;
	int sock;

	if (discovery_done)
		return;
	discovery_done = 1;

	/* Wire up per-family call counters before opening the socket so
	 * the dispatcher can bump them even on hosts where CTRL_GETFAMILY
	 * fails -- a family that never resolves keeps a NULL counter and
	 * the bump degrades to a no-op, but the wire-up itself is
	 * idempotent and cheap. */
	stamp_call_counters();

	if (registry_real_count() == 0)
		return;	/* no families registered yet — nothing to ask about */

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
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

	pick = rnd_modulo_u32(resolved_count);
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
	return fam->cmds[rnd_modulo_u32(fam->n_cmds)].cmd;
}

void genl_family_bump_calls(const struct genl_family_grammar *fam)
{
	if (!fam || !fam->call_counter)
		return;
	__atomic_add_fetch(fam->call_counter, 1, __ATOMIC_RELAXED);
}
