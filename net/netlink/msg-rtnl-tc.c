/*
 * Rtnetlink payload builders for the tc (TCA_*), tc-action (TCA_ROOT_*) and
 * link-stats (IFLA_STATS_*) groups.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_ife.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_skbedit.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/tc_act/tc_nat.h>
#include <linux/tc_act/tc_connmark.h>
#include <linux/tc_act/tc_skbmod.h>
#include <linux/tc_act/tc_mpls.h>
#include <linux/tc_act/tc_ctinfo.h>
#include <linux/tc_act/tc_sample.h>
#include <linux/tc_act/tc_bpf.h>
#include <linux/tc_act/tc_ct.h>
#include <linux/mpls.h>
#include <linux/if_packet.h>
#include "kernel/tc_mirred.h"	/* TCA_MIRRED_BLOCKID */
#include "kernel/tc_tunnel_key.h"	/* TCA_TUNNEL_KEY_NO_FRAG */
#include "bpf.h"
#include "netlink-attrs.h"
#include "msg-internal.h"
#include "msg-rtnl-common.h"
#include "random.h"
#include "trinity.h"
#include "rnd.h"
#include "utils-macros.h"		/* ARRAY_SIZE, RAND_ARRAY */
#include "shm.h"

/* Prototypes for external-linkage generators defined below.  Their
 * sibling declarations for the dispatcher live in net/netlink/msg-core.c;
 * these self-declarations satisfy -Wmissing-prototypes without
 * widening the per-family wire-up beyond the two TUs that need it
 * (this file and msg-core.c). */
size_t gen_rta_stats_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type);
size_t gen_rta_action_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type);

/*
 * UAPI fallbacks for the stab sub-namespace.  pkt_sched.h on stripped
 * sysroots may omit the TCA_STAB_* enum; values are stable UAPI.
 */
#ifndef TCA_STAB_BASE
#define TCA_STAB_BASE	1
#define TCA_STAB_DATA	2
#endif

/*
 * Build a correct TCA_STAB nested payload: TCA_STAB_BASE carrying a
 * struct tc_sizespec and (when tsize > 0) TCA_STAB_DATA carrying
 * tsize u16 size-table entries.  The stab sub-namespace is distinct
 * from the outer TCA_* namespace; using tca_attrs here would draw
 * TCA_KIND/TCA_OPTIONS/... slots, which fail stab_policy validation
 * in qdisc_get_stab() (net/sched/sch_api.c) with -EINVAL.
 *
 * Safety constraint on magnitude inputs: qdisc_calculate_pkt_len()
 * computes pkt_len ~= overhead + (tab[slot] << size_log).  A large
 * product forces drr_dequeue() to spin in the deficit loop under the
 * qdisc spinlock with BH disabled for seconds; STORM_BUDGET_NS cannot
 * cap that stall because the CPU never returns to the childop.
 * The default draws enforce the in-range path (slot < tsize) so the
 * kernel extrapolation branch in __qdisc_calculate_pkt_len() is
 * unreachable: cell_log is set to at least ceil(log2(69631/tsize))
 * so the worst-case slot (69630 >> cell_log, where
 * 69630 = u16_max + overhead_max) is always < tsize.  size_log is
 * drawn from the full kernel-accepted range [0,30]; tab[i] entries
 * are capped at (INT32_MAX >> size_log) so tab[i]<<size_log never
 * exceeds INT32_MAX — well clear of stall territory while still
 * exercising every line of qdisc_get_stab(), the stab dedup walk,
 * qdisc_put_stab(), and the stab branch of qdisc_calculate_pkt_len().
 * Full-range draws for overhead live behind
 * #define STAB_OVERHEAD_UNBOUNDED and must NOT be enabled on shared
 * hardware without the tree maintainer's explicit approval.
 */
static size_t build_stab_nest(unsigned char *p, size_t avail)
{
	struct tc_sizespec s;
	unsigned int tsize;
	size_t data_len;
	size_t off = 0;
	__u16 *tab;
	unsigned int i;

	/*
	 * Derive the maximum tsize that fits within avail before consuming
	 * any RNG state.  Drawing tsize unconditionally then bailing on the
	 * avail check would perturb seeded-run reproducibility and silently
	 * emit zero bytes for TCA_STAB with no observable counter.
	 *
	 * BASE occupies NLA_ALIGN(NLA_HDRLEN + sizeof(s)) bytes; the DATA
	 * attr adds NLA_HDRLEN plus tsize*sizeof(__u16).  Solve for tsize:
	 *   max_tsize = (avail - base_sz - NLA_HDRLEN) / sizeof(__u16)
	 * Cap at 64: kernel validates nla_len(DATA)/sizeof(u16) == tsize.
	 */
	{
		size_t base_sz = NLA_ALIGN(NLA_HDRLEN + sizeof(s));
		size_t max_tsize_sz;

		if (avail <= base_sz + (size_t)NLA_HDRLEN) {
			/* unreachable: caller gate ensures avail >= MIN_STAB_AVAIL */
			return 0;
		}
		max_tsize_sz = (avail - base_sz - (size_t)NLA_HDRLEN) /
			       sizeof(__u16);
		if (max_tsize_sz < 1) {
			/* unreachable: caller gate ensures avail >= MIN_STAB_AVAIL */
			return 0;
		}
		if (max_tsize_sz > 64)
			max_tsize_sz = 64;
		tsize = 1 + rnd_modulo_u32((unsigned int)max_tsize_sz);
	}
	data_len = (size_t)tsize * sizeof(__u16);

	memset(&s, 0, sizeof(s));
	/*
	 * cell_log: enforce the in-range path (slot < tsize) so the kernel's
	 * extrapolation branch is unreachable.  The worst-case input to the
	 * slot computation is pkt_len + overhead <= 65535 + 4095 = 69630.
	 * Find the minimum cell_log such that 69630 >> cell_log < tsize, then
	 * draw uniformly from [min_cell_log, 30].
	 *
	 * size_log: full kernel-accepted range [0,30] (covers all parse paths
	 * including STAB_SIZE_LOG_MAX validation).  tab[i] is capped below to
	 * keep tab[i] << size_log within s32 range.
	 */
	{
		unsigned int min_cl = 0;

		while (min_cl < 30 && (69630U >> min_cl) >= tsize)
			min_cl++;
		s.cell_log = (__u8)(min_cl + rnd_modulo_u32(31U - min_cl));
	}
	s.cell_align = -1;		/* kernel passes through unchanged */
#ifndef STAB_OVERHEAD_UNBOUNDED
	s.size_log   = (__u8)rnd_modulo_u32(31);	/* [0,30]: full parse surface */
	s.overhead   = (int)rnd_modulo_u32(4096);
#else
	s.size_log   = (__u8)rnd_modulo_u32(31);	/* opt-in only */
	s.overhead   = (int)rand32();	/* opt-in only; see safety note above */
#endif
	s.linklayer  = 1 + rnd_modulo_u32(3);	/* 1=ethernet 2=atm 3=adsl */
	s.mpu        = (__u32)rnd_modulo_u32(256);
	s.mtu        = 1500;
	s.tsize      = tsize;

	/* TCA_STAB_BASE: exact sizeof(struct tc_sizespec) bytes required */
	if (!start_nlattr(p, off, avail, TCA_STAB_BASE, sizeof(s)))
		return 0;
	memcpy(p + off + NLA_HDRLEN, &s, sizeof(s));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(s));

	/* TCA_STAB_DATA: tsize u16 entries; length must match s.tsize */
	if (!start_nlattr(p, off, avail, TCA_STAB_DATA, data_len))
		return off;
	tab = (__u16 *)(p + off + NLA_HDRLEN);
	{
		/*
		 * Cap tab[i] so tab[i] << size_log <= INT32_MAX.
		 * max_tab_val = (INT32_MAX >> size_log), clamped to u16 max
		 * since the table element type is __u16.
		 */
#ifndef STAB_OVERHEAD_UNBOUNDED
		unsigned int max_tab_val = 0x7fffffffU >> s.size_log;

		if (max_tab_val > 0xffffU)
			max_tab_val = 0xffffU;
		for (i = 0; i < tsize; i++)
			tab[i] = (__u16)rnd_modulo_u32(max_tab_val + 1U);
#else
		for (i = 0; i < tsize; i++)
			tab[i] = (__u16)rnd_modulo_u32(65536);	/* opt-in only */
#endif
	}
	off += NLA_ALIGN(NLA_HDRLEN + data_len);

	return off;
}

/*
 * Generate a structured payload for tc rtnetlink attributes (TCA_*).
 * Covers RTM_*QDISC / RTM_*TCLASS / RTM_*TFILTER message groups (5/6/7).
 * TCA_KIND is the single highest-leverage attr: it selects the
 * Qdisc_ops / tcf_proto_ops the kernel demuxes to, so a real kind name
 * is what gets the message past find_qdisc_kind() / tcf_proto_lookup()
 * into the per-kind validator.  The fixed-size structs (tc_estimator,
 * tc_stats) and scalar u32/u8 attrs follow the rtm_tca_policy widths
 * so they survive the top-level NLA_BINARY / NLA_U32 / NLA_U8 length
 * checks.  Anything outside this set returns 0 so the caller falls
 * back to a random blob.
 */
size_t gen_rta_tc_payload(unsigned char *p, size_t avail,
			  unsigned short nla_type)
{
	switch (nla_type) {
	case TCA_KIND: {
		/* String: qdisc / class / filter kind.  Picking a real kind
		 * resolves a Qdisc_ops or tcf_proto_ops and reaches the
		 * per-kind validator instead of bouncing off -ENOENT. */
		static const char *kinds[] = {
			"pfifo", "bfifo", "pfifo_fast", "fq", "fq_codel",
			"codel", "htb", "hfsc", "tbf", "sfq", "red", "prio",
			"noqueue", "ingress", "clsact", "netem", "drr",
			"mqprio", "multiq", "etf", "taprio", "ets", "cake",
			"u32", "fw", "route", "tcindex", "basic", "cgroup",
			"matchall", "flower", "bpf", "rsvp",
		};
		const char *name = RAND_ARRAY(kinds);
		size_t slen = strlen(name) + 1;

		if (avail >= slen) {
			memcpy(p, name, slen);
			return slen;
		}
		return 0;
	}

	case TCA_RATE:
		if (avail >= sizeof(struct tc_estimator)) {
			struct tc_estimator est;

			est.interval = rnd_modulo_u32(8);
			est.ewma_log = rnd_modulo_u32(16);
			memcpy(p, &est, sizeof(est));
			return sizeof(est);
		}
		return 0;

	case TCA_CHAIN:
	case TCA_INGRESS_BLOCK:
	case TCA_EGRESS_BLOCK:
	case TCA_FCNT:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case TCA_HW_OFFLOAD:
		if (avail >= 1) {
			*p = rnd_modulo_u32(2);
			return 1;
		}
		return 0;

	case TCA_DUMP_FLAGS:
		/* NLA_BITFIELD32: u32 value + u32 selector mask. */
		if (avail >= sizeof(struct nla_bitfield32)) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_DUMP_FLAGS_TERSE;
			bf.value = rnd_modulo_u32(2) ? TCA_DUMP_FLAGS_TERSE : 0;
			memcpy(p, &bf, sizeof(bf));
			return sizeof(bf);
		}
		return 0;

	case TCA_EXT_WARN_MSG: {
		static const char *msgs[] = {
			"warn", "kind-mismatch", "bad-attr",
		};
		const char *msg = RAND_ARRAY(msgs);
		size_t slen = strlen(msg) + 1;

		if (avail >= slen) {
			memcpy(p, msg, slen);
			return slen;
		}
		return 0;
	}

	case TCA_STATS:
		/* Legacy fixed-size struct tc_stats. */
		if (avail >= sizeof(struct tc_stats)) {
			struct tc_stats st;

			generate_rand_bytes((unsigned char *)&st, sizeof(st));
			memcpy(p, &st, sizeof(st));
			return sizeof(st);
		}
		return 0;

	case TCA_STAB:
		/* Build with the correct stab namespace (TCA_STAB_BASE /
		 * TCA_STAB_DATA under stab_policy in sch_api.c:491).
		 * The outer tca_attrs table (TCA_KIND, TCA_OPTIONS, ...) is
		 * the wrong namespace and always yields -EINVAL inside
		 * qdisc_get_stab() -- build_stab_nest() fixes that.
		 *
		 * Guard against the callee's worst case: tsize=64 requires
		 * NLA_ALIGN(NLA_HDRLEN + 64*sizeof(__u16)) bytes for DATA on
		 * top of the BASE attr.  A weaker guard (e.g. room for only
		 * one u16) lets the caller say "go" when the callee would
		 * return 0 after consuming RNG state, making TCA_STAB absent
		 * from those messages with no observable counter.
		 *
		 * TODO: TCA_OPTIONS and TCA_STATS2 in the sibling case below
		 * are also handled via tca_attrs.  Whether those containers
		 * are equally mis-targeted (drawing outer-namespace slots into
		 * per-kind / per-stat policy walkers) has not been
		 * established; treat it as an open question for a separate
		 * audit rather than assuming this fix answers it. */
		if (avail >= NLA_ALIGN(NLA_HDRLEN + sizeof(struct tc_sizespec)) +
			     NLA_ALIGN(NLA_HDRLEN + 64 * sizeof(__u16)))
			return build_stab_nest(p, avail);
		/* avail below the 160-byte stab minimum (BASE + DATA worst case);
		 * this is the expected-hot skip path that the counter was meant
		 * to observe -- the callee bail arms are structurally unreachable
		 * once this guard is in place. */
		__atomic_add_fetch(&shm->stats.netlink_stab_emit_skipped,
				   1, __ATOMIC_RELAXED);
		return 0;

	case TCA_OPTIONS:
	case TCA_STATS2:
		/* Nested containers.  TCA_OPTIONS is the per-kind options
		 * blob (cls_u32_policy, fq_codel_policy, …); TCA_STATS2 is
		 * the modern stats nest.  Their sub-attr namespaces differ
		 * per container; the tca_attrs table (outer TCA_* namespace)
		 * used here may be similarly mis-targeted -- that is an open
		 * question not addressed in this commit (see TODO above). */
		if (avail >= NLA_HDRLEN + 8) {
			return build_nested_attrs(p, avail, tca_attrs,
						  tca_attrs_n, 0);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Generate a structured payload for link-stats rtnetlink attributes
 * (IFLA_STATS_*).  Covers the RTM_*STATS message group (19).  The
 * IFLA_STATS_LINK_64 attr carries a fixed-width struct
 * rtnl_link_stats64 -- a random-byte payload of length [0, 64) almost
 * never lands at exactly sizeof(struct rtnl_link_stats64), so the attr
 * is length-rejected at the policy gate before any consumer sees it.
 * Size IFLA_STATS_LINK_64 to the struct width and fill with random
 * counter values so the per-attr writer runs.  The remaining
 * IFLA_STATS_* slots (LINK_XSTATS, LINK_XSTATS_SLAVE,
 * LINK_OFFLOAD_XSTATS, AF_SPEC) are NLA_NESTED chains; let those fall
 * through to the random-byte fallback.
 */
size_t gen_rta_stats_payload(unsigned char *p, size_t avail,
			     unsigned short nla_type)
{
	switch (nla_type) {
	case IFLA_STATS_LINK_64:
		if (avail >= sizeof(struct rtnl_link_stats64)) {
			struct rtnl_link_stats64 st;

			generate_rand_bytes((unsigned char *)&st, sizeof(st));
			memcpy(p, &st, sizeof(st));
			return sizeof(st);
		}
		return 0;

	default:
		return 0;
	}
}

/*
 * Registered tc action kind names.  Selecting one resolves a
 * tc_action_ops via tcf_action_lookup_ops and reaches the per-act
 * init_module / late-binding init instead of bouncing on the
 * request_module / -ENOENT path inside tcf_action_init_1.
 */
static const char * const tc_act_kinds[] = {
	"gact", "mirred", "nat", "pedit", "skbedit", "vlan", "bpf",
	"connmark", "skbmod", "csum", "tunnel_key", "simple", "ife",
	"sample", "ct", "police", "mpls", "ctinfo",
};

/*
 * gact's TCA_ACT_OPTIONS.  tcf_gact_init() refuses the action without
 * TCA_GACT_PARMS.  Index 1 to 8 names an action an earlier call may have
 * made, so a NLM_F_REPLACE meets one, and the TCA_GACT_PROB sent half the
 * time sets the ptype/pval pair that a replace without one leaves in
 * place.  The verdicts are the plain ones and a short jump: a goto chain
 * is refused on an action no filter holds.
 */
static size_t build_gact_options(unsigned char *p, size_t avail)
{
	struct tc_gact parm;
	struct tc_gact_p prob;
	size_t off = 0;

	if (!start_nlattr(p, off, avail, TCA_GACT_PARMS, sizeof(parm)))
		return 0;
	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	memcpy(p + off + NLA_HDRLEN, &parm, sizeof(parm));
	off += NLA_ALIGN(NLA_HDRLEN + sizeof(parm));

	if (RAND_BOOL() &&
	    start_nlattr(p, off, avail, TCA_GACT_PROB, sizeof(prob))) {
		memset(&prob, 0, sizeof(prob));
		prob.ptype = rnd_modulo_u32(MAX_RAND);
		prob.pval = RAND_BOOL() ? RAND_RANGE(0, 10) : (__u16) rnd_u32();
		prob.paction = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
			       RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
		memcpy(p + off + NLA_HDRLEN, &prob, sizeof(prob));
		off += NLA_ALIGN(NLA_HDRLEN + sizeof(prob));
	}
	return off;
}

/*
 * ife's TCA_ACT_OPTIONS.  tcf_ife_init() refuses the action without
 * TCA_IFE_PARMS, or with a flag but IFE_ENCODE in them.  An encoder, half
 * of them, carries an ethertype and both MAC addresses three times in
 * four; leaving them out keeps ETH_P_IFE and zero addresses.  Half the
 * actions carry a metadata list: skbmark, skbprio and tcindex, each half
 * the time, with no value (allowed, valued per packet) one time in four
 * or else a value of its width, u32 or u16, which is 0 half the time:
 * an encoder writes a configured 0 (v7.4-rc3).  Without a list
 * use_all_metadata() takes every metadatum whose module is in.  Index 1
 * to 8 names an action an earlier call made, as gact's does.
 */
static size_t build_ife_options(unsigned char *p, size_t avail)
{
	static const struct {
		__u16 id;
		__u16 width;
	} metas[] = {
		{ IFE_META_SKBMARK,	sizeof(__u32) },
		{ IFE_META_PRIO,	sizeof(__u32) },
		{ IFE_META_TCINDEX,	sizeof(__u16) },
	};
	unsigned char list[ARRAY_SIZE(metas) *
			   NLA_ALIGN(NLA_HDRLEN + sizeof(__u32))];
	unsigned char mac[ETH_ALEN];
	struct tc_ife parm;
	size_t off = 0, llen = 0;
	unsigned int i;
	__u16 type;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.flags = RAND_BOOL() ? IFE_ENCODE : IFE_DECODE;
	if (!put_nlattr(p, &off, avail, TCA_IFE_PARMS, &parm, sizeof(parm)))
		return 0;

	if (parm.flags == IFE_ENCODE && !ONE_IN(4)) {
		type = RAND_BOOL() ? ETH_P_IFE : (__u16) rnd_u32();
		put_nlattr(p, &off, avail, TCA_IFE_TYPE, &type, sizeof(type));
		generate_rand_bytes(mac, sizeof(mac));
		put_nlattr(p, &off, avail, TCA_IFE_DMAC, mac, sizeof(mac));
		generate_rand_bytes(mac, sizeof(mac));
		put_nlattr(p, &off, avail, TCA_IFE_SMAC, mac, sizeof(mac));
	}

	if (RAND_BOOL())
		return off;
	for (i = 0; i < ARRAY_SIZE(metas); i++) {
		__u32 val32 = RAND_BOOL() ? 0 : rnd_u32();
		__u16 val16 = (__u16) val32;

		if (RAND_BOOL())
			continue;
		put_nlattr(list, &llen, sizeof(list), metas[i].id,
			   metas[i].width == sizeof(val16) ?
				(const void *) &val16 : (const void *) &val32,
			   ONE_IN(4) ? 0 : metas[i].width);
	}
	put_nlattr(p, &off, avail, TCA_IFE_METALST | NLA_F_NESTED, list, llen);
	return off;
}

/*
 * mirred's TCA_ACT_OPTIONS.  tcf_mirred_init() refuses the action without
 * TCA_MIRRED_PARMS, with an eaction other than the four redirects and
 * mirrors, and with neither a device nor a block, or both.  The device is
 * lo seven times in eight, the one a lane child's netns has, and
 * otherwise the action sends to a block of the range a qdisc's
 * TCA_INGRESS_BLOCK or TCA_EGRESS_BLOCK makes, 1 to 63.  Index 1 to 8
 * names an action an earlier call made, as gact's does.
 */
static size_t build_mirred_options(unsigned char *p, size_t avail)
{
	static const int eactions[] = {
		TCA_EGRESS_REDIR, TCA_EGRESS_MIRROR,
		TCA_INGRESS_REDIR, TCA_INGRESS_MIRROR,
	};
	struct tc_mirred parm;
	size_t off = 0;
	__u32 block;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.eaction = RAND_ARRAY(eactions);
	parm.ifindex = ONE_IN(8) ? 0 : 1;
	if (!put_nlattr(p, &off, avail, TCA_MIRRED_PARMS, &parm, sizeof(parm)))
		return 0;
	if (parm.ifindex == 0) {
		block = RAND_RANGE(1U, 63U);
		put_nlattr(p, &off, avail, TCA_MIRRED_BLOCKID, &block,
			   sizeof(block));
	}
	return off;
}

/*
 * skbedit's TCA_ACT_OPTIONS.  tcf_skbedit_init() refuses the action
 * without TCA_SKBEDIT_PARMS or with no edit beside it, a packet type past
 * PACKET_OTHERHOST, and a TXQ_SKBHASH flag without a queue range whose
 * top is at or above its base (a queue mapping on a filter at ingress is
 * refused as well, which the builder cannot see).  A priority and a mark
 * go in half the time each, the mark with a mask half of those, and a
 * packet type, a queue mapping and the flags a quarter of the time; a
 * mapping hashes over a range half the time, and an action that drew no
 * edit gets a mark.
 */
static size_t build_skbedit_options(unsigned char *p, size_t avail)
{
	struct tc_skbedit parm;
	size_t off = 0;
	bool edit = false;
	__u64 flags = 0;
	__u32 val32;
	__u16 val16, qmax;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	if (!put_nlattr(p, &off, avail, TCA_SKBEDIT_PARMS, &parm, sizeof(parm)))
		return 0;

	if (RAND_BOOL()) {
		val32 = rnd_u32();
		edit |= put_nlattr(p, &off, avail, TCA_SKBEDIT_PRIORITY,
				   &val32, sizeof(val32));
	}
	if (RAND_BOOL()) {
		val32 = RAND_BOOL() ? 0 : rnd_u32();
		edit |= put_nlattr(p, &off, avail, TCA_SKBEDIT_MARK, &val32,
				   sizeof(val32));
		if (RAND_BOOL()) {
			val32 = rnd_u32();
			put_nlattr(p, &off, avail, TCA_SKBEDIT_MASK, &val32,
				   sizeof(val32));
		}
	}
	if (ONE_IN(4)) {
		val16 = RAND_RANGE(PACKET_HOST, PACKET_OTHERHOST);
		edit |= put_nlattr(p, &off, avail, TCA_SKBEDIT_PTYPE, &val16,
				   sizeof(val16));
	}
	if (ONE_IN(4)) {
		val16 = rnd_modulo_u32(8);
		qmax = val16 + rnd_modulo_u32(8);
		if (put_nlattr(p, &off, avail, TCA_SKBEDIT_QUEUE_MAPPING,
			       &val16, sizeof(val16))) {
			edit = true;
			if (RAND_BOOL() &&
			    put_nlattr(p, &off, avail,
				       TCA_SKBEDIT_QUEUE_MAPPING_MAX, &qmax,
				       sizeof(qmax)))
				flags |= SKBEDIT_F_TXQ_SKBHASH;
		}
	}
	if (flags != 0 || ONE_IN(4)) {
		if (RAND_BOOL())
			flags |= SKBEDIT_F_INHERITDSFIELD;
		if (flags != 0)
			edit |= put_nlattr(p, &off, avail, TCA_SKBEDIT_FLAGS,
					   &flags, sizeof(flags));
	}
	if (!edit) {
		val32 = rnd_u32();
		put_nlattr(p, &off, avail, TCA_SKBEDIT_MARK, &val32,
			   sizeof(val32));
	}
	return off;
}

/*
 * pedit's TCA_ACT_OPTIONS.  tcf_pedit_init() takes its keys inside
 * TCA_PEDIT_PARMS, or TCA_PEDIT_PARMS_EX, a struct tc_pedit_sel followed
 * by nkeys struct tc_pedit_key, and refuses no keys, an attribute shorter
 * than nkeys says, and an offset off a 32-bit boundary unless an offmask
 * takes it from the packet.  One key to three, at the head of the packet
 * mostly, one in eight read through an at/offmask/shift as an IP header
 * length is.  Half the actions go out as PARMS_EX with TCA_PEDIT_KEYS_EX,
 * one TCA_PEDIT_KEY_EX per key, each with the header type and command
 * tcf_pedit_keys_ex_parse() requires, within their policy maxima.  Index
 * 1 to 8 names an action an earlier call made, as gact's does.
 */
static size_t build_pedit_options(unsigned char *p, size_t avail)
{
	unsigned char sel_buf[sizeof(struct tc_pedit_sel) +
			      3 * sizeof(struct tc_pedit_key)];
	unsigned char keys_ex[3 * NLA_ALIGN(NLA_HDRLEN +
				2 * NLA_ALIGN(NLA_HDRLEN + sizeof(__u16)))];
	struct tc_pedit_sel sel;
	size_t off = 0, sel_len, klen = 0;
	bool ex = RAND_BOOL();
	unsigned int i;

	memset(&sel, 0, sizeof(sel));
	sel.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	sel.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		     RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	sel.nkeys = RAND_RANGE(1, 3);
	memcpy(sel_buf, &sel, sizeof(sel));
	for (i = 0; i < sel.nkeys; i++) {
		struct tc_pedit_key key;
		unsigned char kex[2 * NLA_ALIGN(NLA_HDRLEN + sizeof(__u16))];
		size_t kexlen = 0;
		__u16 htype = RAND_RANGE(TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK,
					 TCA_PEDIT_HDR_TYPE_MAX);
		__u16 cmd = RAND_RANGE(TCA_PEDIT_KEY_EX_CMD_SET,
				       TCA_PEDIT_CMD_MAX);

		memset(&key, 0, sizeof(key));
		key.mask = RAND_BOOL() ? 0 : rnd_u32();
		key.val = rnd_u32();
		key.off = 4 * rnd_modulo_u32(16);
		if (ONE_IN(8)) {
			key.at = rnd_modulo_u32(16);
			key.offmask = 0x0f000000;
			key.shift = 22;
			key.off = rnd_modulo_u32(64);
		}
		memcpy(sel_buf + sizeof(sel) + i * sizeof(key), &key,
		       sizeof(key));

		put_nlattr(kex, &kexlen, sizeof(kex), TCA_PEDIT_KEY_EX_HTYPE,
			   &htype, sizeof(htype));
		put_nlattr(kex, &kexlen, sizeof(kex), TCA_PEDIT_KEY_EX_CMD,
			   &cmd, sizeof(cmd));
		put_nlattr(keys_ex, &klen, sizeof(keys_ex),
			   TCA_PEDIT_KEY_EX | NLA_F_NESTED, kex, kexlen);
	}
	sel_len = sizeof(sel) + sel.nkeys * sizeof(struct tc_pedit_key);

	if (!put_nlattr(p, &off, avail,
			ex ? TCA_PEDIT_PARMS_EX : TCA_PEDIT_PARMS,
			sel_buf, sel_len))
		return 0;
	if (ex)
		put_nlattr(p, &off, avail, TCA_PEDIT_KEYS_EX | NLA_F_NESTED,
			   keys_ex, klen);
	return off;
}

/*
 * vlan's TCA_ACT_OPTIONS.  tcf_vlan_init() refuses the action without
 * TCA_VLAN_PARMS or with a v_action past its five.  A push or a modify
 * wants TCA_VLAN_PUSH_VLAN_ID under VLAN_VID_MASK, 0xfff (-ERANGE at or
 * past it), and a protocol, when one goes in, of 802.1Q or 802.1ad
 * (-EPROTONOSUPPORT); each carries a protocol and a priority half the
 * time.  A push of an Ethernet header wants both MAC addresses.  Index 1
 * to 8 names an action an earlier call made, as gact's does.
 */
static size_t build_vlan_options(unsigned char *p, size_t avail)
{
	unsigned char mac[ETH_ALEN];
	struct tc_vlan parm;
	size_t off = 0;
	__u16 vid, proto;
	__u8 prio;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.v_action = RAND_RANGE(TCA_VLAN_ACT_POP, TCA_VLAN_ACT_PUSH_ETH);
	if (!put_nlattr(p, &off, avail, TCA_VLAN_PARMS, &parm, sizeof(parm)))
		return 0;

	switch (parm.v_action) {
	case TCA_VLAN_ACT_PUSH:
	case TCA_VLAN_ACT_MODIFY:
		vid = rnd_modulo_u32(0xfff);
		put_nlattr(p, &off, avail, TCA_VLAN_PUSH_VLAN_ID, &vid,
			   sizeof(vid));
		if (RAND_BOOL()) {
			proto = htons(RAND_BOOL() ? ETH_P_8021Q : ETH_P_8021AD);
			put_nlattr(p, &off, avail, TCA_VLAN_PUSH_VLAN_PROTOCOL,
				   &proto, sizeof(proto));
		}
		if (RAND_BOOL()) {
			prio = rnd_modulo_u32(8);
			put_nlattr(p, &off, avail, TCA_VLAN_PUSH_VLAN_PRIORITY,
				   &prio, sizeof(prio));
		}
		break;
	case TCA_VLAN_ACT_PUSH_ETH:
		generate_rand_bytes(mac, sizeof(mac));
		put_nlattr(p, &off, avail, TCA_VLAN_PUSH_ETH_DST, mac,
			   sizeof(mac));
		generate_rand_bytes(mac, sizeof(mac));
		put_nlattr(p, &off, avail, TCA_VLAN_PUSH_ETH_SRC, mac,
			   sizeof(mac));
		break;
	}
	return off;
}

/*
 * csum's TCA_ACT_OPTIONS.  tcf_csum_init() refuses the action only
 * without TCA_CSUM_PARMS, and stores its update flags as they come: seven
 * actions in eight name some of the seven checksums act_csum knows
 * (IPv4 header, ICMP, IGMP, TCP, UDP, UDP-Lite, SCTP), the eighth any
 * bits.  Index 1 to 8 names an action an earlier call made, as gact's
 * does.
 */
static size_t build_csum_options(unsigned char *p, size_t avail)
{
	struct tc_csum parm;
	size_t off = 0;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.update_flags = ONE_IN(8) ? rnd_u32() :
			    1 + rnd_modulo_u32(2 * TCA_CSUM_UPDATE_FLAG_SCTP - 1);
	if (!put_nlattr(p, &off, avail, TCA_CSUM_PARMS, &parm, sizeof(parm)))
		return 0;
	return off;
}

/*
 * The TCA_TUNNEL_KEY_ENC_OPTS of a set, as tunnel_key_copy_opts() takes
 * them: one or two geneve options with 4 to 16 bytes of data, a vxlan
 * gbp, or an erspan v1 index or v2 direction and hwid.  Only geneve
 * options repeat, and the vxlan and erspan nests, past enc_opts_policy's
 * strict_start_type, are refused unflagged.  TUNNEL_KEY_OPT_MAX holds
 * the largest option, a geneve one.
 */
#define TUNNEL_KEY_OPT_MAX \
	(2 * NLA_ALIGN(NLA_HDRLEN + sizeof(__u16)) + NLA_HDRLEN + 16)

static size_t build_tunnel_key_enc_opts(unsigned char *p, size_t cap)
{
	unsigned char opt[TUNNEL_KEY_OPT_MAX];
	unsigned char data[16];
	unsigned short type;
	unsigned int i, n = 1;
	size_t off = 0;

	switch (rnd_modulo_u32(3)) {
	case 0:
		type = TCA_TUNNEL_KEY_ENC_OPTS_GENEVE;
		n = RAND_RANGE(1, 2);
		break;
	case 1:
		type = TCA_TUNNEL_KEY_ENC_OPTS_VXLAN;
		break;
	default:
		type = TCA_TUNNEL_KEY_ENC_OPTS_ERSPAN;
		break;
	}
	for (i = 0; i < n; i++) {
		__u32 val32 = rnd_u32();
		__u16 val16 = rnd_u32();
		__u8 val8 = rnd_u32(), ver = RAND_RANGE(1, 2);
		size_t olen = 0;

		switch (type) {
		case TCA_TUNNEL_KEY_ENC_OPTS_GENEVE:
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_GENEVE_CLASS,
				   &val16, sizeof(val16));
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_GENEVE_TYPE,
				   &val8, sizeof(val8));
			generate_rand_bytes(data, sizeof(data));
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_GENEVE_DATA,
				   data, 4 * RAND_RANGE(1, 4));
			break;
		case TCA_TUNNEL_KEY_ENC_OPTS_VXLAN:
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_VXLAN_GBP,
				   &val32, sizeof(val32));
			break;
		default:
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_ERSPAN_VER,
				   &ver, sizeof(ver));
			if (ver == 1) {
				put_nlattr(opt, &olen, sizeof(opt),
					   TCA_TUNNEL_KEY_ENC_OPT_ERSPAN_INDEX,
					   &val32, sizeof(val32));
				break;
			}
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_ERSPAN_DIR,
				   &val8, sizeof(val8));
			val8 = rnd_u32();
			put_nlattr(opt, &olen, sizeof(opt),
				   TCA_TUNNEL_KEY_ENC_OPT_ERSPAN_HWID,
				   &val8, sizeof(val8));
			break;
		}
		put_nlattr(p, &off, cap, type | NLA_F_NESTED, opt, olen);
	}
	return off;
}

/*
 * tunnel_key's TCA_ACT_OPTIONS.  tunnel_key_init() refuses the action
 * without TCA_TUNNEL_KEY_PARMS, with a t_action other than a set or a
 * release, and a set without both addresses of one family.  Seven in
 * eight are sets, over IPv6 one in four, each with a key id, a port, the
 * no-csum, tos, ttl and no-frag attributes half the time apiece, and
 * encap options half the time.  Index 1 to 8 names an action an earlier
 * call made, as gact's does.
 */
static size_t build_tunnel_key_options(unsigned char *p, size_t avail)
{
	static const unsigned short u8_attrs[] = {
		TCA_TUNNEL_KEY_NO_CSUM, TCA_TUNNEL_KEY_ENC_TOS,
		TCA_TUNNEL_KEY_ENC_TTL,
	};
	unsigned char enc[2 * NLA_ALIGN(NLA_HDRLEN + TUNNEL_KEY_OPT_MAX)];
	struct tc_tunnel_key parm;
	struct in6_addr addr6;
	size_t off = 0, elen;
	unsigned int i;
	__u32 val32;
	__u16 port;
	__u8 val8;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.t_action = ONE_IN(8) ? TCA_TUNNEL_KEY_ACT_RELEASE :
				    TCA_TUNNEL_KEY_ACT_SET;
	if (!put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_PARMS, &parm,
			sizeof(parm)))
		return 0;
	if (parm.t_action == TCA_TUNNEL_KEY_ACT_RELEASE)
		return off;

	if (ONE_IN(4)) {
		generate_rand_bytes((unsigned char *) &addr6, sizeof(addr6));
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_IPV6_SRC,
			   &addr6, sizeof(addr6));
		generate_rand_bytes((unsigned char *) &addr6, sizeof(addr6));
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_IPV6_DST,
			   &addr6, sizeof(addr6));
	} else {
		val32 = rnd_u32();
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_IPV4_SRC,
			   &val32, sizeof(val32));
		val32 = rnd_u32();
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_IPV4_DST,
			   &val32, sizeof(val32));
	}
	if (RAND_BOOL()) {
		val32 = rnd_u32();
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_KEY_ID, &val32,
			   sizeof(val32));
	}
	if (RAND_BOOL()) {
		port = rnd_u32();
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_DST_PORT, &port,
			   sizeof(port));
	}
	for (i = 0; i < ARRAY_SIZE(u8_attrs); i++) {
		if (RAND_BOOL())
			continue;
		val8 = rnd_u32();
		put_nlattr(p, &off, avail, u8_attrs[i], &val8, sizeof(val8));
	}
	if (RAND_BOOL())
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_NO_FRAG, NULL, 0);
	if (RAND_BOOL()) {
		elen = build_tunnel_key_enc_opts(enc, sizeof(enc));
		put_nlattr(p, &off, avail, TCA_TUNNEL_KEY_ENC_OPTS | NLA_F_NESTED,
			   enc, elen);
	}
	return off;
}

/*
 * nat's TCA_ACT_OPTIONS.  tcf_nat_init() refuses the action only without
 * TCA_NAT_PARMS.  Half the actions rewrite lo's address, the one a lane
 * child's netns carries traffic on, under a prefix mask of 0 to 32 bits,
 * and half rewrite on egress.  Index 1 to 8 names an action an earlier
 * call made, as gact's does.
 */
static size_t build_nat_options(unsigned char *p, size_t avail)
{
	unsigned int bits = RAND_RANGE(0, 32);
	struct tc_nat parm;
	size_t off = 0;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.old_addr = RAND_BOOL() ? htonl(INADDR_LOOPBACK) : rnd_u32();
	parm.new_addr = rnd_u32();
	parm.mask = bits == 0 ? 0 : htonl(~0U << (32 - bits));
	parm.flags = RAND_BOOL() ? TCA_NAT_FLAG_EGRESS : 0;
	if (!put_nlattr(p, &off, avail, TCA_NAT_PARMS, &parm, sizeof(parm)))
		return 0;
	return off;
}

/*
 * connmark's TCA_ACT_OPTIONS.  tcf_connmark_init() refuses the action only
 * without TCA_CONNMARK_PARMS.  Half the actions look a packet's conntrack
 * entry up in the default zone, 0, where an unzoned flow's entries live,
 * and the rest in a small zone 1 to 8.  Index 1 to 8 names an action an
 * earlier call made, as gact's does.
 */
static size_t build_connmark_options(unsigned char *p, size_t avail)
{
	struct tc_connmark parm;
	size_t off = 0;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.zone = RAND_BOOL() ? 0 : RAND_RANGE(1, 8);
	if (!put_nlattr(p, &off, avail, TCA_CONNMARK_PARMS, &parm,
			sizeof(parm)))
		return 0;
	return off;
}

/*
 * skbmod's TCA_ACT_OPTIONS.  tcf_skbmod_init() refuses the action without
 * TCA_SKBMOD_PARMS or with nothing to edit: a destination or source MAC,
 * an ethertype, which it takes in host order, or a PARMS flag that swaps
 * the MACs or marks ECN and displaces the rest.  One action in eight
 * swaps and one marks; the others set a source MAC and an ethertype half
 * the time each, a common one half of those, and a destination MAC half
 * the time or where neither drew.  Index 1 to 8 names an action an
 * earlier call made, as gact's does.
 */
static size_t build_skbmod_options(unsigned char *p, size_t avail)
{
	static const __u16 etypes[] = {
		ETH_P_IP, ETH_P_IPV6, ETH_P_ARP, ETH_P_8021Q,
	};
	unsigned char mac[ETH_ALEN];
	struct tc_skbmod parm;
	size_t off = 0;
	bool edit = false;
	__u16 etype;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	switch (rnd_modulo_u32(8)) {
	case 0:
		parm.flags = SKBMOD_F_SWAPMAC;
		break;
	case 1:
		parm.flags = SKBMOD_F_ECN;
		break;
	}
	if (!put_nlattr(p, &off, avail, TCA_SKBMOD_PARMS, &parm, sizeof(parm)))
		return 0;
	if (parm.flags != 0)
		return off;

	if (RAND_BOOL()) {
		generate_rand_bytes(mac, sizeof(mac));
		edit |= put_nlattr(p, &off, avail, TCA_SKBMOD_SMAC, mac,
				   sizeof(mac));
	}
	if (RAND_BOOL()) {
		etype = RAND_BOOL() ? RAND_ARRAY(etypes) : (__u16) rnd_u32();
		edit |= put_nlattr(p, &off, avail, TCA_SKBMOD_ETYPE, &etype,
				   sizeof(etype));
	}
	if (!edit || RAND_BOOL()) {
		generate_rand_bytes(mac, sizeof(mac));
		put_nlattr(p, &off, avail, TCA_SKBMOD_DMAC, mac, sizeof(mac));
	}
	return off;
}

/*
 * mpls's TCA_ACT_OPTIONS, which tcf_mpls_init() parses strictly.  It
 * refuses the action without TCA_MPLS_PARMS or with an m_action past its
 * five; a pop wants an Ethernet protocol for the header beneath and no
 * label field, a dec_ttl nothing, a push a label and no protocol but MPLS
 * unicast or multicast, and a modify no protocol.  A label is a reserved
 * one, 0 to 15 but not implicit null, half the time, else any 20-bit one;
 * a push or a modify sets the TC, TTL and BOS half the time each, and a
 * push names its protocol half the time.  Index 1 to 8 names an action an
 * earlier call made, as gact's does.
 */
static size_t build_mpls_options(unsigned char *p, size_t avail)
{
	static const __u16 pop_protos[] = {
		ETH_P_IP, ETH_P_IPV6, ETH_P_MPLS_UC, ETH_P_TEB,
	};
	struct tc_mpls parm;
	size_t off = 0;
	bool push;
	__u32 label;
	__u16 proto;
	__u8 val8;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.m_action = RAND_RANGE(TCA_MPLS_ACT_POP, TCA_MPLS_ACT_MAC_PUSH);
	if (!put_nlattr(p, &off, avail, TCA_MPLS_PARMS, &parm, sizeof(parm)))
		return 0;

	switch (parm.m_action) {
	case TCA_MPLS_ACT_POP:
		proto = htons(RAND_ARRAY(pop_protos));
		put_nlattr(p, &off, avail, TCA_MPLS_PROTO, &proto,
			   sizeof(proto));
		return off;
	case TCA_MPLS_ACT_DEC_TTL:
		return off;
	}

	push = parm.m_action != TCA_MPLS_ACT_MODIFY;
	if (push && RAND_BOOL()) {
		proto = htons(RAND_BOOL() ? ETH_P_MPLS_UC : ETH_P_MPLS_MC);
		put_nlattr(p, &off, avail, TCA_MPLS_PROTO, &proto,
			   sizeof(proto));
	}
	if (push || RAND_BOOL()) {
		label = RAND_BOOL() ? rnd_modulo_u32(16) :
			rnd_modulo_u32((MPLS_LS_LABEL_MASK >>
					MPLS_LS_LABEL_SHIFT) + 1);
		if (label == MPLS_LABEL_IMPLNULL)
			label = MPLS_LABEL_IPV4NULL;
		put_nlattr(p, &off, avail, TCA_MPLS_LABEL, &label,
			   sizeof(label));
	}
	if (RAND_BOOL()) {
		val8 = rnd_modulo_u32(8);
		put_nlattr(p, &off, avail, TCA_MPLS_TC, &val8, sizeof(val8));
	}
	if (RAND_BOOL()) {
		val8 = RAND_RANGE(1, 255);
		put_nlattr(p, &off, avail, TCA_MPLS_TTL, &val8, sizeof(val8));
	}
	if (RAND_BOOL()) {
		val8 = RAND_BOOL();
		put_nlattr(p, &off, avail, TCA_MPLS_BOS, &val8, sizeof(val8));
	}
	return off;
}

/*
 * ctinfo's TCA_ACT_OPTIONS, which tcf_ctinfo_init() parses strictly.  It
 * refuses the action without TCA_CTINFO_ACT, with a DSCP mask other than
 * six contiguous bits, and with a DSCP statemask that overlaps it.  Half
 * the actions restore DSCP from the conntrack mark, the six bits at any
 * shift, half of those under a statemask bit outside them; half copy the
 * mark to the packet's through a mask, all ones half the time; and half
 * look up a zone 1 to 8 rather than the default.  Index 1 to 8 names an
 * action an earlier call made, as gact's does.
 */
static size_t build_ctinfo_options(unsigned char *p, size_t avail)
{
	struct tc_ctinfo parm;
	unsigned int shift, bit;
	size_t off = 0;
	__u32 mask;
	__u16 zone;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	if (!put_nlattr(p, &off, avail, TCA_CTINFO_ACT, &parm, sizeof(parm)))
		return 0;

	if (RAND_BOOL()) {
		zone = RAND_RANGE(1, 8);
		put_nlattr(p, &off, avail, TCA_CTINFO_ZONE, &zone,
			   sizeof(zone));
	}
	if (RAND_BOOL()) {
		shift = rnd_modulo_u32(32 - 6 + 1);
		mask = 0x3fU << shift;
		put_nlattr(p, &off, avail, TCA_CTINFO_PARMS_DSCP_MASK, &mask,
			   sizeof(mask));
		if (RAND_BOOL()) {
			bit = rnd_modulo_u32(32 - 6);
			if (bit >= shift)
				bit += 6;
			mask = 1U << bit;
			put_nlattr(p, &off, avail,
				   TCA_CTINFO_PARMS_DSCP_STATEMASK, &mask,
				   sizeof(mask));
		}
	}
	if (RAND_BOOL()) {
		mask = RAND_BOOL() ? ~0U : rnd_u32();
		put_nlattr(p, &off, avail, TCA_CTINFO_PARMS_CPMARK_MASK, &mask,
			   sizeof(mask));
	}
	return off;
}

/*
 * sample's TCA_ACT_OPTIONS.  tcf_sample_init() refuses the action without
 * TCA_SAMPLE_PARMS, a TCA_SAMPLE_RATE above 0 and a
 * TCA_SAMPLE_PSAMPLE_GROUP, which psample_group_get() makes in the
 * request's netns when it is new.  The rate is every packet one time in
 * four, else one in up to 2^16; the group is one of eight seven times in
 * eight, so actions share it, else any; and half the actions truncate,
 * mostly to under a frame.  Index 1 to 8 names an action an earlier call
 * made, as gact's does.
 */
static size_t build_sample_options(unsigned char *p, size_t avail)
{
	struct tc_sample parm;
	size_t off = 0;
	__u32 val;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	if (!put_nlattr(p, &off, avail, TCA_SAMPLE_PARMS, &parm, sizeof(parm)))
		return 0;

	val = ONE_IN(4) ? 1 : RAND_RANGE(1U, 1U << 16);
	put_nlattr(p, &off, avail, TCA_SAMPLE_RATE, &val, sizeof(val));
	val = ONE_IN(8) ? rnd_u32() : RAND_RANGE(1U, 8U);
	put_nlattr(p, &off, avail, TCA_SAMPLE_PSAMPLE_GROUP, &val, sizeof(val));
	if (RAND_BOOL()) {
		val = ONE_IN(4) ? rnd_u32() : RAND_RANGE(0U, 1500U);
		put_nlattr(p, &off, avail, TCA_SAMPLE_TRUNC_SIZE, &val,
			   sizeof(val));
	}
	return off;
}

/*
 * police's TCA_ACT_OPTIONS.  tcf_police_init() refuses the action without
 * a TCA_POLICE_TBF of struct tc_police's size or of the compat struct's,
 * which ends before refcnt; a byte rate without the 1024-byte table
 * qdisc_get_rtab() reads, which outgrows an action's room, so the rate
 * stays 0; a packet rate without its burst or the other way round, or
 * either of them 0; and a conform verdict (TCA_POLICE_RESULT) that is no
 * verdict or a goto chain.  Half the actions police packets per second,
 * the rest only the MTU, which half of all set; half carry a conform
 * verdict; and one TBF in eight is the compat size.  Index 1 to 8 names
 * an action an earlier call made, as gact's does.
 */
static size_t build_police_options(unsigned char *p, size_t avail)
{
	struct tc_police parm;
	size_t off = 0;
	__u64 val64;
	__u32 result;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	parm.burst = rnd_u32();
	parm.mtu = RAND_BOOL() ? 0 : RAND_RANGE(64U, 9000U);
	if (!put_nlattr(p, &off, avail, TCA_POLICE_TBF, &parm,
			ONE_IN(8) ? offsetof(struct tc_police, refcnt) :
				    sizeof(parm)))
		return 0;

	if (RAND_BOOL()) {
		val64 = RAND_RANGE(1U, 1000000U);
		put_nlattr(p, &off, avail, TCA_POLICE_PKTRATE64, &val64,
			   sizeof(val64));
		val64 = RAND_BOOL() ? RAND_RANGE(1U, 1U << 24) : rnd_u64() | 1;
		put_nlattr(p, &off, avail, TCA_POLICE_PKTBURST64, &val64,
			   sizeof(val64));
	}
	if (RAND_BOOL()) {
		result = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
			 RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
		put_nlattr(p, &off, avail, TCA_POLICE_RESULT, &result,
			   sizeof(result));
	}
	return off;
}

/*
 * A classic program for a bpf action, written to insns: a return one time
 * in four, else a load of the length, of a packet byte or half-word near
 * the head or of an ancillary field, a compare of it against a constant,
 * and a return each way.  The returns are mostly verdicts tcf_bpf_act()
 * acts on.  Every program gets past bpf_check_classic(): opcodes it
 * knows, jumps inside the program and a return at the end.
 */
static unsigned int build_act_bpf_classic(struct sock_filter *insns)
{
	static const __u16 compares[] = {
		BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JGT | BPF_K,
		BPF_JMP | BPF_JGE | BPF_K, BPF_JMP | BPF_JSET | BPF_K,
	};
	static const __u32 ancillary[] = {
		SKF_AD_PROTOCOL, SKF_AD_PKTTYPE, SKF_AD_IFINDEX, SKF_AD_MARK,
		SKF_AD_QUEUE, SKF_AD_HATYPE, SKF_AD_RXHASH, SKF_AD_CPU,
		SKF_AD_VLAN_TAG, SKF_AD_PAY_OFFSET, SKF_AD_RANDOM,
	};
	unsigned int n = 0;

	if (!ONE_IN(4)) {
		switch (rnd_modulo_u32(4)) {
		case 0:
			insns[n++] = (struct sock_filter)
				BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0);
			break;
		case 1:
			insns[n++] = (struct sock_filter)
				BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
					 rnd_modulo_u32(64));
			break;
		case 2:
			insns[n++] = (struct sock_filter)
				BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
					 rnd_modulo_u32(64));
			break;
		default:
			insns[n++] = (struct sock_filter)
				BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					 SKF_AD_OFF + RAND_ARRAY(ancillary));
			break;
		}
		insns[n++] = (struct sock_filter)
			BPF_JUMP(RAND_ARRAY(compares), rnd_u32(), 0, 1);
		insns[n++] = (struct sock_filter)
			BPF_STMT(BPF_RET | BPF_K, ONE_IN(8) ? rnd_u32() :
			       (__u32) RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX));
	}
	insns[n++] = (struct sock_filter)
		BPF_STMT(BPF_RET | BPF_K, ONE_IN(8) ? rnd_u32() :
		       (__u32) RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX));
	return n;
}

/*
 * bpf's TCA_ACT_OPTIONS.  tcf_bpf_init() refuses the action without
 * TCA_ACT_BPF_PARMS, or without just one of a classic program
 * (TCA_ACT_BPF_OPS_LEN and TCA_ACT_BPF_OPS) and an eBPF program's fd
 * (TCA_ACT_BPF_FD), which bpf_prog_get_type() wants of a sched_act
 * program.  Half the actions run such a program from the pool when it
 * holds one, named half of those, and the rest a small classic one.
 * Index 1 to 8 names an action an earlier call made, as gact's does.
 */
static size_t build_bpf_options(unsigned char *p, size_t avail)
{
	struct sock_filter insns[4];
	struct tc_act_bpf parm;
	size_t off = 0;
	__u16 nops;
	__u32 val;
	int fd;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	if (!put_nlattr(p, &off, avail, TCA_ACT_BPF_PARMS, &parm,
			sizeof(parm)))
		return 0;

	fd = get_rand_bpf_prog_fd_of_type(BPF_PROG_TYPE_SCHED_ACT);
	if (fd >= 0 && RAND_BOOL()) {
		val = (__u32) fd;
		put_nlattr(p, &off, avail, TCA_ACT_BPF_FD, &val, sizeof(val));
		if (RAND_BOOL())
			put_nlattr(p, &off, avail, TCA_ACT_BPF_NAME, "trinity",
				   sizeof("trinity"));
		return off;
	}
	nops = build_act_bpf_classic(insns);
	put_nlattr(p, &off, avail, TCA_ACT_BPF_OPS_LEN, &nops, sizeof(nops));
	put_nlattr(p, &off, avail, TCA_ACT_BPF_OPS, insns,
		   nops * sizeof(insns[0]));
	return off;
}

/*
 * The NAT range of a ct action that translates sources or destinations:
 * addresses of one family, IPv6 one time in four, and a port range half
 * the time, each a minimum alone half the time, which
 * tcf_ct_fill_params_nat() takes for the whole range.
 */
static void build_ct_nat_range(unsigned char *p, size_t *off, size_t avail)
{
	struct in6_addr addr6;
	__u32 addr;
	__u16 port;

	if (ONE_IN(4)) {
		generate_rand_bytes((unsigned char *) &addr6, sizeof(addr6));
		put_nlattr(p, off, avail, TCA_CT_NAT_IPV6_MIN, &addr6,
			   sizeof(addr6));
		if (RAND_BOOL()) {
			generate_rand_bytes((unsigned char *) &addr6,
					    sizeof(addr6));
			put_nlattr(p, off, avail, TCA_CT_NAT_IPV6_MAX, &addr6,
				   sizeof(addr6));
		}
	} else {
		addr = rnd_u32();
		put_nlattr(p, off, avail, TCA_CT_NAT_IPV4_MIN, &addr,
			   sizeof(addr));
		if (RAND_BOOL()) {
			addr = rnd_u32();
			put_nlattr(p, off, avail, TCA_CT_NAT_IPV4_MAX, &addr,
				   sizeof(addr));
		}
	}
	if (RAND_BOOL()) {
		port = rnd_u32();
		put_nlattr(p, off, avail, TCA_CT_NAT_PORT_MIN, &port,
			   sizeof(port));
		if (RAND_BOOL()) {
			port = rnd_u32();
			put_nlattr(p, off, avail, TCA_CT_NAT_PORT_MAX, &port,
				   sizeof(port));
		}
	}
}

/*
 * ct's TCA_ACT_OPTIONS, which tcf_ct_init() parses strictly.  It refuses
 * the action without TCA_CT_PARMS, a NAT both ways, and a helper name
 * over 15 characters or of no helper nf_ct_add_helper() finds for its
 * family and protocol; a ct in a filter also wants the filter's qdisc to
 * be ingress or clsact.  One action in eight clears the packet's entry.
 * The others commit half the time, forced one in four of those, and NAT
 * one time in four, translating sources or destinations or neither; and
 * each sets a zone 1 to 8 half the time, a mark one in four and labels
 * one in eight, either under a mask half the time, and an ftp, tftp or
 * sip helper over IPv4 or IPv6 one in eight.  Index 1 to 8 names an
 * action an earlier call made, as gact's does.
 */
static size_t build_ct_options(unsigned char *p, size_t avail)
{
	static const __u16 nat_dirs[] = {
		0, TCA_CT_ACT_NAT_SRC, TCA_CT_ACT_NAT_DST,
	};
	static const struct {
		const char *name;
		__u8 proto;
	} helpers[] = {
		{ "ftp", IPPROTO_TCP }, { "tftp", IPPROTO_UDP },
		{ "sip", IPPROTO_UDP }, { "sip", IPPROTO_TCP },
	};
	unsigned char labels[16];
	struct tc_ct parm;
	size_t off = 0;
	unsigned int h;
	__u16 action = 0, zone;
	__u32 mark;
	__u8 val8;

	memset(&parm, 0, sizeof(parm));
	parm.index = ONE_IN(4) ? 0 : RAND_RANGE(1U, 8U);
	parm.action = ONE_IN(8) ? TC_ACT_JUMP | RAND_RANGE(1, 3) :
		      RAND_RANGE(TC_ACT_UNSPEC, TC_ACT_VALUE_MAX);
	if (!put_nlattr(p, &off, avail, TCA_CT_PARMS, &parm, sizeof(parm)))
		return 0;

	if (ONE_IN(8)) {
		action = TCA_CT_ACT_CLEAR;
		put_nlattr(p, &off, avail, TCA_CT_ACTION, &action,
			   sizeof(action));
		return off;
	}
	if (RAND_BOOL())
		action |= TCA_CT_ACT_COMMIT | (ONE_IN(4) ? TCA_CT_ACT_FORCE : 0);
	if (ONE_IN(4))
		action |= TCA_CT_ACT_NAT | RAND_ARRAY(nat_dirs);
	if (action != 0)
		put_nlattr(p, &off, avail, TCA_CT_ACTION, &action,
			   sizeof(action));
	if (action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST))
		build_ct_nat_range(p, &off, avail);

	if (RAND_BOOL()) {
		zone = RAND_RANGE(1, 8);
		put_nlattr(p, &off, avail, TCA_CT_ZONE, &zone, sizeof(zone));
	}
	if (ONE_IN(4)) {
		mark = rnd_u32();
		put_nlattr(p, &off, avail, TCA_CT_MARK, &mark, sizeof(mark));
		if (RAND_BOOL()) {
			mark = rnd_u32();
			put_nlattr(p, &off, avail, TCA_CT_MARK_MASK, &mark,
				   sizeof(mark));
		}
	}
	if (ONE_IN(8)) {
		generate_rand_bytes(labels, sizeof(labels));
		put_nlattr(p, &off, avail, TCA_CT_LABELS, labels,
			   sizeof(labels));
		if (RAND_BOOL()) {
			generate_rand_bytes(labels, sizeof(labels));
			put_nlattr(p, &off, avail, TCA_CT_LABELS_MASK, labels,
				   sizeof(labels));
		}
	}
	if (ONE_IN(8)) {
		h = rnd_modulo_u32(ARRAY_SIZE(helpers));
		put_nlattr(p, &off, avail, TCA_CT_HELPER_NAME, helpers[h].name,
			   strlen(helpers[h].name) + 1);
		val8 = RAND_BOOL() ? AF_INET : AF_INET6;
		put_nlattr(p, &off, avail, TCA_CT_HELPER_FAMILY, &val8,
			   sizeof(val8));
		val8 = helpers[h].proto;
		put_nlattr(p, &off, avail, TCA_CT_HELPER_PROTO, &val8,
			   sizeof(val8));
	}
	return off;
}

/*
 * Build a single nested per-action container, written at p+offset and
 * sized within cap.  Lays down a leading TCA_ACT_KIND string sub-attr
 * (required; tcf_action_init_1 -EINVALs the action when missing), for
 * the kinds in typed[] the TCA_ACT_OPTIONS their builders fill, then 0-3
 * random siblings drawn from the inner TCA_ACT_* set sized to the widths
 * the kernel's tca_act_policy walker expects (NLA_BITFIELD32 for FLAGS /
 * HW_STATS, NLA_U32 for INDEX / USED_HW_STATS / IN_HW_COUNT, NLA_NESTED
 * for OPTIONS / STATS).  Every kind but simple is in typed[]:
 * tcf_simp_act() pr_info()s each packet it sees, unratelimited, so a
 * simple action that took would flood the log from any filter with
 * traffic.
 * Returns the inner payload length (excluding the outer per-action
 * header, which the caller writes); 0 on no-room.
 */
static size_t build_tca_act_nested(unsigned char *p, size_t avail)
{
	static const struct {
		const char *kind;
		size_t (*build)(unsigned char *p, size_t avail);
	} typed[] = {
		{ "gact",	build_gact_options },
		{ "ife",	build_ife_options },
		{ "mirred",	build_mirred_options },
		{ "skbedit",	build_skbedit_options },
		{ "pedit",	build_pedit_options },
		{ "vlan",	build_vlan_options },
		{ "csum",	build_csum_options },
		{ "tunnel_key",	build_tunnel_key_options },
		{ "nat",	build_nat_options },
		{ "connmark",	build_connmark_options },
		{ "skbmod",	build_skbmod_options },
		{ "mpls",	build_mpls_options },
		{ "ctinfo",	build_ctinfo_options },
		{ "sample",	build_sample_options },
		{ "police",	build_police_options },
		{ "bpf",	build_bpf_options },
		{ "ct",		build_ct_options },
	};
	size_t (*build_options)(unsigned char *p, size_t avail) = NULL;
	const char *kind;
	size_t klen;
	size_t off = 0;
	size_t cap;
	int nchildren;
	unsigned int i;

	cap = avail;
	if (cap > 192)
		cap = 192;

	kind = tc_act_kinds[rnd_modulo_u32(ARRAY_SIZE(tc_act_kinds))];
	for (i = 0; i < ARRAY_SIZE(typed); i++)
		if (strcmp(kind, typed[i].kind) == 0)
			build_options = typed[i].build;
	klen = strlen(kind) + 1;
	if (off + NLA_ALIGN(NLA_HDRLEN + klen) > cap)
		return 0;
	if (!start_nlattr(p, off, cap, TCA_ACT_KIND, klen))
		return 0;
	memcpy(p + off + NLA_HDRLEN, kind, klen);
	off += NLA_ALIGN(NLA_HDRLEN + klen);

	if (build_options != NULL && off + NLA_HDRLEN < cap) {
		size_t olen = build_options(p + off + NLA_HDRLEN,
					    cap - off - NLA_HDRLEN);

		if (olen != 0) {
			struct nlattr nla = {
				.nla_len = NLA_HDRLEN + olen,
				.nla_type = TCA_ACT_OPTIONS | NLA_F_NESTED,
			};

			memcpy(p + off, &nla, NLA_HDRLEN);
			off += NLA_ALIGN(NLA_HDRLEN + olen);
		}
	}

	nchildren = RAND_RANGE(0, 3);
	while (nchildren-- > 0) {
		unsigned short atype;
		size_t plen;
		size_t total;
		unsigned char *payload;

		switch (rnd_modulo_u32(6)) {
		case 0:
			atype = TCA_ACT_INDEX;
			plen = sizeof(__u32);
			break;
		case 1:
			atype = TCA_ACT_IN_HW_COUNT;
			plen = sizeof(__u32);
			break;
		case 2:
			atype = TCA_ACT_FLAGS;
			plen = sizeof(struct nla_bitfield32);
			break;
		case 3:
			atype = TCA_ACT_HW_STATS;
			plen = sizeof(struct nla_bitfield32);
			break;
		case 4:
			atype = TCA_ACT_USED_HW_STATS;
			plen = sizeof(struct nla_bitfield32);
			break;
		default:
			/* TCA_ACT_OPTIONS / TCA_ACT_STATS are per-act nested
			 * containers — the sub-attr namespaces are
			 * tc_action_ops::policy and TCA_STATS_* and differ per
			 * kind.  Random siblings here keep the inner walker
			 * exercised without the per-kind table the policy
			 * would need to validate cleanly.  The typed kinds
			 * have their tables above, which a second OPTIONS
			 * would displace: the parse keeps the last. */
			atype = build_options != NULL || RAND_BOOL() ?
				TCA_ACT_STATS : TCA_ACT_OPTIONS;
			plen = RAND_RANGE(4, 16);
			break;
		}

		total = NLA_ALIGN(NLA_HDRLEN + plen);
		if (off + total > cap)
			break;
		if (!start_nlattr(p, off, cap, atype, plen))
			break;
		payload = p + off + NLA_HDRLEN;
		if (atype == TCA_ACT_FLAGS) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_ACT_FLAGS_NO_PERCPU_STATS |
				      TCA_ACT_FLAGS_SKIP_HW |
				      TCA_ACT_FLAGS_SKIP_SW;
			bf.value = rnd_u32() & bf.selector;
			memcpy(payload, &bf, sizeof(bf));
		} else if (atype == TCA_ACT_HW_STATS ||
			   atype == TCA_ACT_USED_HW_STATS) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_ACT_HW_STATS_IMMEDIATE |
				      TCA_ACT_HW_STATS_DELAYED;
			bf.value = rnd_u32() & bf.selector;
			memcpy(payload, &bf, sizeof(bf));
		} else if (plen == sizeof(__u32)) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(payload, &val, sizeof(val));
		} else {
			generate_rand_bytes(payload, plen);
		}
		off += total;
	}

	return off;
}

/*
 * Build the TCA_ROOT_TAB nested payload: 1-3 per-action containers,
 * each at nla_type = action-index in [1, TCA_ACT_MAX_PRIO-1] (the
 * kernel's tcf_action_init walker iterates tb[1..TCA_ACT_MAX_PRIO]
 * and -EINVALs on index 0 / >= TCA_ACT_MAX_PRIO).  Each inner
 * container is the typed TCA_ACT_* chain build_tca_act_nested lays
 * down.  Indices are assigned sequentially starting at a small base
 * so the kernel walker sees a contiguous run from tb[base] onward.
 * The outer TCA_ROOT_TAB header is written by append_nlattr.
 */
static size_t build_tca_root_tab_nested(unsigned char *p, size_t avail)
{
	size_t off = 0;
	size_t cap;
	int n_actions;
	int act_idx;

	if (avail < 2 * NLA_HDRLEN + 4)
		return 0;

	cap = avail;
	if (cap > 384)
		cap = 384;

	n_actions = RAND_RANGE(1, 3);
	act_idx = 1;

	while (n_actions-- > 0 && act_idx < TCA_ACT_MAX_PRIO) {
		struct nlattr act;
		size_t inner_avail;
		size_t inner_off;

		if (off + NLA_HDRLEN + NLA_HDRLEN > cap)
			break;

		inner_avail = cap - off - NLA_HDRLEN;
		inner_off = build_tca_act_nested(p + off + NLA_HDRLEN,
						 inner_avail);
		if (inner_off == 0)
			break;

		act.nla_len = NLA_HDRLEN + inner_off;
		act.nla_type = act_idx | NLA_F_NESTED;
		memcpy(p + off, &act, NLA_HDRLEN);
		off += NLA_ALIGN(NLA_HDRLEN + inner_off);
		act_idx++;
	}

	return off;
}

/*
 * Every classifier parses its own TCA_OPTIONS namespace, which the outer
 * TCA_* types the attribute draws give it never are, so seven filter adds
 * in eight go out as a matchall filter: its options (mall_policy) are a
 * classid and flags beside TCA_MATCHALL_ACT, the action array
 * tcf_exts_validate_ex() hands tcf_action_init().  That array is the one
 * way an action reaches a lane child, since tc_ctl_action() tests
 * CAP_NET_ADMIN in the initial user namespace and a filter add only over
 * the request socket's netns.  The flags are 0 or one skip bit half the
 * time (tc_flags_valid() refuses both), and a classid goes in one filter
 * in four, naming a small class as the tc headers do.  Returns the new
 * length of the message, whose first len bytes hold its header in a
 * buffer of cap bytes; len leaves it to the random draws.
 */
size_t append_tfilter_shape(struct nlmsghdr *nlh, size_t len, size_t cap)
{
	static const __u32 mall_flags[] = {
		0, TCA_CLS_FLAGS_SKIP_HW, TCA_CLS_FLAGS_SKIP_SW,
	};
	unsigned char *msg = (unsigned char *) nlh;
	size_t off = NLMSG_ALIGN(len);
	size_t opts, acts, alen;
	struct nlattr nla;
	__u32 val;

	if (len < NLMSG_LENGTH(sizeof(struct tcmsg)) || ONE_IN(8))
		return len;
	if (!put_nlattr(msg, &off, cap, TCA_KIND, "matchall",
			sizeof("matchall")))
		return len;

	opts = off;
	acts = opts + NLA_HDRLEN;
	if (acts + NLA_HDRLEN > cap)
		return len;
	alen = build_tca_root_tab_nested(msg + acts + NLA_HDRLEN,
					 cap - acts - NLA_HDRLEN);
	if (alen == 0)
		return len;
	nla.nla_len = NLA_HDRLEN + alen;
	nla.nla_type = TCA_MATCHALL_ACT | NLA_F_NESTED;
	memcpy(msg + acts, &nla, NLA_HDRLEN);
	off = acts + NLA_ALIGN(nla.nla_len);

	if (RAND_BOOL()) {
		val = RAND_ARRAY(mall_flags);
		put_nlattr(msg, &off, cap, TCA_MATCHALL_FLAGS, &val,
			   sizeof(val));
	}
	if (ONE_IN(4)) {
		val = TC_H_MAKE(RAND_RANGE(1U, 4U) << 16, RAND_RANGE(1U, 4U));
		put_nlattr(msg, &off, cap, TCA_MATCHALL_CLASSID, &val,
			   sizeof(val));
	}

	nla.nla_len = off - opts;
	nla.nla_type = TCA_OPTIONS | NLA_F_NESTED;
	memcpy(msg + opts, &nla, NLA_HDRLEN);
	return off;
}

/*
 * Generate a structured payload for tc-action rtnetlink attributes
 * (TCA_ROOT_*).  Covers the RTM_*ACTION message group (8).  The kernel
 * net/sched/act_api.c:tca_action_gd walker parses tcaa_policy and
 * length-rejects TCA_ROOT_FLAGS (NLA_BITFIELD32), TCA_ROOT_COUNT
 * (NLA_U32) and TCA_ROOT_TIME_DELTA (NLA_U32) at the wrong-width gate;
 * TCA_ROOT_TAB (== TCA_ACT_TAB) is the NLA_NESTED container the per-
 * action parser walks via tcf_action_init -> tcf_action_init_1, and
 * the parse short-circuits at -EINVAL when the leading TCA_ACT_KIND
 * sub-attr is missing or doesn't resolve to a registered
 * tc_action_ops.  Size each TCA_ROOT_* to its policy width and build
 * TCA_ROOT_TAB as a typed per-action chain so the inner per-kind
 * init runs instead of bouncing at the outer parse.
 *
 * TCA_ROOT_TAB aliases TCA_ROOT_FLAGS=2 / TCA_ROOT_COUNT=3 /
 * TCA_ROOT_TIME_DELTA=4 with the inner TCA_ACT_KIND=1 /
 * TCA_ACT_OPTIONS=2 / TCA_ACT_INDEX=3 / TCA_ACT_STATS=4 values, so
 * those inner attrs aren't emitted at the top level here -- they
 * appear inside the build_tca_act_nested chain.
 */
size_t gen_rta_action_payload(unsigned char *p, size_t avail,
			      unsigned short nla_type)
{
	switch (nla_type) {
	case TCA_ROOT_TAB:
		if (avail >= 2 * NLA_HDRLEN + 4)
			return build_tca_root_tab_nested(p, avail);
		return 0;

	case TCA_ROOT_FLAGS:
		/* NLA_BITFIELD32 over the tcaa_root_flags_policy bits
		 * (TCA_FLAG_LARGE_DUMP_ON / TCA_ACT_FLAG_TERSE_DUMP). */
		if (avail >= sizeof(struct nla_bitfield32)) {
			struct nla_bitfield32 bf;

			bf.selector = TCA_FLAG_LARGE_DUMP_ON |
				      TCA_ACT_FLAG_TERSE_DUMP;
			bf.value = rnd_u32() & bf.selector;
			memcpy(p, &bf, sizeof(bf));
			return sizeof(bf);
		}
		return 0;

	case TCA_ROOT_COUNT:
	case TCA_ROOT_TIME_DELTA:
		if (avail >= 4) {
			__u32 val = rnd_modulo_u32(64);

			memcpy(p, &val, 4);
			return 4;
		}
		return 0;

	case TCA_ROOT_EXT_WARN_MSG: {
		static const char * const msgs[] = {
			"act-warn", "kind-mismatch", "bad-attr",
		};
		const char *msg = msgs[rnd_modulo_u32(ARRAY_SIZE(msgs))];
		size_t slen = strlen(msg) + 1;

		if (avail >= slen) {
			memcpy(p, msg, slen);
			return slen;
		}
		return 0;
	}

	default:
		return 0;
	}
}
