/*
 * msg-rtnl-tc.c
 *
 * Per-family rtnetlink payload builders for the tc (TCA_*),
 * tc-action (TCA_ROOT_*) and link-stats (IFLA_STATS_*) groups, split
 * out of net/netlink/msg-rtnl-payloads.c so each family's rationale
 * comments and per-attr switch live in a TU a reviewer thinks about
 * separately.  Shared helpers (rand_ipv4, rand_ipv6, start_nlattr,
 * build_nested_attrs) live in net/netlink/msg-rtnl-common.c.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
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
			__atomic_add_fetch(&shm->stats.netlink_stab_emit_skipped,
					   1, __ATOMIC_RELAXED);
			return 0;
		}
		max_tsize_sz = (avail - base_sz - (size_t)NLA_HDRLEN) /
			       sizeof(__u16);
		if (max_tsize_sz < 1) {
			__atomic_add_fetch(&shm->stats.netlink_stab_emit_skipped,
					   1, __ATOMIC_RELAXED);
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
 * Build a single nested per-action container, written at p+offset and
 * sized within cap.  Lays down a leading TCA_ACT_KIND string sub-attr
 * (required; tcf_action_init_1 -EINVALs the action when missing) then
 * 0-3 random siblings drawn from the inner TCA_ACT_* set sized to the
 * widths the kernel's tca_act_policy walker expects (NLA_BITFIELD32
 * for FLAGS / HW_STATS, NLA_U32 for INDEX / USED_HW_STATS /
 * IN_HW_COUNT, NLA_NESTED for OPTIONS / STATS).  Returns the inner
 * payload length (excluding the outer per-action header, which the
 * caller writes); 0 on no-room.
 */
static size_t build_tca_act_nested(unsigned char *p, size_t avail)
{
	const char *kind;
	size_t klen;
	size_t off = 0;
	size_t cap;
	int nchildren;

	cap = avail;
	if (cap > 192)
		cap = 192;

	kind = tc_act_kinds[rnd_modulo_u32(ARRAY_SIZE(tc_act_kinds))];
	klen = strlen(kind) + 1;
	if (off + NLA_ALIGN(NLA_HDRLEN + klen) > cap)
		return 0;
	if (!start_nlattr(p, off, cap, TCA_ACT_KIND, klen))
		return 0;
	memcpy(p + off + NLA_HDRLEN, kind, klen);
	off += NLA_ALIGN(NLA_HDRLEN + klen);

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
			 * would need to validate cleanly. */
			atype = RAND_BOOL() ? TCA_ACT_OPTIONS : TCA_ACT_STATS;
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
