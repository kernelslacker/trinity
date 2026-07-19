/*
 * xt.c
 *
 * xtables sockopt grammar probes used by nftables_churn.
 */

#include "internal.h"

/*
 * xt_CT v1+v2 usersize sub-mode (upstream 8bedb6c46945 "netfilter: xt_CT:
 * fix kernel infoleak via xt_get_target").  Drives the iptables sockopt
 * reply path -- IPT/IP6T_SO_GET_ENTRIES -> xt_target_to_user -- where a
 * usersize/targetsize mismatch historically leaked the trailing
 * kernel-internal "struct nf_conn *ct" (and timeout pointer at revision 2)
 * into the userspace reply.  Each iteration installs a "raw" table with
 * one PRE_ROUTING rule whose target is xt_CT (revision selectable), then
 * walks GET_INFO -> GET_ENTRIES, then drops in an empty replace and
 * closes.  Independent latch (ns_unsupported_xt_ct) so a kernel without
 * xt_CT or CAP_NET_ADMIN pays the EFAIL once.
 *
 * Layouts come from local-named mirrors -- including <linux/netfilter_ipv4
 * /ip_tables.h> here would clash with this TU's pre-existing <net/if.h>
 * via <linux/in.h> / <linux/if.h>.  The mirrors track the stable kernel
 * UAPI for ip_tables / ip6_tables / x_tables.
 */
#ifndef IPT_SO_SET_REPLACE
#define IPT_SO_SET_REPLACE	64
#endif
#ifndef IPT_SO_GET_INFO
#define IPT_SO_GET_INFO		64
#endif
#ifndef IPT_SO_GET_ENTRIES
#define IPT_SO_GET_ENTRIES	65
#endif
#ifndef IP6T_SO_SET_REPLACE
#define IP6T_SO_SET_REPLACE	64
#endif
#ifndef IP6T_SO_GET_INFO
#define IP6T_SO_GET_INFO	64
#endif
#ifndef IP6T_SO_GET_ENTRIES
#define IP6T_SO_GET_ENTRIES	65
#endif
#ifndef IPPROTO_RAW
#define IPPROTO_RAW		255
#endif
#ifndef XT_CT_NOTRACK
#define XT_CT_NOTRACK		(1U << 0)
#endif
#define XT_LC_TABLE_MAXNAMELEN	32
#define XT_LC_EXT_MAXNAMELEN	29
#define XT_LC_FUNC_MAXNAMELEN	30
#define XT_LC_NUMHOOKS		5
#define XT_LC_ALIGN8(x)		(((x) + 7U) & ~7U)

/* Locally-named struct mirrors.  Layouts mirror linux/netfilter/x_tables.h
 * and linux/netfilter_ipv{4,6}/ip{,6}_tables.h as of upstream 6.x. */
struct xt_lc_counters {
	__u64	pcnt, bcnt;
};

struct xt_lc_entry_target_hdr {
	__u16	target_size;
	char	name[XT_LC_EXT_MAXNAMELEN];
	__u8	revision;
};	/* 32 bytes; layout matches xt_entry_target.u.user */

struct xt_lc_ip4 {
	__u32	src, dst;
	__u32	smsk, dmsk;
	char	iniface[16], outiface[16];
	unsigned char iniface_mask[16], outiface_mask[16];
	__u16	proto;
	__u8	flags, invflags;
};

struct xt_lc_ip6 {
	__u32	src[4], dst[4];
	__u32	smsk[4], dmsk[4];
	char	iniface[16], outiface[16];
	unsigned char iniface_mask[16], outiface_mask[16];
	__u16	proto;
	__u8	tos;
	__u8	flags, invflags;
};

struct xt_lc_ipt_entry {
	struct xt_lc_ip4		ip;
	unsigned int			nfcache;
	__u16				target_offset, next_offset;
	unsigned int			comefrom;
	struct xt_lc_counters		counters;
};

struct xt_lc_ip6t_entry {
	struct xt_lc_ip6		ipv6;
	unsigned int			nfcache;
	__u16				target_offset, next_offset;
	unsigned int			comefrom;
	struct xt_lc_counters		counters;
};

struct xt_lc_ipt_replace {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			valid_hooks;
	unsigned int			num_entries;
	unsigned int			size;
	unsigned int			hook_entry[XT_LC_NUMHOOKS];
	unsigned int			underflow[XT_LC_NUMHOOKS];
	unsigned int			num_counters;
	struct xt_lc_counters		*counters;
};

struct xt_lc_getinfo {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			valid_hooks;
	unsigned int			hook_entry[XT_LC_NUMHOOKS];
	unsigned int			underflow[XT_LC_NUMHOOKS];
	unsigned int			num_entries;
	unsigned int			size;
};

struct xt_lc_get_entries_hdr {
	char				name[XT_LC_TABLE_MAXNAMELEN];
	unsigned int			size;
};

/* xt_CT target_info mirrors.  Sysroot's xt_ct_target_info_v1 may or may
 * not be present; local naming avoids any collision and pins the trailing
 * kernel-pointer slot count per revision (the slot xt_target_to_user
 * historically copied back without trimming via usersize). */
struct xtct_lc_v1 {
	__u16	flags;
	__u16	zone;
	__u32	ct_events;
	__u32	exp_events;
	char	helper[16];
	char	timeout[32];
	__u64	_kpad_ct;	/* mirrors kernel's trailing nf_conn *ct */
} __attribute__((aligned(8)));

struct xtct_lc_v2 {
	__u16	flags;
	__u16	zone;
	__u32	ct_events;
	__u32	exp_events;
	char	helper[16];
	char	timeout[32];
	__u64	_kpad_ct;
	__u64	_kpad_to;	/* extra trailing timeout pointer at v2 */
} __attribute__((aligned(8)));

static bool ns_unsupported_xt_ct;

bool nft_xt_ct_usersize_unsupported(void)
{
	return ns_unsupported_xt_ct;
}

static void xt_ct_emit_target(unsigned char *t_off, const char *name,
			      __u8 revision, __u16 target_size_total)
{
	struct xt_lc_entry_target_hdr *th = (struct xt_lc_entry_target_hdr *)t_off;

	th->target_size = target_size_total;
	th->revision    = revision;
	strncpy(th->name, name, XT_LC_EXT_MAXNAMELEN - 1);
}

static void xt_ct_emit_std_policy(unsigned char *e_off, unsigned int entry_hdr_sz,
				  unsigned int policy_sz, unsigned int std_total,
				  bool ipv6)
{
	int *verdict;

	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)policy_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)policy_sz;
	}
	xt_ct_emit_target(e_off + entry_hdr_sz, "", 0, (__u16)std_total);
	verdict = (int *)(e_off + entry_hdr_sz +
			  XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr)));
	*verdict = -NF_ACCEPT - 1;
}

static void xt_ct_emit_error(unsigned char *e_off, unsigned int entry_hdr_sz,
			     unsigned int error_sz, unsigned int err_total,
			     bool ipv6)
{
	unsigned char *errname;

	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)error_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)e_off;

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)error_sz;
	}
	xt_ct_emit_target(e_off + entry_hdr_sz, "ERROR", 0, (__u16)err_total);
	errname = e_off + entry_hdr_sz +
		  XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	memcpy(errname, "ERROR", 5);
}

static void xt_ct_fill_replace_hdr(unsigned char *buf, unsigned int rule_sz,
				   unsigned int policy_sz, unsigned int total_sz,
				   struct xt_lc_counters *counters_scratch,
				   unsigned int num_entries)
{
	struct xt_lc_ipt_replace *r = (struct xt_lc_ipt_replace *)buf;

	memcpy(r->name, "raw", 4);
	r->valid_hooks  = (1U << NF_INET_PRE_ROUTING) | (1U << NF_INET_LOCAL_OUT);
	r->num_entries  = num_entries;
	r->size         = total_sz;
	r->hook_entry[NF_INET_PRE_ROUTING] = 0;
	r->underflow[NF_INET_PRE_ROUTING]  = rule_sz;
	r->hook_entry[NF_INET_LOCAL_OUT]   = rule_sz + policy_sz;
	r->underflow[NF_INET_LOCAL_OUT]    = rule_sz + policy_sz;
	r->num_counters = num_entries;
	r->counters     = counters_scratch;
}

static void xt_ct_probe_one(bool ipv6, __u8 revision)
{
	unsigned char buf[1536];
	unsigned char get_buf[1536];
	struct xt_lc_counters counters_scratch[8];
	unsigned int hdr_sz, entry_hdr_sz;
	unsigned int target_hdr_sz, target_data_sz;
	unsigned int std_total, err_total;
	unsigned int rule_sz, policy_sz, error_sz, total_sz;
	unsigned int off, t_data_off;
	int fd, level, sockopt_set, sockopt_get_info, sockopt_get_entries;

	__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_iters, 1, __ATOMIC_RELAXED);

	if (ipv6) {
		level                = IPPROTO_IPV6;
		sockopt_set          = IP6T_SO_SET_REPLACE;
		sockopt_get_info     = IP6T_SO_GET_INFO;
		sockopt_get_entries  = IP6T_SO_GET_ENTRIES;
		entry_hdr_sz         = (unsigned int)sizeof(struct xt_lc_ip6t_entry);
		fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	} else {
		level                = IPPROTO_IP;
		sockopt_set          = IPT_SO_SET_REPLACE;
		sockopt_get_info     = IPT_SO_GET_INFO;
		sockopt_get_entries  = IPT_SO_GET_ENTRIES;
		entry_hdr_sz         = (unsigned int)sizeof(struct xt_lc_ipt_entry);
		fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	}
	hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_replace);
	if (fd < 0) {
		if (errno == EPERM) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EAFNOSUPPORT ||
			   errno == EPROTONOSUPPORT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	target_hdr_sz  = (unsigned int)XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	target_data_sz = (revision == 2)
		? (unsigned int)XT_LC_ALIGN8(sizeof(struct xtct_lc_v2))
		: (unsigned int)XT_LC_ALIGN8(sizeof(struct xtct_lc_v1));
	std_total      = target_hdr_sz + (unsigned int)XT_LC_ALIGN8(sizeof(int));
	err_total      = target_hdr_sz +
			 (unsigned int)XT_LC_ALIGN8(XT_LC_FUNC_MAXNAMELEN);

	rule_sz   = entry_hdr_sz + target_hdr_sz + target_data_sz;
	policy_sz = entry_hdr_sz + std_total;
	error_sz  = entry_hdr_sz + err_total;
	total_sz  = rule_sz + 2 * policy_sz + error_sz;

	if (hdr_sz + total_sz > sizeof(buf))
		goto out;

	memset(buf, 0, sizeof(buf));
	memset(counters_scratch, 0, sizeof(counters_scratch));
	xt_ct_fill_replace_hdr(buf, rule_sz, policy_sz, total_sz,
			       counters_scratch, 4);

	off = hdr_sz;

	/* Entry 1: PRE_ROUTING rule -- xt_CT target, no match. */
	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	}
	xt_ct_emit_target(buf + off + entry_hdr_sz, "CT", revision,
			  (__u16)(target_hdr_sz + target_data_sz));
	t_data_off = off + entry_hdr_sz + target_hdr_sz;
	if (revision == 2) {
		struct xtct_lc_v2 *info = (struct xtct_lc_v2 *)(buf + t_data_off);

		info->flags      = XT_CT_NOTRACK;
		info->zone       = (__u16)(rand32() & 0xffff);
		info->ct_events  = rand32();
		info->exp_events = rand32();
		generate_rand_bytes((unsigned char *)info->helper,
				    sizeof(info->helper));
		generate_rand_bytes((unsigned char *)info->timeout,
				    sizeof(info->timeout));
	} else {
		struct xtct_lc_v1 *info = (struct xtct_lc_v1 *)(buf + t_data_off);

		info->flags      = XT_CT_NOTRACK;
		info->zone       = (__u16)(rand32() & 0xffff);
		info->ct_events  = rand32();
		info->exp_events = rand32();
		generate_rand_bytes((unsigned char *)info->helper,
				    sizeof(info->helper));
		generate_rand_bytes((unsigned char *)info->timeout,
				    sizeof(info->timeout));
	}
	off += rule_sz;

	/* Entries 2 + 3: PRE_ROUTING policy + LOCAL_OUT policy (std ACCEPT). */
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;

	/* Entry 4: error sentinel. */
	xt_ct_emit_error(buf + off, entry_hdr_sz, error_sz, err_total, ipv6);

	if (setsockopt(fd, level, sockopt_set, buf,
		       (socklen_t)(hdr_sz + total_sz)) < 0) {
		if (errno == EPERM) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == ENOENT || errno == EOPNOTSUPP ||
			   errno == ENOPROTOOPT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_set_ok, 1, __ATOMIC_RELAXED);
	if (revision == 2)
		__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_v2_seen,
				   1, __ATOMIC_RELAXED);

	/* GET_INFO -> GET_ENTRIES.  The historical leak window is the
	 * second sockopt: xt_target_to_user copies the kernel's full
	 * targetsize tail into the userspace reply. */
	{
		struct xt_lc_getinfo gi;
		socklen_t gi_len = (socklen_t)sizeof(gi);

		memset(&gi, 0, sizeof(gi));
		memcpy(gi.name, "raw", 4);
		if (getsockopt(fd, level, sockopt_get_info,
			       &gi, &gi_len) == 0 && gi.size > 0 &&
		    sizeof(struct xt_lc_get_entries_hdr) + gi.size <=
		    sizeof(get_buf)) {
			socklen_t ge_len = (socklen_t)
				(sizeof(struct xt_lc_get_entries_hdr) + gi.size);

			memset(get_buf, 0, sizeof(get_buf));
			memcpy(get_buf, "raw", 4);
			((struct xt_lc_get_entries_hdr *)get_buf)->size = gi.size;
			if (getsockopt(fd, level, sockopt_get_entries,
				       get_buf, &ge_len) == 0)
				__atomic_add_fetch(&shm->stats.nftables_churn.xt_ct_get_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/* Cleanup: empty replace (only policy + error entries, no xt_CT
	 * rule).  Reuses buf with rule entry stripped. */
	{
		unsigned int empty_total = 2 * policy_sz + error_sz;
		unsigned int empty_off;

		memset(buf, 0, sizeof(buf));
		xt_ct_fill_replace_hdr(buf, 0, policy_sz, empty_total,
				       counters_scratch, 3);
		empty_off = hdr_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_error(buf + empty_off, entry_hdr_sz,
				 error_sz, err_total, ipv6);
		(void)setsockopt(fd, level, sockopt_set, buf,
				 (socklen_t)(hdr_sz + empty_total));
	}
out:
	close(fd);
}

void nft_xt_ct_usersize_sweep(void)
{
	if (ns_unsupported_xt_ct)
		return;
	xt_ct_probe_one(false, 1);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(false, 2);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(true, 1);
	if (!ns_unsupported_xt_ct)
		xt_ct_probe_one(true, 2);
}

/*
 * xt_IDLETIMER grammar sub-mode.  Extends the iptables blob builder
 * above to install an IDLETIMER target so trinity can exercise the
 * module's setsockopt validation, label/timeout churn, and the v1
 * timer_type field (XT_IDLETIMER_ALARM).  Layout mirrors
 * xt_ct_probe_one and shares the same struct xt_lc_ipt_* /
 * xt_ct_emit_target helpers so the wire format stays byte-identical
 * with the CT path -- only the target name and info-blob layout
 * differ.
 *
 * Config: CONFIG_NETFILTER_XT_TARGET_IDLETIMER (module).  When the
 * module isn't present, setsockopt fails cleanly with ENOENT /
 * EOPNOTSUPP / ENOPROTOOPT (no hard dependency on the target) and
 * the ns_unsupported_xt_idletimer latch short-circuits sibling
 * probes for the child's lifetime.
 *
 * Local mirrors track the stable kernel UAPI in
 * <linux/netfilter/xt_IDLETIMER.h>; XT_IDLETIMER_ALARM and
 * idletimer_tg_info_v1 aren't guaranteed in the build sysroot's
 * headers so both are #ifndef-shimmed.  The trailing __u64 slot
 * mirrors the kernel's internal "struct idletimer_tg *timer" tail
 * (aligned(8) in the uapi) -- keeps setsockopt's targetsize check
 * happy without depending on the kernel-internal pointer type.
 */
#ifndef XT_IDLETIMER_LABEL_MAX
#define XT_IDLETIMER_LABEL_MAX	28
#endif
#ifndef XT_IDLETIMER_ALARM
#define XT_IDLETIMER_ALARM	0x01
#endif

struct xtidle_lc_v0 {
	__u32	timeout;
	char	label[XT_IDLETIMER_LABEL_MAX];
	__u64	_kpad_timer;	/* mirrors kernel's trailing idletimer_tg * */
} __attribute__((aligned(8)));

struct xtidle_lc_v1 {
	__u32	timeout;
	char	label[XT_IDLETIMER_LABEL_MAX];
	__u8	timer_type;	/* v1: XT_IDLETIMER_ALARM or 0 */
	__u64	_kpad_timer;
} __attribute__((aligned(8)));

static bool ns_unsupported_xt_idletimer;

bool nft_xt_idletimer_unsupported(void)
{
	return ns_unsupported_xt_idletimer;
}

static void xt_idletimer_probe_one(bool ipv6, __u8 revision)
{
	unsigned char buf[1536];
	struct xt_lc_counters counters_scratch[8];
	unsigned int hdr_sz, entry_hdr_sz;
	unsigned int target_hdr_sz, target_data_sz;
	unsigned int std_total, err_total;
	unsigned int rule_sz, policy_sz, error_sz, total_sz;
	unsigned int off, t_data_off;
	int fd, level, sockopt_set;

	if (ipv6) {
		level        = IPPROTO_IPV6;
		sockopt_set  = IP6T_SO_SET_REPLACE;
		entry_hdr_sz = (unsigned int)sizeof(struct xt_lc_ip6t_entry);
		fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	} else {
		level        = IPPROTO_IP;
		sockopt_set  = IPT_SO_SET_REPLACE;
		entry_hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_entry);
		fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	}
	hdr_sz = (unsigned int)sizeof(struct xt_lc_ipt_replace);
	if (fd < 0) {
		if (errno == EPERM || errno == EAFNOSUPPORT ||
		    errno == EPROTONOSUPPORT)
			ns_unsupported_xt_idletimer = true;
		return;
	}

	target_hdr_sz  = (unsigned int)XT_LC_ALIGN8(sizeof(struct xt_lc_entry_target_hdr));
	target_data_sz = (revision == 1)
		? (unsigned int)XT_LC_ALIGN8(sizeof(struct xtidle_lc_v1))
		: (unsigned int)XT_LC_ALIGN8(sizeof(struct xtidle_lc_v0));
	std_total      = target_hdr_sz + (unsigned int)XT_LC_ALIGN8(sizeof(int));
	err_total      = target_hdr_sz +
			 (unsigned int)XT_LC_ALIGN8(XT_LC_FUNC_MAXNAMELEN);

	rule_sz   = entry_hdr_sz + target_hdr_sz + target_data_sz;
	policy_sz = entry_hdr_sz + std_total;
	error_sz  = entry_hdr_sz + err_total;
	total_sz  = rule_sz + 2 * policy_sz + error_sz;

	if (hdr_sz + total_sz > sizeof(buf))
		goto out;

	memset(buf, 0, sizeof(buf));
	memset(counters_scratch, 0, sizeof(counters_scratch));
	xt_ct_fill_replace_hdr(buf, rule_sz, policy_sz, total_sz,
			       counters_scratch, 4);

	off = hdr_sz;

	/* Entry 1: PRE_ROUTING rule -- IDLETIMER target, no match. */
	if (ipv6) {
		struct xt_lc_ip6t_entry *e = (struct xt_lc_ip6t_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	} else {
		struct xt_lc_ipt_entry *e = (struct xt_lc_ipt_entry *)(buf + off);

		e->target_offset = (__u16)entry_hdr_sz;
		e->next_offset   = (__u16)rule_sz;
	}
	xt_ct_emit_target(buf + off + entry_hdr_sz, "IDLETIMER", revision,
			  (__u16)(target_hdr_sz + target_data_sz));
	t_data_off = off + entry_hdr_sz + target_hdr_sz;
	if (revision == 1) {
		struct xtidle_lc_v1 *info = (struct xtidle_lc_v1 *)(buf + t_data_off);

		info->timeout = rand32();
		snprintf(info->label, sizeof(info->label), "trlbl_%u",
			 (unsigned int)(rand32() & 0xffffu));
		info->timer_type = (rand32() & 1) ? XT_IDLETIMER_ALARM : 0;
	} else {
		struct xtidle_lc_v0 *info = (struct xtidle_lc_v0 *)(buf + t_data_off);

		info->timeout = rand32();
		snprintf(info->label, sizeof(info->label), "trlbl_%u",
			 (unsigned int)(rand32() & 0xffffu));
	}
	off += rule_sz;

	/* Entries 2 + 3: PRE_ROUTING policy + LOCAL_OUT policy (std ACCEPT). */
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;
	xt_ct_emit_std_policy(buf + off, entry_hdr_sz, policy_sz, std_total, ipv6);
	off += policy_sz;

	/* Entry 4: error sentinel. */
	xt_ct_emit_error(buf + off, entry_hdr_sz, error_sz, err_total, ipv6);

	if (setsockopt(fd, level, sockopt_set, buf,
		       (socklen_t)(hdr_sz + total_sz)) < 0) {
		if (errno == EPERM || errno == ENOENT ||
		    errno == EOPNOTSUPP || errno == ENOPROTOOPT)
			ns_unsupported_xt_idletimer = true;
		goto out;
	}

	/* Cleanup: empty replace (only policy + error entries, no IDLETIMER
	 * rule).  Reuses buf with rule entry stripped. */
	{
		unsigned int empty_total = 2 * policy_sz + error_sz;
		unsigned int empty_off;

		memset(buf, 0, sizeof(buf));
		xt_ct_fill_replace_hdr(buf, 0, policy_sz, empty_total,
				       counters_scratch, 3);
		empty_off = hdr_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_std_policy(buf + empty_off, entry_hdr_sz,
				      policy_sz, std_total, ipv6);
		empty_off += policy_sz;
		xt_ct_emit_error(buf + empty_off, entry_hdr_sz,
				 error_sz, err_total, ipv6);
		(void)setsockopt(fd, level, sockopt_set, buf,
				 (socklen_t)(hdr_sz + empty_total));
	}
out:
	close(fd);
}

void nft_xt_idletimer_sweep(void)
{
	if (ns_unsupported_xt_idletimer)
		return;
	xt_idletimer_probe_one(false, 0);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(false, 1);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(true, 0);
	if (!ns_unsupported_xt_idletimer)
		xt_idletimer_probe_one(true, 1);
}
