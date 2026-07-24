/*
 * internal-state.h
 *
 * Common per-rule/set/chain state, base includes, and shared inline
 * netlink helpers used across the nftables/ TU cluster.  This is the
 * base header the other internal-*.h shards pull in for their forward-
 * declared types (struct nfnl_ctx, __u32/64, size_t, bool, ...).
 *
 * Split out of internal.h; contents are moved verbatim.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_STATE_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_STATE_H

#if __has_include(<linux/netfilter/nf_tables.h>)
#include <linux/netfilter/nf_tables.h>
#endif
#if __has_include(<linux/netfilter/nfnetlink.h>)
#include <linux/netfilter/nfnetlink.h>
#endif
#if __has_include(<linux/xfrm.h>)
#include <linux/xfrm.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#define NFNL_BUF_BYTES			2048

/*
 * Small netlink-attribute helpers.  Originally file-static in
 * churn.c; promoted to static-inline so every TU in the
 * split (churn.c plus the exprs-*.c per-family builders) can
 * call them without changing observable
 * linkage.
 */
static inline size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static inline size_t nla_put_be16(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u16 v)
{
	__u16 be = htons(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static inline size_t nla_put_be64(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u64 v)
{
	__u64 be = ((__u64)htonl((__u32)(v >> 32))) |
		   (((__u64)htonl((__u32)v)) << 32);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

/*
 * Plan describing which optional expressions a NEWRULE message should
 * carry.  Named fields keep designated-initialiser call sites and
 * debugger inspection legible.
 */
struct nft_expr_plan {
	bool with_payload;
	bool with_meta;
	bool with_lookup;
	bool with_log;
	bool with_bitwise;
	bool with_cmp;
	bool with_range;
	bool with_byteorder;
	bool with_socket;
	bool with_quota;
	bool with_limit;
	bool with_numgen;
	bool with_hash;
	bool with_synproxy;
	bool with_counter;
	bool with_connlimit;
	bool with_masq;
	bool with_redir;
	bool with_tproxy;
	bool with_xfrm;
	bool with_dup_netdev;
	bool with_dup_ipv4;
	bool with_dup_ipv6;
	bool with_fwd_netdev;
	bool with_last;
	bool with_rt;
	bool with_fib;
	bool with_exthdr;
	bool with_osf;
	bool with_queue;
	bool with_immediate;
	bool with_dynset;
	bool with_ct;
	bool with_objref;
};

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_STATE_H */
