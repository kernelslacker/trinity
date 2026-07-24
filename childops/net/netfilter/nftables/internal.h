/*
 * internal.h
 *
 * Shared declarations split out of childops/net/netfilter/nftables/churn.c to allow
 * the nftables_churn helper families to live in their own translation
 * units and compile in parallel with the dispatched entry point.  This
 * header is private to the nftables/ TUs — do not include it from
 * anywhere else.
 *
 * Contents:
 *   - the UAPI conditional #includes and their fallback macros, so the
 *     cluster sees exactly the same nf_tables symbol values;
 *   - static-inline nla_put_be{32,16,64} netlink helpers, kept inline
 *     so the linker does not see them as external (no real linkage
 *     change);
 *   - forward declarations for helpers deliberately widened from
 *     file-static to external linkage so the orchestration and sub-mode
 *     TUs can share builders without changing behaviour.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_H

#include "internal-state.h"

#include "internal-compat.h"

int nft_build_newtable(struct nfnl_ctx *ctx, __u8 family, const char *table_name);
int nft_build_deltable(struct nfnl_ctx *ctx, __u8 family, const char *table_name);
int nft_build_newset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name, __u32 set_id);
int nft_build_delset(struct nfnl_ctx *ctx, __u8 family,
		 const char *table_name, const char *set_name);
int nft_build_newchain(struct nfnl_ctx *ctx, __u8 family,
		       const char *table_name, const char *chain_name,
		       bool hook_present);
int nft_build_newrule(struct nfnl_ctx *ctx, __u8 family,
		      const char *table_name, const char *chain_name,
		      const char *target_chain, __u32 verdict_code,
		      __u64 position, const struct nft_expr_plan *plan,
		      const char *set_name, __u32 set_id);
int nft_build_delrule(struct nfnl_ctx *ctx, __u8 family,
		      const char *table_name, const char *chain_name);
__u8 nft_pick_family(void);
void nft_fill_table_name(char *out, size_t cap, const char *prefix);
void nft_expr_plan_randomize(struct nft_expr_plan *plan);
void nft_expr_plan_record_stats(const struct nft_expr_plan *plan);

void nft_dormant_abort_sweep(struct nfnl_ctx *ctx);


void nft_fwd_netdev_loop_sweep(struct nfnl_ctx *nfnl, struct nl_ctx *rtnl);
bool nft_fwd_netdev_loop_unsupported(void);

void nft_l4_aware_frag_sweep(struct nfnl_ctx *nfnl);

/*
 * build_nft_*_expr family.  Definitions live in the per-family
 * exprs-{data,set,stateful,hash,nat,conn}.c TUs.
 * Linkage widened from static to extern so the nft_expr_table
 * dispatch array in builders.c can reference them across
 * the TU split.  None of these helpers touch churn.c
 * file-scope state; they only consume caller-provided buffers
 * and netlink helpers.
 */
size_t build_nft_payload_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_meta_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_lookup_expr(unsigned char *buf, size_t off,
			     size_t cap, const char *set_name,
			     __u32 set_id);
size_t build_nft_log_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_bitwise_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_cmp_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_range_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_byteorder_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_socket_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_quota_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_objref_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_limit_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_numgen_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_hash_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_synproxy_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_counter_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_connlimit_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_masq_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_redir_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_tproxy_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_xfrm_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_dup_netdev_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_dup_ipv4_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_dup_ipv6_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_fwd_netdev_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_last_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_rt_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_fib_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_exthdr_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_osf_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_queue_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_immediate_expr(unsigned char *buf, size_t off, size_t cap);
size_t build_nft_dynset_expr(unsigned char *buf, size_t off,
			     size_t cap, const char *set_name,
			     __u32 set_id);
size_t build_nft_ct_expr(unsigned char *buf, size_t off, size_t cap);

#endif /* CHILDOPS_NFTABLES_CHURN_INTERNAL_H */
