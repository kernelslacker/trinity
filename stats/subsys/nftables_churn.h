#ifndef _TRINITY_STATS_SUBSYS_NFTABLES_CHURN_H
#define _TRINITY_STATS_SUBSYS_NFTABLES_CHURN_H

/* nftables_churn childop counters */
struct nftables_churn_stats {
	unsigned long runs;			/* total nftables_churn invocations */
	unsigned long setup_failed;		/* unshare / nfnl_open / nf_tables latched */
	unsigned long table_create_ok;		/* NFT_MSG_NEWTABLE accepted */
	unsigned long set_create_ok;		/* NFT_MSG_NEWSET (anonymous) accepted */
	unsigned long chain_create_ok;		/* NFT_MSG_NEWCHAIN (base or aux) accepted */
	unsigned long rule_create_ok;		/* NFT_MSG_NEWRULE (append) accepted */
	unsigned long packet_sent_ok;		/* loopback UDP sendto returned >0 (drives input hook) */
	unsigned long rule_insert_ok;		/* NFT_MSG_NEWRULE at NFTA_RULE_POSITION accepted */
	unsigned long rule_del_ok;		/* NFT_MSG_DELRULE bulk-del accepted */
	unsigned long table_del_ok;		/* NFT_MSG_DELTABLE accepted */
	unsigned long payload_expr_emit;	/* NEWRULE carried a structured nft_payload expression */
	unsigned long meta_expr_emit;		/* NEWRULE carried a structured nft_meta expression */
	unsigned long lookup_expr_emit;		/* NEWRULE carried a structured nft_lookup expression */
	unsigned long log_expr_emit;		/* NEWRULE carried a structured nft_log expression */
	unsigned long bitwise_expr_emit;	/* NEWRULE carried a structured nft_bitwise expression */
	unsigned long cmp_expr_emit;		/* NEWRULE carried a structured nft_cmp expression */
	unsigned long range_expr_emit;		/* NEWRULE carried a structured nft_range expression */
	unsigned long byteorder_expr_emit;	/* NEWRULE carried a structured nft_byteorder expression */
	unsigned long socket_expr_emit;		/* NEWRULE carried a structured nft_socket expression */
	unsigned long quota_expr_emit;		/* NEWRULE carried a structured nft_quota expression */
	unsigned long limit_expr_emit;		/* NEWRULE carried a structured nft_limit expression */
	unsigned long numgen_expr_emit;		/* NEWRULE carried a structured nft_numgen expression */
	unsigned long hash_expr_emit;		/* NEWRULE carried a structured nft_hash expression */
	unsigned long synproxy_expr_emit;	/* NEWRULE carried a structured nft_synproxy expression */
	unsigned long counter_expr_emit;	/* NEWRULE carried a structured nft_counter expression */
	unsigned long connlimit_expr_emit;	/* NEWRULE carried a structured nft_connlimit expression */
	unsigned long masq_expr_emit;		/* NEWRULE carried a structured nft_masq expression */
	unsigned long redir_expr_emit;		/* NEWRULE carried a structured nft_redir expression */
	unsigned long tproxy_expr_emit;		/* NEWRULE carried a structured nft_tproxy expression */
	unsigned long xfrm_expr_emit;		/* NEWRULE carried a structured nft_xfrm expression */
	unsigned long dup_netdev_expr_emit;	/* NEWRULE carried a structured nft_dup_netdev expression */
	unsigned long dup_ipv4_expr_emit;	/* NEWRULE carried a structured nft_dup_ipv4 expression */
	unsigned long dup_ipv6_expr_emit;	/* NEWRULE carried a structured nft_dup_ipv6 expression */
	unsigned long fwd_netdev_expr_emit;	/* NEWRULE carried a structured nft_fwd_netdev expression */
	unsigned long last_expr_emit;		/* NEWRULE carried a structured nft_last expression */
	unsigned long rt_expr_emit;		/* NEWRULE carried a structured nft_rt expression */
	unsigned long fib_expr_emit;		/* NEWRULE carried a structured nft_fib expression */
	unsigned long exthdr_expr_emit;		/* NEWRULE carried a structured nft_exthdr expression */
	unsigned long osf_expr_emit;		/* NEWRULE carried a structured nft_osf expression */
	unsigned long queue_expr_emit;		/* NEWRULE carried a structured nft_queue expression */
	unsigned long immediate_expr_emit;	/* NEWRULE carried a structured nft_immediate expression */
	unsigned long dynset_expr_emit;		/* NEWRULE carried a structured nft_dynset expression */
	unsigned long ct_expr_emit;		/* NEWRULE carried a structured nft_ct expression */
	unsigned long objref_expr_emit;		/* NEWRULE carried a structured nft_objref expression */
	unsigned long nft_compat_validate_install_ok;		/* (target, hook) chain+rule accepted */
	unsigned long nft_compat_validate_install_fail;		/* (target, hook) chain+rule rejected (non-unsupported) */
	unsigned long nft_compat_validate_unsupported;		/* EOPNOTSUPP/EPROTONOSUPPORT (compat target absent) */
	unsigned long nft_compat_validate_per_hook_pairs;	/* (target, hook) pair install attempts */
	unsigned long nft_dormant_abort_iters;		/* dormant-table abort sub-mode invocations */
	unsigned long nft_dormant_abort_eperm;		/* sendmsg EPERM (CAP_NET_ADMIN gate) -- latches */
	unsigned long nft_dormant_abort_emsg;		/* sendmsg failures other than EPERM */
	unsigned long nft_dormant_abort_ok;		/* batch sent + drain completed */
	unsigned long xt_ct_iters;		/* xt_CT usersize sub-mode invocations */
	unsigned long xt_ct_eperm;		/* setsockopt EPERM (CAP_NET_ADMIN gate) -- latches */
	unsigned long xt_ct_unsupported;	/* xt_CT module absent (ENOENT/EOPNOTSUPP/ENOPROTOOPT) -- latches */
	unsigned long xt_ct_set_ok;		/* IPT/IP6T_SO_SET_REPLACE accepted */
	unsigned long xt_ct_get_ok;		/* IPT/IP6T_SO_GET_ENTRIES accepted (xt_target_to_user reply path) */
	unsigned long xt_ct_v2_seen;		/* revision 2 path actually accepted on this kernel */
	unsigned long nft_fwd_loop_runs;		/* nft_fwd_netdev loop sub-mode invocations */
	unsigned long nft_fwd_loop_ns_setup_failed;	/* veth/addr/netdev-table install failed -- latches */
	unsigned long nft_fwd_loop_probe_sent_ok;	/* ICMP probe via raw socket sendto returned >0 */
	unsigned long nft_fwd_loop_completed_ok;	/* full setup + chains + rules + probe completed */
	unsigned long nft_l4frag_iters;			/* L4-aware-on-fragment sub-mode invocations */
	unsigned long nft_l4frag_install_ok;		/* table + pre-defrag chain install accepted */
	unsigned long nft_l4frag_rule_ok;		/* NEWRULE carrying socket/tproxy/exthdr/osf accepted */
	unsigned long nft_l4frag_send_ok;		/* raw IPv4 fragment sendto returned >0 */
	unsigned long nft_l4frag_send_failed;		/* raw IPv4 fragment sendto returned <=0 (incl. EPERM on raw open) */
};

#endif /* _TRINITY_STATS_SUBSYS_NFTABLES_CHURN_H */
