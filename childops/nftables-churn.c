/*
 * nftables_churn - nftables table/chain/set/rule churn racing live traffic.
 *
 * Per-syscall fuzzing rolls a fresh NFT_MSG_* per call and never gets
 * past nf_tables_api's per-message lookup gates: NEWCHAIN demands an
 * existing table, NEWRULE demands an existing chain, DELRULE demands
 * a chain that has rules.  The interesting bug surface lives in the
 * transaction-commit path (nf_tables_commit / nft_chain_commit_drop_policy
 * / nft_rule_destroy / nft_set_destroy), where the rule/set/chain has
 * to actually have references — live verdicts pointing at it, an
 * ongoing lookup walking it, an in-flight skb traversing the hook
 * while the commit tears it down.  Without a coherent table -> chain
 * -> rule chain plus traffic into the registered hook, the whole
 * commit machinery never engages and the recent CVE-class window
 * (CVE-2024-1086 nft_verdict UAF, CVE-2023-32233 anonymous-set
 * double-free, CVE-2024-26642 nft_setelem, CVE-2024-26581
 * nft_set_rbtree, CVE-2023-3390 nft_chain) stays cold.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host nftables ruleset is touched.  Failure
 *      latches the whole op off.
 *   2. Bring lo up inside the netns (one-time).
 *   3. socket(AF_NETLINK, NETLINK_NETFILTER).  EPROTONOSUPPORT here
 *      means CONFIG_NF_NETLINK is off — latch ns_unsupported_nfnetlink
 *      and skip permanently.
 *   4. NFT_MSG_NEWTABLE with a random nf_tables family chosen from
 *      {NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV} per call.  The
 *      family is rolled per-iteration so the commit path runs against
 *      different per-family afinfo registrations, not just one.
 *      EOPNOTSUPP / EAFNOSUPPORT / EPROTONOSUPPORT all latch
 *      ns_unsupported_nf_tables — the kernel's nf_tables module is
 *      unavailable, no point retrying.
 *   5. NFT_MSG_NEWSET creating an anonymous (NFT_SET_ANONYMOUS) +
 *      dynamic (NFT_SET_DYNAMIC) set keyed on ipv4_addr (key_len = 4).
 *      The anonymous flag is what the CVE-2023-32233 double-free
 *      window hangs off — anonymous sets are tied to the rule that
 *      owns them and torn down on rule removal, with a refcount
 *      arrangement that historically races commit vs abort.
 *   6. NFT_MSG_NEWCHAIN creating an auxiliary regular (no-hook) chain
 *      "chain_aux" — the jump target referenced by the rule's verdict
 *      in step 8.  Created before the base chain so the base-chain
 *      rule's NFT_JUMP/NFT_GOTO can bind successfully on first commit.
 *   7. NFT_MSG_NEWCHAIN creating a base chain "chain_in" with
 *      hook=NF_INET_LOCAL_IN, prio=0, type="filter".  This is the
 *      chain the loopback traffic in step 9 will traverse.
 *   8. NFT_MSG_NEWRULE on chain_in carrying one immediate-verdict
 *      expression: dreg=NFT_REG_VERDICT, code in {NFT_JUMP, NFT_GOTO}
 *      (rolled per call), chain="chain_aux".  A jumping verdict is
 *      what arms the nft_verdict UAF window the CVE-2024-1086 lineage
 *      lives in.
 *   9. socket(AF_INET, SOCK_DGRAM); sendto a small payload to
 *      127.0.0.1:NFT_INNER_PORT inside the netns.  Drives the input
 *      hook via nf_hook_slow on the receive side, walking the freshly
 *      installed chain_in -> chain_aux jump.  BUDGETED+JITTER around
 *      base 3 with a STORM_BUDGET_NS 200 ms wall-clock cap and a
 *      64-frame upper limit on the inner send loop.
 *  10. NFT_MSG_NEWRULE inserted at NFTA_RULE_POSITION = 1 (small
 *      handle guess) on chain_in, mid-traffic.  The position-based
 *      insert path is a different commit-time codepath from the
 *      append-only path in step 8 and historically has its own
 *      reference-count windows.
 *  11. NFT_MSG_DELRULE on chain_in with no NFTA_RULE_HANDLE — kernel
 *      treats this as "delete every rule in chain_in", racing any
 *      in-flight skb from step 9 still draining through softirq.
 *      This is the targeted commit-vs-traffic teardown window.
 *  12. NFT_MSG_DELSET on the anonymous set, then NFT_MSG_DELTABLE on
 *      the table.  DELTABLE cascades cleanup of any chain/rule/set
 *      survivors via nf_tables_table_destroy, racing the same
 *      in-flight skbs.
 *
 * CVE class: CVE-2024-1086 nft_verdict use-after-free (in-the-wild
 * LPE), CVE-2023-32233 anonymous set double-free, CVE-2024-26642
 * nft_setelem ref window, CVE-2024-26581 nft_set_rbtree race,
 * CVE-2023-3390 nft_chain reference window — the most CVE-productive
 * subsystem in the kernel for the last 24 months.  Subsystems reached:
 * net/netfilter/nf_tables_api.c, net/netfilter/nft_immediate.c,
 * net/netfilter/nft_set_*.c, net/netfilter/nf_tables_offload.c,
 * net/netfilter/core.c (nf_hook_slow).
 *
 * Self-bounding: one full create/destroy cycle per invocation, packet
 * burst count BUDGETED+JITTER around base 3 with a STORM_BUDGET_NS
 * 200 ms wall-clock cap and a 64-frame ceiling on the inner send
 * loop.  All netlink and socket I/O is MSG_DONTWAIT, SO_RCVTIMEO=1s
 * on the netfilter ack socket, so an unresponsive kernel can't wedge
 * us past the SIGALRM(1s) cap inherited from child.c.  Loopback only
 * (private netns).  Three latches so a kernel without
 * CONFIG_NF_NETLINK / CONFIG_NF_TABLES / CONFIG_INET pays the EFAIL
 * once and skips that path permanently.
 */

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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * UAPI fallbacks.  The header on stripped sysroots may not have
 * nf_tables.h / nfnetlink.h at all — we still want to compile on those
 * systems and let the latches catch the missing kernel support at
 * runtime.  IDs come from the in-tree UAPI and are stable.
 */
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
#endif
#ifndef NFNETLINK_V0
#define NFNETLINK_V0			0
#endif
#ifndef NFNL_MSG_BATCH_BEGIN
#define NFNL_MSG_BATCH_BEGIN		16
#endif
#ifndef NFNL_MSG_BATCH_END
#define NFNL_MSG_BATCH_END		17
#endif
#ifndef NFT_TABLE_F_DORMANT
#define NFT_TABLE_F_DORMANT		0x1
#endif

#ifndef NFPROTO_INET
#define NFPROTO_INET			1
#endif
#ifndef NFPROTO_IPV4
#define NFPROTO_IPV4			2
#endif
#ifndef NFPROTO_NETDEV
#define NFPROTO_NETDEV			5
#endif
#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif
#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6			10
#endif

#ifndef NF_INET_PRE_ROUTING
#define NF_INET_PRE_ROUTING		0
#endif
#ifndef NF_INET_LOCAL_IN
#define NF_INET_LOCAL_IN		1
#endif
#ifndef NF_INET_FORWARD
#define NF_INET_FORWARD			2
#endif
#ifndef NF_INET_LOCAL_OUT
#define NF_INET_LOCAL_OUT		3
#endif
#ifndef NF_INET_POST_ROUTING
#define NF_INET_POST_ROUTING		4
#endif

#ifndef NFTA_TARGET_NAME
#define NFTA_TARGET_NAME		1
#define NFTA_TARGET_REV			2
#define NFTA_TARGET_INFO		3
#endif

/* nf_tables msg types */
#ifndef NFT_MSG_NEWTABLE
#define NFT_MSG_NEWTABLE		0
#define NFT_MSG_DELTABLE		2
#define NFT_MSG_NEWCHAIN		3
#define NFT_MSG_NEWRULE			6
#define NFT_MSG_DELRULE			8
#define NFT_MSG_NEWSET			9
#define NFT_MSG_DELSET			11
#endif

/* nf_tables verdicts (stored as __be32 in NFTA_VERDICT_CODE) */
#ifndef NFT_JUMP
#define NFT_JUMP			(0xfffffffdU)
#define NFT_GOTO			(0xfffffffcU)
#endif
#ifndef NFT_CONTINUE
#define NFT_CONTINUE			(0xffffffffU)
#endif
#ifndef NFT_BREAK
#define NFT_BREAK			(0xfffffffeU)
#endif
#ifndef NFT_RETURN
#define NFT_RETURN			(0xfffffffbU)
#endif

/* netfilter base verdicts (used in NFTA_VERDICT_CODE for terminal verdicts) */
#ifndef NF_DROP
#define NF_DROP				0
#endif
#ifndef NF_ACCEPT
#define NF_ACCEPT			1
#endif

#ifndef NFT_REG_VERDICT
#define NFT_REG_VERDICT			0
#endif
#ifndef NFT_REG_1
#define NFT_REG_1			1
#define NFT_REG_2			2
#define NFT_REG_3			3
#define NFT_REG_4			4
#endif
#ifndef NFT_REG32_00
#define NFT_REG32_00			8
#endif

/* nft_payload base / NFTA_PAYLOAD_* attribute IDs.  The validator in
 * net/netfilter/nft_payload.c (nft_payload_init / nft_payload_set_init)
 * accepts BASE in {LL,NETWORK,TRANSPORT,INNER}_HEADER, OFFSET as a
 * bounded uint, and LEN <= NFT_REG_SIZE on the read path; values
 * outside those ranges yield -EINVAL before the per-expression parser
 * runs. */
#ifndef NFT_PAYLOAD_LL_HEADER
#define NFT_PAYLOAD_LL_HEADER		0
#define NFT_PAYLOAD_NETWORK_HEADER	1
#define NFT_PAYLOAD_TRANSPORT_HEADER	2
#define NFT_PAYLOAD_INNER_HEADER	3
#endif

#ifndef NFTA_PAYLOAD_DREG
#define NFTA_PAYLOAD_DREG		1
#define NFTA_PAYLOAD_BASE		2
#define NFTA_PAYLOAD_OFFSET		3
#define NFTA_PAYLOAD_LEN		4
#define NFTA_PAYLOAD_SREG		5
#define NFTA_PAYLOAD_CSUM_TYPE		6
#define NFTA_PAYLOAD_CSUM_OFFSET	7
#define NFTA_PAYLOAD_CSUM_FLAGS		8
#endif

/* nft_meta NFTA_META_* attribute IDs and NFT_META_* key IDs.  The
 * validator in net/netfilter/nft_meta.c (nft_meta_get_init /
 * nft_meta_set_init) drives off NFTA_META_KEY: a read-path expression
 * sets DREG and the per-key dispatch picks the load helper, a write-
 * path expression sets SREG and is rejected on read-only keys before
 * any register check runs. */
#ifndef NFTA_META_DREG
#define NFTA_META_DREG			1
#define NFTA_META_KEY			2
#define NFTA_META_SREG			3
#endif

/* Per-key fallbacks.  Each is its own #ifndef so we don't clobber
 * macros the kernel header already defines (NFT_META_IIFTYPE in
 * particular is a macro alias for the NFT_META_IFTYPE enumerator,
 * not a bare enumerator).  Values track the enum positions in
 * include/uapi/linux/netfilter/nf_tables.h. */
#ifndef NFT_META_LEN
#define NFT_META_LEN			0
#endif
#ifndef NFT_META_PROTOCOL
#define NFT_META_PROTOCOL		1
#endif
#ifndef NFT_META_PRIORITY
#define NFT_META_PRIORITY		2
#endif
#ifndef NFT_META_MARK
#define NFT_META_MARK			3
#endif
#ifndef NFT_META_IIF
#define NFT_META_IIF			4
#endif
#ifndef NFT_META_OIF
#define NFT_META_OIF			5
#endif
#ifndef NFT_META_IIFNAME
#define NFT_META_IIFNAME		6
#endif
#ifndef NFT_META_OIFNAME
#define NFT_META_OIFNAME		7
#endif
#ifndef NFT_META_IIFTYPE
#define NFT_META_IIFTYPE		8
#endif
#ifndef NFT_META_OIFTYPE
#define NFT_META_OIFTYPE		9
#endif
#ifndef NFT_META_SKUID
#define NFT_META_SKUID			10
#endif
#ifndef NFT_META_SKGID
#define NFT_META_SKGID			11
#endif
#ifndef NFT_META_NFTRACE
#define NFT_META_NFTRACE		12
#endif
#ifndef NFT_META_RTCLASSID
#define NFT_META_RTCLASSID		13
#endif
#ifndef NFT_META_SECMARK
#define NFT_META_SECMARK		14
#endif
#ifndef NFT_META_NFPROTO
#define NFT_META_NFPROTO		15
#endif
#ifndef NFT_META_L4PROTO
#define NFT_META_L4PROTO		16
#endif
#ifndef NFT_META_BRI_IIFNAME
#define NFT_META_BRI_IIFNAME		17
#endif
#ifndef NFT_META_BRI_OIFNAME
#define NFT_META_BRI_OIFNAME		18
#endif
#ifndef NFT_META_PKTTYPE
#define NFT_META_PKTTYPE		19
#endif
#ifndef NFT_META_CPU
#define NFT_META_CPU			20
#endif
#ifndef NFT_META_IIFGROUP
#define NFT_META_IIFGROUP		21
#endif
#ifndef NFT_META_OIFGROUP
#define NFT_META_OIFGROUP		22
#endif
#ifndef NFT_META_CGROUP
#define NFT_META_CGROUP			23
#endif
#ifndef NFT_META_PRANDOM
#define NFT_META_PRANDOM		24
#endif
#ifndef NFT_META_IIFKIND
#define NFT_META_IIFKIND		26
#endif
#ifndef NFT_META_OIFKIND
#define NFT_META_OIFKIND		27
#endif
#ifndef NFT_META_BRI_IIFPVID
#define NFT_META_BRI_IIFPVID		28
#endif
#ifndef NFT_META_BRI_IIFVPROTO
#define NFT_META_BRI_IIFVPROTO		29
#endif
#ifndef NFT_META_TIME_NS
#define NFT_META_TIME_NS		30
#endif
#ifndef NFT_META_TIME_DAY
#define NFT_META_TIME_DAY		31
#endif
#ifndef NFT_META_TIME_HOUR
#define NFT_META_TIME_HOUR		32
#endif
#ifndef NFT_META_SDIF
#define NFT_META_SDIF			33
#endif
#ifndef NFT_META_SDIFNAME
#define NFT_META_SDIFNAME		34
#endif

/* set flags */
#ifndef NFT_SET_ANONYMOUS
#define NFT_SET_ANONYMOUS		0x1
#endif
#ifndef NFT_SET_DYNAMIC
#define NFT_SET_DYNAMIC			0x10
#endif

/* nft data types: NFT_DATA_VALUE = 0; per-data-type IDs come from
 * include/net/netfilter/nf_tables.h NFT_DATATYPE_*.  ipv4_addr is
 * type id 7 in the kernel's nft_*data* registry; key_len is the
 * width in bytes (4). */
#ifndef NFT_DATATYPE_IPADDR
#define NFT_DATATYPE_IPADDR		7
#endif

/* Top-level NFTA_* attr IDs we emit.  Numbering matches kernel UAPI
 * (per-namespace; numbers reused across namespaces). */
#ifndef NFTA_TABLE_NAME
#define NFTA_TABLE_NAME			1
#define NFTA_TABLE_FLAGS		2
#endif

#ifndef NFTA_CHAIN_TABLE
#define NFTA_CHAIN_TABLE		1
#define NFTA_CHAIN_HANDLE		2
#define NFTA_CHAIN_NAME			3
#define NFTA_CHAIN_HOOK			4
#define NFTA_CHAIN_TYPE			7
#endif

#ifndef NFTA_HOOK_HOOKNUM
#define NFTA_HOOK_HOOKNUM		1
#define NFTA_HOOK_PRIORITY		2
#endif
#ifndef NFTA_HOOK_DEV
#define NFTA_HOOK_DEV			3
#endif

#ifndef NF_NETDEV_INGRESS
#define NF_NETDEV_INGRESS		0
#endif

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER			1
#endif

#ifndef NFTA_RULE_TABLE
#define NFTA_RULE_TABLE			1
#define NFTA_RULE_CHAIN			2
#define NFTA_RULE_HANDLE		3
#define NFTA_RULE_EXPRESSIONS		4
#define NFTA_RULE_POSITION		5
#endif

#ifndef NFTA_LIST_ELEM
#define NFTA_LIST_ELEM			1
#endif

#ifndef NFTA_EXPR_NAME
#define NFTA_EXPR_NAME			1
#define NFTA_EXPR_DATA			2
#endif

#ifndef NFTA_IMMEDIATE_DREG
#define NFTA_IMMEDIATE_DREG		1
#define NFTA_IMMEDIATE_DATA		2
#endif

#ifndef NFTA_DATA_VERDICT
#define NFTA_DATA_VERDICT		2
#endif

#ifndef NFTA_VERDICT_CODE
#define NFTA_VERDICT_CODE		1
#define NFTA_VERDICT_CHAIN		2
#endif

#ifndef NFTA_SET_TABLE
#define NFTA_SET_TABLE			1
#define NFTA_SET_NAME			2
#define NFTA_SET_FLAGS			3
#define NFTA_SET_KEY_TYPE		4
#define NFTA_SET_KEY_LEN		5
#define NFTA_SET_ID			10
#endif

/* nft_lookup NFTA_LOOKUP_* attribute IDs and lookup-flag bits.  The
 * validator in net/netfilter/nft_lookup.c (nft_lookup_init) requires
 * NFTA_LOOKUP_SET to name an existing set in the same transaction, with
 * NFTA_LOOKUP_SET_ID disambiguating anonymous-set names; NFTA_LOOKUP_SREG
 * is the register holding the key, NFTA_LOOKUP_DREG is only valid for
 * map-typed sets and yields -EOPNOTSUPP otherwise. */
#ifndef NFTA_LOOKUP_SET
#define NFTA_LOOKUP_SET			1
#define NFTA_LOOKUP_SREG		2
#define NFTA_LOOKUP_DREG		3
#define NFTA_LOOKUP_SET_ID		4
#define NFTA_LOOKUP_FLAGS		5
#endif

#ifndef NFT_LOOKUP_F_INV
#define NFT_LOOKUP_F_INV		(1 << 0)
#endif

/* nft_dynset NFTA_DYNSET_* attribute IDs.  The validator in
 * net/netfilter/nft_dynset.c (nft_dynset_init) requires NFTA_DYNSET_OP,
 * NFTA_DYNSET_SREG_KEY, and a set binding (SET_NAME + SET_ID for
 * anonymous sets resolved in the same transaction).  TIMEOUT is u64,
 * FLAGS is u32; the nested NFTA_DYNSET_EXPR / NFTA_DYNSET_EXPRESSIONS
 * containers are intentionally not emitted here — separate slice. */
#ifndef NFTA_DYNSET_SET_NAME
#define NFTA_DYNSET_SET_NAME		1
#define NFTA_DYNSET_SET_ID		2
#define NFTA_DYNSET_OP			3
#define NFTA_DYNSET_SREG_KEY		4
#define NFTA_DYNSET_SREG_DATA		5
#define NFTA_DYNSET_TIMEOUT		6
#define NFTA_DYNSET_FLAGS		9
#endif

#ifndef NFT_DYNSET_OP_ADD
#define NFT_DYNSET_OP_ADD		0
#define NFT_DYNSET_OP_UPDATE		1
#define NFT_DYNSET_OP_DELETE		2
#endif

#ifndef NFT_DYNSET_F_INV
#define NFT_DYNSET_F_INV		(1 << 0)
#endif

/* NFTA_LOG_* attribute identifiers (uapi/linux/netfilter/nf_tables.h).
 * Values match the kernel enum nft_log_attributes; guarded so the
 * build still works on older host headers that predate nft_log. */
#ifndef NFTA_LOG_PREFIX
#define NFTA_LOG_PREFIX			1
#define NFTA_LOG_GROUP			2
#define NFTA_LOG_SNAPLEN		3
#define NFTA_LOG_QTHRESHOLD		4
#define NFTA_LOG_LEVEL			5
#define NFTA_LOG_FLAGS			6
#endif

#ifndef NF_LOG_DEFAULT_MASK
#define NF_LOG_DEFAULT_MASK		0x0f
#endif

/* nft_bitwise NFTA_BITWISE_* attribute IDs and NFT_BITWISE_* op codes.
 * The validator in net/netfilter/nft_bitwise.c (nft_bitwise_init)
 * branches on NFTA_BITWISE_OP: NFT_BITWISE_BOOL takes MASK + XOR (each
 * a nested NFTA_DATA_VALUE of LEN bytes), NFT_BITWISE_LSHIFT /
 * NFT_BITWISE_RSHIFT take NFTA_BITWISE_DATA (a nested NFTA_DATA_VALUE
 * carrying a __be32 shift count).  Guarded so the build still works on
 * older host headers that predate nft_bitwise's UAPI exposure. */
#ifndef NFTA_BITWISE_SREG
#define NFTA_BITWISE_SREG		1
#define NFTA_BITWISE_DREG		2
#define NFTA_BITWISE_LEN		3
#define NFTA_BITWISE_MASK		4
#define NFTA_BITWISE_XOR		5
#define NFTA_BITWISE_OP			6
#define NFTA_BITWISE_DATA		7
#endif

#ifndef NFT_BITWISE_BOOL
#define NFT_BITWISE_BOOL		0
#define NFT_BITWISE_LSHIFT		1
#define NFT_BITWISE_RSHIFT		2
#endif

#ifndef NFTA_DATA_VALUE
#define NFTA_DATA_VALUE			1
#endif

/* nft_cmp NFTA_CMP_* attribute IDs and NFT_CMP_* op codes.  The
 * validator in net/netfilter/nft_cmp.c (nft_cmp_init) demands SREG +
 * OP + DATA; DATA is a nested NFTA_DATA_VALUE carrying the comparison
 * bytes.  Guarded so the build still works on older host headers that
 * predate nft_cmp's UAPI exposure. */
#ifndef NFTA_CMP_SREG
#define NFTA_CMP_SREG			1
#define NFTA_CMP_OP			2
#define NFTA_CMP_DATA			3
#endif

#ifndef NFT_CMP_EQ
#define NFT_CMP_EQ			0
#define NFT_CMP_NEQ			1
#define NFT_CMP_LT			2
#define NFT_CMP_LTE			3
#define NFT_CMP_GT			4
#define NFT_CMP_GTE			5
#endif

/* nft_range NFTA_RANGE_* attribute IDs and NFT_RANGE_* op codes.  The
 * validator in net/netfilter/nft_range.c (nft_range_init) demands SREG
 * + OP + FROM_DATA + TO_DATA; FROM_DATA and TO_DATA are each a nested
 * NFTA_DATA_VALUE carrying the bound bytes.  The kernel rejects
 * reversed bounds (memcmp(from, to) > 0) before any register check
 * runs.  Guarded so the build still works on older host headers that
 * predate nft_range's UAPI exposure. */
#ifndef NFTA_RANGE_OP
#define NFTA_RANGE_OP			1
#define NFTA_RANGE_SREG			2
#define NFTA_RANGE_FROM_DATA		3
#define NFTA_RANGE_TO_DATA		4
#endif

#ifndef NFT_RANGE_EQ
#define NFT_RANGE_EQ			0
#define NFT_RANGE_NEQ			1
#endif

/* nft_byteorder NFTA_BYTEORDER_* attribute IDs and NFT_BYTEORDER_* op
 * codes.  The validator in net/netfilter/nft_byteorder.c
 * (nft_byteorder_init) demands SREG + DREG + OP + LEN + SIZE — every
 * slot in nft_byteorder_policy[] is mandatory (no NLA_F_OPTIONAL on
 * any).  SIZE must be one of {2, 4, 8} and LEN must be a non-zero
 * multiple of SIZE; LEN is further capped at FIELD_SIZEOF(struct
 * nft_data, data) which is 16 bytes.  Guarded per-symbol so the build
 * still works on older host headers that predate any of these. */
#ifndef NFTA_BYTEORDER_SREG
#define NFTA_BYTEORDER_SREG		1
#endif
#ifndef NFTA_BYTEORDER_DREG
#define NFTA_BYTEORDER_DREG		2
#endif
#ifndef NFTA_BYTEORDER_OP
#define NFTA_BYTEORDER_OP		3
#endif
#ifndef NFTA_BYTEORDER_LEN
#define NFTA_BYTEORDER_LEN		4
#endif
#ifndef NFTA_BYTEORDER_SIZE
#define NFTA_BYTEORDER_SIZE		5
#endif

#ifndef NFT_BYTEORDER_NTOH
#define NFT_BYTEORDER_NTOH		0
#endif
#ifndef NFT_BYTEORDER_HTON
#define NFT_BYTEORDER_HTON		1
#endif

/* nft_socket NFTA_SOCKET_* attribute IDs and NFT_SOCKET_* key IDs.
 * The validator in net/netfilter/nft_socket.c (nft_socket_init) requires
 * NFTA_SOCKET_KEY and NFTA_SOCKET_DREG, accepts KEY in
 * {TRANSPARENT, MARK, WILDCARD, CGROUPV2}, and demands NFTA_SOCKET_LEVEL
 * iff KEY == NFT_SOCKET_CGROUPV2 (rejected for any other KEY).  LEVEL is
 * a u32 cgroup hierarchy depth bounded by the kernel at 0..255.  The
 * NFT_SOCKET_CGROUPV2 / NFTA_SOCKET_LEVEL pair post-dates 5.4 LTS, so
 * each symbol is guarded individually so the build still works on older
 * host headers that predate any subset of these. */
#ifndef NFTA_SOCKET_KEY
#define NFTA_SOCKET_KEY			1
#endif
#ifndef NFTA_SOCKET_DREG
#define NFTA_SOCKET_DREG		2
#endif
#ifndef NFTA_SOCKET_LEVEL
#define NFTA_SOCKET_LEVEL		3
#endif

#ifndef NFT_SOCKET_TRANSPARENT
#define NFT_SOCKET_TRANSPARENT		0
#endif
#ifndef NFT_SOCKET_MARK
#define NFT_SOCKET_MARK			1
#endif
#ifndef NFT_SOCKET_WILDCARD
#define NFT_SOCKET_WILDCARD		2
#endif
#ifndef NFT_SOCKET_CGROUPV2
#define NFT_SOCKET_CGROUPV2		3
#endif

/* nft_quota NFTA_QUOTA_* attribute IDs and the NFT_QUOTA_F_INV flag.
 * The validator in net/netfilter/nft_quota.c (nft_quota_init) reads the
 * nft_quota_policy[] table — NFTA_QUOTA_BYTES (u64) is mandatory and
 * carries the cap, NFTA_QUOTA_FLAGS (u32) is optional and the only bit
 * the kernel accepts is NFT_QUOTA_F_INV (any other bit is rejected with
 * -EOPNOTSUPP), and NFTA_QUOTA_CONSUMED (u64) is optional and pre-seeds
 * the per-rule counter.  BYTES == 0 is permitted by the parser; the
 * eval-time comparator (consumed vs bytes, optionally inverted) is what
 * decides the verdict.  Each symbol is guarded individually so the
 * build still works on older host headers that predate any subset. */
#ifndef NFTA_QUOTA_BYTES
#define NFTA_QUOTA_BYTES		1
#endif
#ifndef NFTA_QUOTA_FLAGS
#define NFTA_QUOTA_FLAGS		2
#endif
#ifndef NFTA_QUOTA_CONSUMED
#define NFTA_QUOTA_CONSUMED		3
#endif

#ifndef NFT_QUOTA_F_INV
#define NFT_QUOTA_F_INV			(1 << 0)
#endif

/* nft_objref NFTA_OBJREF_* attribute IDs and the NFT_OBJECT_* type
 * constants the IMM-mode validator dispatches on.  The validator in
 * net/netfilter/nft_objref.c selects between two ops via
 * nft_objref_select_ops(): IMM mode requires NFTA_OBJREF_IMM_NAME
 * (NLA_STRING, NFT_OBJ_MAXNAMELEN-1 bounded) plus NFTA_OBJREF_IMM_TYPE
 * (NLA_U32, must match a registered NFT_OBJECT_* family); SET mode
 * requires NFTA_OBJREF_SET_SREG plus one of NFTA_OBJREF_SET_NAME or
 * NFTA_OBJREF_SET_ID.  Each symbol is guarded individually so the build
 * still works on older host headers that predate any subset. */
#ifndef NFTA_OBJREF_IMM_TYPE
#define NFTA_OBJREF_IMM_TYPE		1
#endif
#ifndef NFTA_OBJREF_IMM_NAME
#define NFTA_OBJREF_IMM_NAME		2
#endif
#ifndef NFTA_OBJREF_SET_SREG
#define NFTA_OBJREF_SET_SREG		3
#endif
#ifndef NFTA_OBJREF_SET_NAME
#define NFTA_OBJREF_SET_NAME		4
#endif
#ifndef NFTA_OBJREF_SET_ID
#define NFTA_OBJREF_SET_ID		5
#endif

#ifndef NFT_OBJECT_COUNTER
#define NFT_OBJECT_COUNTER		1
#endif
#ifndef NFT_OBJECT_QUOTA
#define NFT_OBJECT_QUOTA		2
#endif
#ifndef NFT_OBJECT_CT_HELPER
#define NFT_OBJECT_CT_HELPER		3
#endif
#ifndef NFT_OBJECT_LIMIT
#define NFT_OBJECT_LIMIT		4
#endif
#ifndef NFT_OBJECT_CONNLIMIT
#define NFT_OBJECT_CONNLIMIT		5
#endif
#ifndef NFT_OBJECT_TUNNEL
#define NFT_OBJECT_TUNNEL		6
#endif
#ifndef NFT_OBJECT_CT_TIMEOUT
#define NFT_OBJECT_CT_TIMEOUT		7
#endif
#ifndef NFT_OBJECT_SECMARK
#define NFT_OBJECT_SECMARK		8
#endif
#ifndef NFT_OBJECT_CT_EXPECT
#define NFT_OBJECT_CT_EXPECT		9
#endif
#ifndef NFT_OBJECT_SYNPROXY
#define NFT_OBJECT_SYNPROXY		10
#endif

/* nft_limit NFTA_LIMIT_* attribute IDs plus the NFT_LIMIT_PKTS /
 * NFT_LIMIT_PKT_BYTES type selectors and the NFT_LIMIT_F_INV flag.  The
 * validator in net/netfilter/nft_limit.c (nft_limit_init) reads the
 * nft_limit_policy[] table — NFTA_LIMIT_RATE (u64) and NFTA_LIMIT_UNIT
 * (u64) are both mandatory (the per-period token count and the period
 * length in seconds), NFTA_LIMIT_BURST (u32) is optional and widens the
 * tolerance window, NFTA_LIMIT_TYPE (u32) is optional and dispatches
 * between the packet-count limiter (NFT_LIMIT_PKTS == 0, default) and
 * the byte-count limiter (NFT_LIMIT_PKT_BYTES == 1) — any other TYPE
 * value is rejected with -EOPNOTSUPP — and NFTA_LIMIT_FLAGS (u32) is
 * optional and the only bit the kernel accepts is NFT_LIMIT_F_INV (any
 * other bit is rejected with -EOPNOTSUPP).  RATE == 0 is rejected
 * outright; the parser then computes nfs = unit * NSEC_PER_SEC before
 * dispatching to nft_limit_pkts_init or nft_limit_bytes_init for
 * token-bucket arithmetic.  Each symbol is guarded individually so the
 * build still works on older host headers that predate any subset. */
#ifndef NFTA_LIMIT_RATE
#define NFTA_LIMIT_RATE			1
#endif
#ifndef NFTA_LIMIT_UNIT
#define NFTA_LIMIT_UNIT			2
#endif
#ifndef NFTA_LIMIT_BURST
#define NFTA_LIMIT_BURST		3
#endif
#ifndef NFTA_LIMIT_TYPE
#define NFTA_LIMIT_TYPE			4
#endif
#ifndef NFTA_LIMIT_FLAGS
#define NFTA_LIMIT_FLAGS		5
#endif

#ifndef NFT_LIMIT_PKTS
#define NFT_LIMIT_PKTS			0
#endif
#ifndef NFT_LIMIT_PKT_BYTES
#define NFT_LIMIT_PKT_BYTES		1
#endif

#ifndef NFT_LIMIT_F_INV
#define NFT_LIMIT_F_INV			(1 << 0)
#endif

/* nft_numgen NFTA_NG_* attribute IDs and the NFT_NG_INCREMENTAL /
 * NFT_NG_RANDOM type selectors.  The validator in
 * net/netfilter/nft_numgen.c dispatches on NFTA_NG_TYPE: the parser
 * reads nft_ng_policy[] (DREG/MODULUS/TYPE/OFFSET, all u32), then
 * NFT_NG_INCREMENTAL routes to nft_ng_inc_init (atomic counter mod
 * modulus) and NFT_NG_RANDOM to nft_ng_random_init (PRNG mod modulus).
 * Both init helpers reject MODULUS == 0 with -ERANGE; any TYPE outside
 * {INCREMENTAL, RANDOM} is rejected with -EOPNOTSUPP before the
 * type-specific init runs.  OFFSET is added to the result at eval time
 * and is optional.  Each symbol is guarded individually so the build
 * still works on older host headers that predate any subset. */
#ifndef NFTA_NG_DREG
#define NFTA_NG_DREG			1
#endif
#ifndef NFTA_NG_MODULUS
#define NFTA_NG_MODULUS			2
#endif
#ifndef NFTA_NG_TYPE
#define NFTA_NG_TYPE			3
#endif
#ifndef NFTA_NG_OFFSET
#define NFTA_NG_OFFSET			4
#endif

#ifndef NFT_NG_INCREMENTAL
#define NFT_NG_INCREMENTAL		0
#endif
#ifndef NFT_NG_RANDOM
#define NFT_NG_RANDOM			1
#endif

/* nft_hash NFTA_HASH_* attribute IDs and the NFT_HASH_JENKINS /
 * NFT_HASH_SYM type selectors.  The validator in
 * net/netfilter/nft_hash.c dispatches on NFTA_HASH_TYPE: NFT_HASH_JENKINS
 * (default if absent) routes to nft_jhash_init, which requires
 * NFTA_HASH_SREG + NFTA_HASH_LEN + NFTA_HASH_DREG + NFTA_HASH_MODULUS
 * and accepts optional NFTA_HASH_SEED (a u32 jhash seed; if absent the
 * kernel synthesises one via prandom at init time) plus optional
 * NFTA_HASH_OFFSET; NFT_HASH_SYM routes to nft_symhash_init, which uses
 * skb->hash as the input and therefore requires only NFTA_HASH_DREG +
 * NFTA_HASH_MODULUS plus optional NFTA_HASH_OFFSET — SREG, LEN and SEED
 * are all rejected with -EINVAL on the symhash path.  Both inits reject
 * MODULUS == 0 with -ERANGE; any TYPE outside {JENKINS, SYM} is rejected
 * with -EOPNOTSUPP before the type-specific init runs.  LEN on the
 * jhash path must satisfy 1..NFT_REG_SIZE*4 == 1..64.  Each symbol is
 * guarded individually so the build still works on older host headers
 * that predate any subset. */
#ifndef NFTA_HASH_SREG
#define NFTA_HASH_SREG			1
#endif
#ifndef NFTA_HASH_DREG
#define NFTA_HASH_DREG			2
#endif
#ifndef NFTA_HASH_LEN
#define NFTA_HASH_LEN			3
#endif
#ifndef NFTA_HASH_MODULUS
#define NFTA_HASH_MODULUS		4
#endif
#ifndef NFTA_HASH_SEED
#define NFTA_HASH_SEED			5
#endif
#ifndef NFTA_HASH_OFFSET
#define NFTA_HASH_OFFSET		6
#endif
#ifndef NFTA_HASH_TYPE
#define NFTA_HASH_TYPE			7
#endif

#ifndef NFT_HASH_JENKINS
#define NFT_HASH_JENKINS		0
#endif
#ifndef NFT_HASH_SYM
#define NFT_HASH_SYM			1
#endif

/* nft_synproxy NFTA_SYNPROXY_* attribute IDs and NF_SYNPROXY_OPT_* option
 * bits.  The validator in net/netfilter/nft_synproxy.c
 * (nft_synproxy_do_init) drives off nft_synproxy_policy[]: each of MSS,
 * WSCALE and FLAGS is individually OPTIONAL (gated by `if (tb[...])` in
 * the init body), but emitting zero of them leaves the priv struct at
 * default-zero which is uninteresting, so the emitter forces MSS present
 * if the per-attr coin-flips would otherwise produce the empty payload.
 * WSCALE is bounded by NLA_POLICY_MAX(NLA_U8, TCP_MAX_WSCALE) where
 * TCP_MAX_WSCALE == 14 in include/net/tcp.h — values > 14 are rejected
 * with -EINVAL by the policy walker before the init body sees them.
 * FLAGS is bounded by NLA_POLICY_MASK(NLA_BE32, NF_SYNPROXY_OPT_MASK)
 * where the mask is MSS | WSCALE | SACK_PERM | TIMESTAMP == 0x0F;
 * NF_SYNPROXY_OPT_ECN (0x10) is DELIBERATELY excluded from the mask and
 * rejected by the policy walker.  MSS is NLA_U16 read on-wire as
 * big-endian via ntohs(nla_get_be16()) in the kernel and has no
 * additional validator beyond the type.  Chain-context (LOCAL_IN /
 * FORWARD priority on a base chain) is enforced by nft_synproxy_validate
 * at validate-hook time, not by do_init — so this payload exercises the
 * policy walker and do_init reliably regardless of which chain the rule
 * lands on.  Each symbol is guarded individually so the build still
 * works on older host headers that predate any subset. */
#ifndef NFTA_SYNPROXY_MSS
#define NFTA_SYNPROXY_MSS		1
#endif
#ifndef NFTA_SYNPROXY_WSCALE
#define NFTA_SYNPROXY_WSCALE		2
#endif
#ifndef NFTA_SYNPROXY_FLAGS
#define NFTA_SYNPROXY_FLAGS		3
#endif

#ifndef NF_SYNPROXY_OPT_MSS
#define NF_SYNPROXY_OPT_MSS		0x01
#endif
#ifndef NF_SYNPROXY_OPT_WSCALE
#define NF_SYNPROXY_OPT_WSCALE		0x02
#endif
#ifndef NF_SYNPROXY_OPT_SACK_PERM
#define NF_SYNPROXY_OPT_SACK_PERM	0x04
#endif
#ifndef NF_SYNPROXY_OPT_TIMESTAMP
#define NF_SYNPROXY_OPT_TIMESTAMP	0x08
#endif

#ifndef TCP_MAX_WSCALE
#define TCP_MAX_WSCALE			14
#endif

/* nft_counter NFTA_COUNTER_* attribute IDs.  The validator in
 * net/netfilter/nft_counter.c (nft_counter_init) drives off
 * nft_counter_policy[]: NFTA_COUNTER_BYTES (NLA_U64) and
 * NFTA_COUNTER_PACKETS (NLA_U64) are BOTH individually OPTIONAL — the
 * init body gates each one with `if (tb[...])` and reads the wire value
 * via be64_to_cpu(nla_get_be64()), seeding the per-cpu counter's byte
 * and packet starting values respectively.  The policy has no bounds
 * (any u64 is accepted), no flag mask, and no chain-context restriction
 * (nft_counter has no validate hook beyond standard expression
 * validation).  Emitting zero attrs leaves the per-cpu counter at
 * default-zero which does still drive a code path, but the more
 * interesting init path runs `nft_be64_set` for at-least-one attr — so
 * the emitter forces PACKETS present if the per-attr coin-flips would
 * otherwise produce the empty payload.  Each symbol is guarded
 * individually so the build still works on older host headers that
 * predate any subset. */
#ifndef NFTA_COUNTER_BYTES
#define NFTA_COUNTER_BYTES		1
#endif
#ifndef NFTA_COUNTER_PACKETS
#define NFTA_COUNTER_PACKETS		2
#endif

/* nft_connlimit NFTA_CONNLIMIT_* attribute IDs and NFT_CONNLIMIT_F_INV
 * flag bit.  The validator in net/netfilter/nft_connlimit.c
 * (nft_connlimit_do_init) drives off nft_connlimit_policy[]:
 * NFTA_CONNLIMIT_COUNT (NLA_U32, big-endian on wire — read via
 * ntohl(nla_get_be32())) is REQUIRED (the init body returns -EINVAL when
 * tb[NFTA_CONNLIMIT_COUNT] is NULL) and seeds the per-rule connection
 * cap that nft_connlimit_do_eval compares the live conncount against.
 * NFTA_CONNLIMIT_FLAGS (NLA_U32, big-endian) is OPTIONAL and the only
 * legal bit is NFT_CONNLIMIT_F_INV (0x01); any other bit fails the
 * `flags & ~NFT_CONNLIMIT_F_INV` check with -EOPNOTSUPP before the
 * priv struct is initialised.  When set, NFT_CONNLIMIT_F_INV flips the
 * eval comparator's verdict via XOR so over-cap becomes the matching
 * side instead of the rejecting side.  Each symbol is guarded
 * individually so the build still works on older host headers that
 * predate any subset.  Depends on CONFIG_NF_CONNTRACK + CONFIG_NF_CONNCOUNT
 * (auto-pulled by CONFIG_NFT_CONNLIMIT=m); fuzz-box config has it. */
#ifndef NFTA_CONNLIMIT_COUNT
#define NFTA_CONNLIMIT_COUNT		1
#endif
#ifndef NFTA_CONNLIMIT_FLAGS
#define NFTA_CONNLIMIT_FLAGS		2
#endif
#ifndef NFT_CONNLIMIT_F_INV
#define NFT_CONNLIMIT_F_INV		(1 << 0)
#endif

/* nft_masq NFTA_MASQ_* attribute IDs and NF_NAT_RANGE_* flag bits.  The
 * validator in net/netfilter/nft_masq.c (nft_masq_init, shared by the
 * nft_masq_ipv4 / nft_masq_ipv6 / nft_masq_inet modules via the same
 * nft_masq_policy[]) accepts three OPTIONAL attributes:
 * NFTA_MASQ_FLAGS (NLA_U32, big-endian on wire — read via
 * ntohl(nla_get_be32())) carries a subset of nf_nat_range flags; the
 * legal bits are NF_NAT_RANGE_PROTO_RANDOM (0x4),
 * NF_NAT_RANGE_PERSISTENT (0x8) and NF_NAT_RANGE_PROTO_RANDOM_FULLY
 * (0x10), forming NF_NAT_RANGE_MASK = 0x1c.  Any out-of-mask bit is
 * rejected with -EINVAL before priv setup.  NFTA_MASQ_REG_PROTO_MIN and
 * NFTA_MASQ_REG_PROTO_MAX (NLA_U32, big-endian) hold register
 * references (NFT_REG_*) bracketing the source-port rewrite range; if
 * MIN is present and MAX is absent the kernel defaults MAX to MIN, but
 * MAX present without MIN is rejected with -EINVAL, so the emitter
 * gates MAX on MIN.  All three attributes absent leaves the expression
 * at zero flags / no port range, which is a legal but uninteresting
 * pass-through.  Each symbol is guarded individually so the build still
 * works on older host headers that predate any subset.  Depends on
 * CONFIG_NF_NAT (auto-pulled by CONFIG_NFT_MASQ=m); fuzz-box config has
 * it. */
#ifndef NFTA_MASQ_FLAGS
#define NFTA_MASQ_FLAGS			1
#endif
#ifndef NFTA_MASQ_REG_PROTO_MIN
#define NFTA_MASQ_REG_PROTO_MIN		2
#endif
#ifndef NFTA_MASQ_REG_PROTO_MAX
#define NFTA_MASQ_REG_PROTO_MAX		3
#endif
#ifndef NF_NAT_RANGE_PROTO_RANDOM
#define NF_NAT_RANGE_PROTO_RANDOM	0x4
#endif
#ifndef NF_NAT_RANGE_PERSISTENT
#define NF_NAT_RANGE_PERSISTENT		0x8
#endif
#ifndef NF_NAT_RANGE_PROTO_RANDOM_FULLY
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY	0x10
#endif

/* nft_redir NFTA_REDIR_* attribute IDs.  The validator in
 * net/netfilter/nft_redir.c (nft_redir_init, shared by the
 * nft_redir_ipv4 / nft_redir_ipv6 / nft_redir_inet modules via the same
 * nft_redir_policy[]) accepts three OPTIONAL attributes:
 * NFTA_REDIR_REG_PROTO_MIN and NFTA_REDIR_REG_PROTO_MAX (NLA_U32,
 * big-endian on wire) hold register references (NFT_REG_*) bracketing
 * the destination-port rewrite range loaded at eval time; if MIN is
 * present and MAX is absent the kernel defaults MAX to MIN, but MAX
 * present without MIN is rejected with -EINVAL, so the emitter gates
 * MAX on MIN.  NFTA_REDIR_FLAGS (NLA_U32, big-endian on wire — read via
 * ntohl(nla_get_be32())) carries a subset of nf_nat_range flags drawn
 * from the same NF_NAT_RANGE_MASK == 0x1c surface as nft_masq
 * (NF_NAT_RANGE_PROTO_RANDOM 0x4, NF_NAT_RANGE_PERSISTENT 0x8,
 * NF_NAT_RANGE_PROTO_RANDOM_FULLY 0x10); any out-of-mask bit fails the
 * `flags & ~NF_NAT_RANGE_MASK` check with -EINVAL before the priv
 * struct is initialised.  All three attributes absent leaves the
 * expression at zero flags / no port range, which is a legal but
 * uninteresting pass-through.  The NF_NAT_RANGE_* constants are
 * already shimmed by the nft_masq block above and are not re-shimmed
 * here.  Each NFTA_REDIR_* symbol is guarded individually so the build
 * still works on older host headers that predate any subset.  Depends
 * on CONFIG_NF_NAT (auto-pulled by CONFIG_NFT_REDIR=m); fuzz-box
 * config has it. */
#ifndef NFTA_REDIR_REG_PROTO_MIN
#define NFTA_REDIR_REG_PROTO_MIN	1
#endif
#ifndef NFTA_REDIR_REG_PROTO_MAX
#define NFTA_REDIR_REG_PROTO_MAX	2
#endif
#ifndef NFTA_REDIR_FLAGS
#define NFTA_REDIR_FLAGS		3
#endif

/* nft_tproxy NFTA_TPROXY_* attribute IDs.  The validator in
 * net/netfilter/nft_tproxy.c (nft_tproxy_init) walks
 * nft_tproxy_policy[] and accepts three attributes:
 * NFTA_TPROXY_FAMILY (NLA_U32, big-endian on wire — read via
 * ntohl(nla_get_be32())) carries the address family of the proxied
 * destination and is required-ish; only NFPROTO_IPV4 (2) and
 * NFPROTO_IPV6 (10) are accepted, any other value is rejected with
 * -EINVAL before the priv struct is initialised.  NFTA_TPROXY_REG_ADDR
 * and NFTA_TPROXY_REG_PORT (NLA_U32, big-endian) hold register
 * references (NFT_REG_*) bracketing the rewritten dst-addr / dst-port
 * loaded at eval time; out-of-range register values are rejected with
 * -ERANGE through nft_parse_register_load.  The kernel allows REG_ADDR
 * and REG_PORT independently when the family-resolution path is OK, so
 * the emitter does not gate one on the other.  Each NFTA_TPROXY_*
 * symbol is guarded individually so the build still works on older
 * host headers that predate any subset.  NFPROTO_IPV4 / NFPROTO_IPV6
 * are stable and need no shim.  Depends on CONFIG_NFT_TPROXY=m, which
 * the fuzz-box config has. */
#ifndef NFTA_TPROXY_FAMILY
#define NFTA_TPROXY_FAMILY		1
#endif
#ifndef NFTA_TPROXY_REG_ADDR
#define NFTA_TPROXY_REG_ADDR		2
#endif
#ifndef NFTA_TPROXY_REG_PORT
#define NFTA_TPROXY_REG_PORT		3
#endif

/* nft_xfrm NFTA_XFRM_* attribute IDs and NFT_XFRM_KEY_* enum values.
 * The validator in net/netfilter/nft_xfrm.c (nft_xfrm_get_init) walks
 * nft_xfrm_policy[] and accepts four attributes:
 *   - NFTA_XFRM_DREG (NLA_U32) — REQUIRED — destination register
 *     (NFT_REG_1..NFT_REG_4 / NFT_REG32_*) resolved through
 *     nft_parse_register_load; out-of-range register values are
 *     rejected with -ERANGE.
 *   - NFTA_XFRM_KEY (NLA_POLICY_MAX(NLA_BE32, 255)) — REQUIRED — one
 *     of NFT_XFRM_KEY_DADDR_IP4 (1), NFT_XFRM_KEY_DADDR_IP6 (2),
 *     NFT_XFRM_KEY_SADDR_IP4 (3), NFT_XFRM_KEY_SADDR_IP6 (4),
 *     NFT_XFRM_KEY_REQID (5), NFT_XFRM_KEY_SPI (6).
 *     NFT_XFRM_KEY_UNSPEC (0) and any value above the enum max are
 *     rejected with -EINVAL by the init switch.
 *   - NFTA_XFRM_DIR (NLA_U8) — REQUIRED — must be XFRM_POLICY_IN (0)
 *     or XFRM_POLICY_OUT (1); other values are rejected with -EINVAL.
 *   - NFTA_XFRM_SPNUM (NLA_POLICY_MAX(NLA_BE32, 255)) — OPTIONAL —
 *     secpath array index, kernel ntohl()s the wire value.
 * ctx->family must be NFPROTO_IPV4 / NFPROTO_IPV6 / NFPROTO_INET; any
 * other family is rejected with -EOPNOTSUPP before the policy walker
 * runs.  Each NFTA_XFRM_* and NFT_XFRM_KEY_* symbol is guarded
 * individually so the build still works on stale host headers that
 * predate any subset.  XFRM_POLICY_IN / XFRM_POLICY_OUT (0/1) are
 * stable in <linux/xfrm.h> and need no shim.  Depends on
 * CONFIG_NFT_XFRM=m, which the fuzz-box config has. */
#ifndef NFTA_XFRM_DREG
#define NFTA_XFRM_DREG			1
#endif
#ifndef NFTA_XFRM_KEY
#define NFTA_XFRM_KEY			2
#endif
#ifndef NFTA_XFRM_DIR
#define NFTA_XFRM_DIR			3
#endif
#ifndef NFTA_XFRM_SPNUM
#define NFTA_XFRM_SPNUM			4
#endif
#ifndef NFT_XFRM_KEY_DADDR_IP4
#define NFT_XFRM_KEY_DADDR_IP4		1
#endif
#ifndef NFT_XFRM_KEY_DADDR_IP6
#define NFT_XFRM_KEY_DADDR_IP6		2
#endif
#ifndef NFT_XFRM_KEY_SADDR_IP4
#define NFT_XFRM_KEY_SADDR_IP4		3
#endif
#ifndef NFT_XFRM_KEY_SADDR_IP6
#define NFT_XFRM_KEY_SADDR_IP6		4
#endif
#ifndef NFT_XFRM_KEY_REQID
#define NFT_XFRM_KEY_REQID		5
#endif
#ifndef NFT_XFRM_KEY_SPI
#define NFT_XFRM_KEY_SPI		6
#endif

/* nft_dup_netdev NFTA_DUP_SREG_DEV attribute ID.  The validator in
 * net/netfilter/nft_dup_netdev.c (nft_dup_netdev_init) walks
 * nft_dup_netdev_policy[] and consumes a single REQUIRED attribute:
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — REQUIRED — source register of the
 *     output netdev ifindex (NFT_REG_1..NFT_REG_4 / NFT_REG32_*),
 *     resolved through nft_parse_register_load with NFT_DATA_VALUE
 *     size sizeof(int).  NULL returns -EINVAL; out-of-range register
 *     values are rejected with -ERANGE.
 * The expression is registered for NFPROTO_NETDEV table family only,
 * so emissions on ipv4/ipv6/inet/arp/bridge tables get rejected at
 * expression-type lookup before init runs — that exercises the
 * lookup-side rejection path on top of the netdev-family success
 * path.  The neighbouring NFTA_DUP_SREG_ADDR attribute in the same
 * enum is consumed by the ip/ip6 family ip{6}_dup_pktinfo expression
 * in nft_dup_ipv4.c / nft_dup_ipv6.c and is not part of this
 * netdev-family slice.  The symbol is guarded individually so the
 * build still works on stale host headers that predate it.
 * NFPROTO_NETDEV is stable in <linux/netfilter.h>.  Depends on
 * CONFIG_NFT_DUP_NETDEV=m, which the fuzz-box config has. */
#ifndef NFTA_DUP_SREG_DEV
#define NFTA_DUP_SREG_DEV		2
#endif

/* nft_dup_ipv4 NFTA_DUP_SREG_ADDR attribute ID.  Sibling of the
 * NFTA_DUP_SREG_DEV slot in the same uapi enum (NFTA_DUP_UNSPEC=0,
 * NFTA_DUP_SREG_ADDR=1, NFTA_DUP_SREG_DEV=2).  Consumed by the
 * validator in net/ipv4/netfilter/nft_dup_ipv4.c (nft_dup_ipv4_init),
 * which walks nft_dup_ipv4_policy[]:
 *   - NFTA_DUP_SREG_ADDR (NLA_U32) — REQUIRED — source register
 *     loading a __be32 IPv4 gateway address (sizeof(struct in_addr)),
 *     resolved via nft_parse_register_load.  Missing returns -EINVAL;
 *     out-of-range register values are rejected with -ERANGE.
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — OPTIONAL — source register
 *     loading the int oif.  Absent leaves oif == -1 in the kernel
 *     branch.
 * The expression is registered for NFPROTO_IPV4 table family only,
 * sharing the "dup" expression name with the NFPROTO_NETDEV variant
 * in net/netfilter/nft_dup_netdev.c — the expression-type lookup
 * disambiguates by ctx->family.  Emissions on non-IPv4 chains get
 * rejected at lookup before init runs, exercising the -ENOPROTOOPT
 * leg on top of the IPv4-family success path.  The symbol is guarded
 * individually so the build still works on stale host headers that
 * predate it.  Depends on CONFIG_NFT_DUP_IPV4=m, which the fuzz-box
 * config has. */
#ifndef NFTA_DUP_SREG_ADDR
#define NFTA_DUP_SREG_ADDR		1
#endif

/* nft_fwd_netdev NFTA_FWD_* attribute IDs.  The validator in
 * net/netfilter/nft_fwd_netdev.c walks two policies that share the
 * NFTA_FWD_* uapi enum (NFTA_FWD_UNSPEC=0, NFTA_FWD_SREG_DEV=1,
 * NFTA_FWD_SREG_ADDR=2, NFTA_FWD_NFPROTO=3) — the enum is distinct
 * from the NFTA_DUP_* set used by nft_dup_netdev / nft_dup_ipv4 /
 * nft_dup_ipv6, despite the naming overlap.  Two init paths consume
 * these:
 *   - nft_fwd_netdev_init (bare-forward arm) consumes only
 *     NFTA_FWD_SREG_DEV (NLA_U32) — REQUIRED — source register loading
 *     the int oif, resolved through nft_parse_register_load with
 *     NFT_DATA_VALUE size sizeof(int).  Missing returns -EINVAL.
 *   - nft_fwd_neigh_init (forward-with-neigh-resolve arm) consumes
 *     NFTA_FWD_SREG_DEV and additionally NFTA_FWD_SREG_ADDR
 *     (NLA_U32) — source register loading either struct in_addr
 *     (4 bytes) or struct in6_addr (16 bytes), and NFTA_FWD_NFPROTO
 *     (NLA_U32) — REQUIRED for this arm — carrying NFPROTO_IPV4 or
 *     NFPROTO_IPV6 to pick the address load size.  The kernel
 *     branches on NFTA_FWD_SREG_ADDR presence to switch between the
 *     two init paths.
 * The expression is registered for NFPROTO_NETDEV table family only;
 * emissions on any other table family are rejected at expression-type
 * lookup with -ENOPROTOOPT before init runs, which exercises the
 * family-mismatch leg on top of the netdev-family success path.  The
 * expression name is "fwd" and is NOT shared with the nft_dup_*
 * family (those use "dup"), so no shim sharing is possible.  The
 * symbols are guarded individually so the build still works on stale
 * host headers that predate them.  NFPROTO_IPV4 / NFPROTO_IPV6 /
 * NFPROTO_NETDEV are already shimmed earlier in the file and stable
 * in <linux/netfilter.h>.  Depends on CONFIG_NFT_FWD_NETDEV=m, which
 * the fuzz-box config has. */
#ifndef NFTA_FWD_UNSPEC
#define NFTA_FWD_UNSPEC			0
#endif
#ifndef NFTA_FWD_SREG_DEV
#define NFTA_FWD_SREG_DEV		1
#endif
#ifndef NFTA_FWD_SREG_ADDR
#define NFTA_FWD_SREG_ADDR		2
#endif
#ifndef NFTA_FWD_NFPROTO
#define NFTA_FWD_NFPROTO		3
#endif

/* nft_last NFTA_LAST_* attribute IDs.  The validator in
 * net/netfilter/nft_last.c (nft_last_init) drives off
 * nft_last_policy[]: NFTA_LAST_SET (NLA_U32, big-endian on wire — read
 * via ntohl(nla_get_be32())) is OPTIONAL and acts as a 0/1 flag that
 * controls whether the 'last seen' state is pre-seeded as already set;
 * NFTA_LAST_MSECS (NLA_U64, big-endian on wire — fed through
 * nf_msecs_to_jiffies64, which rejects negative-from-jiffies wraps and
 * oversized future-jiffies values) is OPTIONAL and only consumed when
 * SET == 1, where it carries the seed delta backed off from the
 * current jiffies.  Both attributes absent leaves the expression in
 * the default-init shape; SET == 0 with MSECS present is a no-op for
 * the seed since init only reads MSECS when SET is true.  Each symbol
 * is guarded individually so the build still works on older host
 * headers that predate any subset.  nft_last is built into nf_tables
 * core (no separate CONFIG_NFT_LAST), so any host with
 * CONFIG_NF_TABLES has the expression available. */
#ifndef NFTA_LAST_SET
#define NFTA_LAST_SET			1
#endif
#ifndef NFTA_LAST_MSECS
#define NFTA_LAST_MSECS			2
#endif

/* nft_rt NFTA_RT_* attribute IDs and NFT_RT_* key IDs.  The validator
 * in net/netfilter/nft_rt.c (nft_rt_init / nft_rt_validate) drives off
 * nft_rt_policy[]: NFTA_RT_DREG (NLA_U32) and NFTA_RT_KEY
 * (NLA_POLICY_MAX(NLA_BE32, 255)) are both MANDATORY.  The KEY enum
 * (CLASSID=0, NEXTHOP4=1, NEXTHOP6=2, TCPMSS=3, XFRM=4) selects which
 * dst/route field gets loaded into the destination register; out-of-
 * enum keys are rejected by nft_rt_init's switch statement with
 * -EINVAL even though the policy mask permits 0..255.  Validate() also
 * rejects family != IPv4/IPv6/INET with -EOPNOTSUPP, and TCPMSS
 * additionally requires a FORWARD/LOCAL_OUT/POST_ROUTING hook.
 * nft_rt is built into nf_tables core (no separate CONFIG_NFT_RT), so
 * any host with CONFIG_NF_TABLES has the expression available.  Each
 * symbol is guarded individually so the build still works on older
 * host headers that predate any subset. */
#ifndef NFTA_RT_DREG
#define NFTA_RT_DREG			1
#endif
#ifndef NFTA_RT_KEY
#define NFTA_RT_KEY			2
#endif
#ifndef NFT_RT_CLASSID
#define NFT_RT_CLASSID			0
#endif
#ifndef NFT_RT_NEXTHOP4
#define NFT_RT_NEXTHOP4			1
#endif
#ifndef NFT_RT_NEXTHOP6
#define NFT_RT_NEXTHOP6			2
#endif
#ifndef NFT_RT_TCPMSS
#define NFT_RT_TCPMSS			3
#endif
#ifndef NFT_RT_XFRM
#define NFT_RT_XFRM			4
#endif

/* nft_fib NFTA_FIB_* attribute IDs, NFT_FIB_RESULT_* result IDs, and
 * NFTA_FIB_F_* flag bits.  The validator in net/netfilter/nft_fib.c
 * (nft_fib_init / nft_fib_validate) drives off nft_fib_policy[]: all
 * three of NFTA_FIB_DREG (NLA_U32), NFTA_FIB_RESULT (NLA_U32), and
 * NFTA_FIB_FLAGS (NLA_U32) are MANDATORY (nft_fib_init returns -EINVAL
 * if any are missing).  RESULT is an enum (OIF=1, OIFNAME=2,
 * ADDRTYPE=3); FLAGS is a bitmap (SADDR=1<<0, DADDR=1<<1, MARK=1<<2,
 * IIF=1<<3, OIF=1<<4, PRESENT=1<<5).  nft_fib_init enforces several
 * cross-field constraints: exactly one of SADDR/DADDR must be set
 * (-EINVAL otherwise), IIF and OIF are mutually exclusive (-EINVAL if
 * both), PRESENT is only valid with RESULT=ADDRTYPE (-EOPNOTSUPP
 * otherwise), and MARK requires CONFIG_NF_CONNTRACK_MARK.  Validate()
 * additionally restricts result OIF/OIFNAME/ADDRTYPE-with-OIF to
 * PRE_ROUTING/LOCAL_IN/FORWARD/LOCAL_OUT/POST_ROUTING hooks.  nft_fib
 * is built as CONFIG_NFT_FIB=m (with per-family nft_fib_ipv4/ipv6/inet
 * also =m) on the fuzz-box, so the policy validation path is exercised
 * once the module loads at runtime.  Each symbol is guarded individually
 * so the build still works on stale-host headers that predate any
 * subset of the UAPI exposure. */
#ifndef NFTA_FIB_DREG
#define NFTA_FIB_DREG			1
#endif
#ifndef NFTA_FIB_RESULT
#define NFTA_FIB_RESULT			2
#endif
#ifndef NFTA_FIB_FLAGS
#define NFTA_FIB_FLAGS			3
#endif
#ifndef NFT_FIB_RESULT_OIF
#define NFT_FIB_RESULT_OIF		1
#endif
#ifndef NFT_FIB_RESULT_OIFNAME
#define NFT_FIB_RESULT_OIFNAME		2
#endif
#ifndef NFT_FIB_RESULT_ADDRTYPE
#define NFT_FIB_RESULT_ADDRTYPE		3
#endif
#ifndef NFTA_FIB_F_SADDR
#define NFTA_FIB_F_SADDR		(1 << 0)
#endif
#ifndef NFTA_FIB_F_DADDR
#define NFTA_FIB_F_DADDR		(1 << 1)
#endif
#ifndef NFTA_FIB_F_MARK
#define NFTA_FIB_F_MARK			(1 << 2)
#endif
#ifndef NFTA_FIB_F_IIF
#define NFTA_FIB_F_IIF			(1 << 3)
#endif
#ifndef NFTA_FIB_F_OIF
#define NFTA_FIB_F_OIF			(1 << 4)
#endif
#ifndef NFTA_FIB_F_PRESENT
#define NFTA_FIB_F_PRESENT		(1 << 5)
#endif

/* nft_exthdr NFTA_EXTHDR_* attribute IDs, NFT_EXTHDR_OP_* op enum and the
 * NFT_EXTHDR_F_PRESENT flag bit.  The validator in
 * net/netfilter/nft_exthdr.c is a 4-arm parser whose entry point is
 * nft_exthdr_init: NFTA_EXTHDR_OP (NLA_U32, default OP_IPV6 when absent)
 * selects which init helper runs (nft_exthdr_ipv6_init,
 * nft_exthdr_tcp_init, nft_exthdr_ipv4_init, nft_exthdr_sctp_init).
 * Common-to-all-arms attrs are NFTA_EXTHDR_TYPE (NLA_U8 — interpretation
 * depends on OP), NFTA_EXTHDR_OFFSET (NLA_U32, big-endian on wire),
 * NFTA_EXTHDR_LEN (NLA_U32, big-endian, validator clamps at 127), plus
 * exactly one register: NFTA_EXTHDR_DREG (NLA_U32) on the read path and
 * NFTA_EXTHDR_SREG (NLA_U32) on the write path (TCPOPT-only — the only
 * arm that supports writing an option back).  NFTA_EXTHDR_FLAGS (NLA_U32,
 * big-endian) is OPTIONAL and the only legal bit is NFT_EXTHDR_F_PRESENT
 * (0x01); rejected with -EINVAL when combined with SREG.  nft_exthdr is
 * built into nf_tables core (no separate CONFIG_NFT_EXTHDR), so any host
 * with CONFIG_NF_TABLES has the expression available.  Each symbol is
 * guarded individually so the build still works on older host headers
 * that predate any subset of NFTA_EXTHDR_OP / NFTA_EXTHDR_SREG (added
 * later than the rest of the attr space). */
#ifndef NFTA_EXTHDR_DREG
#define NFTA_EXTHDR_DREG		1
#endif
#ifndef NFTA_EXTHDR_TYPE
#define NFTA_EXTHDR_TYPE		2
#endif
#ifndef NFTA_EXTHDR_OFFSET
#define NFTA_EXTHDR_OFFSET		3
#endif
#ifndef NFTA_EXTHDR_LEN
#define NFTA_EXTHDR_LEN			4
#endif
#ifndef NFTA_EXTHDR_FLAGS
#define NFTA_EXTHDR_FLAGS		5
#endif
#ifndef NFTA_EXTHDR_OP
#define NFTA_EXTHDR_OP			6
#endif
#ifndef NFTA_EXTHDR_SREG
#define NFTA_EXTHDR_SREG		7
#endif
#ifndef NFT_EXTHDR_OP_IPV6
#define NFT_EXTHDR_OP_IPV6		0
#endif
#ifndef NFT_EXTHDR_OP_TCPOPT
#define NFT_EXTHDR_OP_TCPOPT		1
#endif
#ifndef NFT_EXTHDR_OP_IPV4
#define NFT_EXTHDR_OP_IPV4		2
#endif
#ifndef NFT_EXTHDR_OP_SCTP
#define NFT_EXTHDR_OP_SCTP		3
#endif
#ifndef NFT_EXTHDR_F_PRESENT
#define NFT_EXTHDR_F_PRESENT		(1 << 0)
#endif

/* nft_osf NFTA_OSF_* attribute IDs and the NFT_OSF_F_VERSION flag bit.
 * The validator in net/netfilter/nft_osf.c (nft_osf_init) is a single-arm
 * parser whose policy table requires NFTA_OSF_DREG (NLA_BE32 register
 * destination, capped at NFT_REG32_MAX), accepts NFTA_OSF_TTL (NLA_U8,
 * init clamps the meaningful range to 0..2 — values above 2 are rejected
 * with -EINVAL) and accepts NFTA_OSF_FLAGS (NLA_BE32) only when the
 * value is exactly NFT_OSF_F_VERSION (0x01); any other bit pattern is
 * rejected with -EINVAL.  nft_osf builds as CONFIG_NFT_OSF=m, so the
 * policy path runs only once the module is loaded — but the wire bytes
 * are structurally valid either way.  Each symbol is guarded individually
 * so the build still works on older host headers that predate any subset
 * of the attribute or flag definitions. */
#ifndef NFTA_OSF_DREG
#define NFTA_OSF_DREG			1
#endif
#ifndef NFTA_OSF_TTL
#define NFTA_OSF_TTL			2
#endif
#ifndef NFTA_OSF_FLAGS
#define NFTA_OSF_FLAGS			3
#endif
#ifndef NFT_OSF_F_VERSION
#define NFT_OSF_F_VERSION		(1 << 0)
#endif

/* nft_queue NFTA_QUEUE_* attribute IDs and the NFT_QUEUE_FLAG_* mask
 * bits.  The validator in net/netfilter/nft_queue.c is a two-arm
 * parser: nft_queue_init dispatches on whether NFTA_QUEUE_SREG_QNUM is
 * present.  STATIC arm requires NFTA_QUEUE_NUM (NLA_U16, BE16 on wire,
 * the queue index) and accepts NFTA_QUEUE_TOTAL (NLA_U16, BE16 on
 * wire, defaulting to 1 — kernel enforces priv->queuenum +
 * priv->queues_total - 1 <= USHRT_MAX else -ERANGE) plus
 * NFTA_QUEUE_FLAGS (NLA_U16, BE16 on wire, masked against
 * NFT_QUEUE_FLAG_MASK = 0x03 — any bit outside NFT_QUEUE_FLAG_BYPASS |
 * NFT_QUEUE_FLAG_CPU_FANOUT trips -EINVAL).  SREG arm
 * (nft_queue_sreg_init) reads NFTA_QUEUE_SREG_QNUM as a u32 register
 * source (validated by nft_parse_register_load against
 * NFT_REG32_00..NFT_REG32_15) and still accepts the FLAGS mask check;
 * NUM is mutually exclusive with SREG_QNUM (passing both yields
 * -EINVAL).  nft_queue builds as CONFIG_NFT_QUEUE=m on the fuzz-box,
 * so the validator only runs once the module is loaded — but the wire
 * bytes are structurally valid either way.  Each symbol is guarded
 * individually so the build still works on older host headers that
 * predate any subset of the attribute or flag definitions. */
#ifndef NFTA_QUEUE_NUM
#define NFTA_QUEUE_NUM			1
#endif
#ifndef NFTA_QUEUE_TOTAL
#define NFTA_QUEUE_TOTAL		2
#endif
#ifndef NFTA_QUEUE_FLAGS
#define NFTA_QUEUE_FLAGS		3
#endif
#ifndef NFTA_QUEUE_SREG_QNUM
#define NFTA_QUEUE_SREG_QNUM		4
#endif
#ifndef NFT_QUEUE_FLAG_BYPASS
#define NFT_QUEUE_FLAG_BYPASS		0x01
#endif
#ifndef NFT_QUEUE_FLAG_CPU_FANOUT
#define NFT_QUEUE_FLAG_CPU_FANOUT	0x02
#endif
#ifndef NFT_QUEUE_FLAG_MASK
#define NFT_QUEUE_FLAG_MASK		0x03
#endif

/* nft_ct NFTA_CT_* attribute IDs and NFT_CT_* key IDs.  The validator
 * in net/netfilter/nft_ct.c (nft_ct_get_init / nft_ct_set_init) drives
 * off NFTA_CT_KEY: a read-path expression sets DREG and the per-key
 * dispatch picks the load helper, a write-path expression sets SREG
 * and is rejected on read-only keys before any register check runs.
 * NFTA_CT_DIRECTION is only meaningful for tuple keys (SRC/DST/PROTO_*)
 * and is silently ignored on the rest.  Guarded so the build still
 * works on older host headers that predate nft_ct's UAPI exposure. */
#ifndef NFTA_CT_DREG
#define NFTA_CT_DREG			1
#define NFTA_CT_KEY			2
#define NFTA_CT_DIRECTION		3
#define NFTA_CT_SREG			4
#endif

/* Per-key fallbacks.  Each is its own #ifndef so we don't clobber
 * macros the kernel header already defines.  Values track the enum
 * positions in include/uapi/linux/netfilter/nf_tables.h. */
#ifndef NFT_CT_STATE
#define NFT_CT_STATE			0
#endif
#ifndef NFT_CT_DIRECTION
#define NFT_CT_DIRECTION		1
#endif
#ifndef NFT_CT_STATUS
#define NFT_CT_STATUS			2
#endif
#ifndef NFT_CT_MARK
#define NFT_CT_MARK			3
#endif
#ifndef NFT_CT_SECMARK
#define NFT_CT_SECMARK			4
#endif
#ifndef NFT_CT_EXPIRATION
#define NFT_CT_EXPIRATION		5
#endif
#ifndef NFT_CT_HELPER
#define NFT_CT_HELPER			6
#endif
#ifndef NFT_CT_L3PROTOCOL
#define NFT_CT_L3PROTOCOL		7
#endif
#ifndef NFT_CT_SRC
#define NFT_CT_SRC			8
#endif
#ifndef NFT_CT_DST
#define NFT_CT_DST			9
#endif
#ifndef NFT_CT_PROTOCOL
#define NFT_CT_PROTOCOL			10
#endif
#ifndef NFT_CT_PROTO_SRC
#define NFT_CT_PROTO_SRC		11
#endif
#ifndef NFT_CT_PROTO_DST
#define NFT_CT_PROTO_DST		12
#endif
#ifndef NFT_CT_LABELS
#define NFT_CT_LABELS			13
#endif
#ifndef NFT_CT_PKTS
#define NFT_CT_PKTS			14
#endif
#ifndef NFT_CT_BYTES
#define NFT_CT_BYTES			15
#endif
#ifndef NFT_CT_AVGPKT
#define NFT_CT_AVGPKT			16
#endif
#ifndef NFT_CT_ZONE
#define NFT_CT_ZONE			17
#endif
#ifndef NFT_CT_EVENTMASK
#define NFT_CT_EVENTMASK		18
#endif
#ifndef NFT_CT_SRC_IP
#define NFT_CT_SRC_IP			19
#endif
#ifndef NFT_CT_DST_IP
#define NFT_CT_DST_IP			20
#endif
#ifndef NFT_CT_SRC_IP6
#define NFT_CT_SRC_IP6			21
#endif
#ifndef NFT_CT_DST_IP6
#define NFT_CT_DST_IP6			22
#endif
#ifndef NFT_CT_ID
#define NFT_CT_ID			23
#endif

#ifndef IP_CT_DIR_ORIGINAL
#define IP_CT_DIR_ORIGINAL		0
#endif
#ifndef IP_CT_DIR_REPLY
#define IP_CT_DIR_REPLY			1
#endif

/* Reasonable ceiling on a single nfnetlink message + payload.  The
 * rule message with one nested expression containing a verdict +
 * chain string is the largest we emit; well under 1 KiB.  2 KiB
 * leaves headroom. */
#define NFNL_BUF_BYTES			2048
#define NFNL_RECV_TIMEO_S		1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it: a
 * productive run grows toward the cap, an unproductive one shrinks
 * to floor.  Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * the iteration past the SIGALRM(1s) cap. */
#define NFT_PACKET_BASE			3U
#define NFT_PACKET_FLOOR		8U	/* always send at least this many */
#define NFT_PACKET_CAP			64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS			200000000L	/* 200 ms */

/* UDP destination port for the loopback drive packet.  Loopback-only
 * inside a private netns — the value doesn't matter functionally; a
 * fixed non-privileged port keeps any escaped packet trivially
 * identifiable in a tcpdump trace during triage. */
#define NFT_INNER_PORT			34568

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module / config
 * presence is static for the child's lifetime, so we pay the EFAIL
 * once and skip the path on subsequent invocations. */
static bool ns_unsupported_nfnetlink;
static bool ns_unsupported_nf_tables;
static bool ns_unsupported_inet;
static bool ns_unsupported_nft_compat_validate;
static bool ns_unsupported_xt_ct;
static bool ns_unsupported_nft_fwd_netdev_loop;

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = NFNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static int nfnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = NFNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static size_t nla_put_be32(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u32 v)
{
	__u32 be = htonl(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static size_t nla_put_be16(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u16 v)
{
	__u16 be = htons(v);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static size_t nla_put_be64(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u64 v)
{
	__u64 be = ((__u64)htonl((__u32)(v >> 32))) |
		   (((__u64)htonl((__u32)v)) << 32);

	return nla_put(buf, off, cap, type, &be, sizeof(be));
}

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Send via NETLINK_NETFILTER and consume one ack.  Returns 0 on a
 * positive ack (nlmsgerr.error == 0), the negated kernel errno on a
 * rejection, and -EIO on local sendmsg / recv failure.
 */
static int nfnl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	return -EIO;
}

/*
 * nfnetlink message header skeleton: nlmsghdr (with type encoded as
 * (subsys << 8) | msg_id) followed by an nfgenmsg carrying the family
 * and version.  Caller fills attributes after the returned offset.
 */
struct nfgenmsg_local {
	__u8  nfgen_family;
	__u8  version;
	__u16 res_id;	/* network byte order */
};

static size_t nfnl_hdr(unsigned char *buf, __u16 msg_id, __u16 flags,
		       __u8 family)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg_local *nfg;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = (NFNL_SUBSYS_NFTABLES << 8) | msg_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nlh->nlmsg_seq   = next_seq();

	nfg = (struct nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(0);

	return NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
}

static void nfnl_finalize(unsigned char *buf, size_t off)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = (__u32)off;
}

/*
 * Bring lo up inside the private netns.  A freshly-unshared netns
 * has lo present but DOWN; the loopback sendto in step 9 silently
 * drops if lo is down, and without the rx-side completion the input
 * hook never runs and the rule's verdict path stays cold.  Setlink
 * errors are ignored — a kernel that refuses lo up is also one where
 * the rest of the sequence will fail visibly.
 */
static void bring_lo_up(int rtnl)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)nfnl_send_recv(rtnl, buf, nlh->nlmsg_len);
}

/*
 * NFT_MSG_NEWTABLE.  Family is randomised per call; flags=0.
 * NLM_F_CREATE | NLM_F_EXCL fails if the name already exists, which
 * is what we want — the caller rolls a fresh suffix per iteration.
 */
static int build_newtable(int fd, __u8 family, const char *table_name)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS, 0);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static int build_deltable(int fd, __u8 family, const char *table_name)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELTABLE, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_NEWSET, anonymous + dynamic, keyed on ipv4_addr (key_len 4).
 * NFTA_SET_ID is a userspace-assigned cookie so subsequent in-batch
 * commands could reference the set; we don't reference it but the
 * kernel still expects the attr present for newer set-create paths.
 */
static int build_newset(int fd, __u8 family, const char *table_name,
			const char *set_name, __u32 set_id)
{
	unsigned char buf[NFNL_BUF_BYTES];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_FLAGS,
			   NFT_SET_ANONYMOUS | NFT_SET_DYNAMIC);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_KEY_TYPE,
			   NFT_DATATYPE_IPADDR);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_KEY_LEN, 4);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_SET_ID, set_id);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static int build_delset(int fd, __u8 family, const char *table_name,
			const char *set_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELSET, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_SET_NAME, set_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_NEWCHAIN.  When hook_present is true, emits NFTA_CHAIN_HOOK
 * (HOOKNUM=NF_INET_LOCAL_IN, PRIORITY=0) + NFTA_CHAIN_TYPE="filter"
 * — that's a base chain attached to the input hook.  Otherwise emits
 * a regular (no-hook) chain usable as a jump target.
 */
static int build_newchain(int fd, __u8 family, const char *table_name,
			  const char *chain_name, bool hook_present)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_EXCL, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain_name);
	if (!off)
		return -EIO;

	if (hook_present) {
		hook_off = off;
		off = nla_put(buf, off, sizeof(buf),
			      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
		if (!off)
			return -EIO;
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_PRIORITY, 0);
		if (!off)
			return -EIO;
		hook_attr = (struct nlattr *)(buf + hook_off);
		hook_attr->nla_len = (unsigned short)(off - hook_off);

		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return -EIO;
	}

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_payload
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  All field values are picked from kernel-accepted ranges
 * so the message reaches the per-expression parser surface in
 * net/netfilter/nft_payload.c instead of bouncing off NFTA_EXPR_DATA
 * validation in nf_tables_newexpr.  Two variants are emitted, rolled
 * per call:
 *   - read path  (DREG set):  load LEN bytes from base+offset into a
 *     general-purpose register.  Reaches nft_payload_init.
 *   - write path (SREG set):  write LEN bytes from a register back
 *     into the packet at base+offset, optionally with a checksum
 *     fixup.  Reaches nft_payload_set_init plus the csum-helper path.
 */
static size_t build_nft_payload_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 bases[] = {
		NFT_PAYLOAD_LL_HEADER, NFT_PAYLOAD_NETWORK_HEADER,
		NFT_PAYLOAD_TRANSPORT_HEADER, NFT_PAYLOAD_INNER_HEADER,
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
		NFT_REG32_00, NFT_REG32_00 + 1, NFT_REG32_00 + 2,
		NFT_REG32_00 + 3, NFT_REG32_00 + 7,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 base = bases[rand32() % ARRAY_SIZE(bases)];
	__u32 reg  = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 offset_v = rand32() % 64;
	__u32 len_v    = (rand32() % 16) + 1;
	bool write_path = ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "payload");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_BASE, base);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_OFFSET, offset_v);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_LEN, len_v);
	if (!off)
		return 0;

	if (write_path) {
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_SREG, reg);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_TYPE,
				   rand32() % 3);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_OFFSET,
				   rand32() % 64);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_CSUM_FLAGS,
				   rand32() & 0x1);
		if (!off)
			return 0;
	} else {
		off = nla_put_be32(buf, off, cap, NFTA_PAYLOAD_DREG, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_meta
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-key validator + register check in
 * net/netfilter/nft_meta.c (nft_meta_get_init / nft_meta_set_init)
 * instead of bouncing off NFTA_EXPR_DATA validation in
 * nf_tables_newexpr.  Two variants, rolled per call:
 *   - read path  (DREG, 3-in-4): load the metadata field named by
 *     NFTA_META_KEY into a general-purpose register.  Key is rolled
 *     across the full read-allowed set.
 *   - write path (SREG, 1-in-4): write a register value back into a
 *     writable metadata field.  The kernel rejects SREG on read-only
 *     keys before any register validation runs, so the key is rolled
 *     over a conservative writable subset (MARK, PRIORITY, NFTRACE,
 *     PKTTYPE) — widening it would just pre-empt coverage of
 *     nft_meta_set_init.
 */
static size_t build_nft_meta_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 read_keys[] = {
		NFT_META_LEN, NFT_META_PROTOCOL, NFT_META_PRIORITY,
		NFT_META_MARK, NFT_META_IIF, NFT_META_OIF,
		NFT_META_IIFNAME, NFT_META_OIFNAME,
		NFT_META_IIFTYPE, NFT_META_OIFTYPE,
		NFT_META_SKUID, NFT_META_SKGID, NFT_META_NFTRACE,
		NFT_META_RTCLASSID, NFT_META_SECMARK,
		NFT_META_NFPROTO, NFT_META_L4PROTO,
		NFT_META_BRI_IIFNAME, NFT_META_BRI_OIFNAME,
		NFT_META_PKTTYPE, NFT_META_CPU,
		NFT_META_IIFGROUP, NFT_META_OIFGROUP,
		NFT_META_CGROUP, NFT_META_PRANDOM,
		NFT_META_IIFKIND, NFT_META_OIFKIND,
		NFT_META_BRI_IIFPVID, NFT_META_BRI_IIFVPROTO,
		NFT_META_TIME_NS, NFT_META_TIME_DAY, NFT_META_TIME_HOUR,
		NFT_META_SDIF, NFT_META_SDIFNAME,
	};
	static const __u32 write_keys[] = {
		NFT_META_MARK, NFT_META_PRIORITY,
		NFT_META_NFTRACE, NFT_META_PKTTYPE,
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
		NFT_REG32_00, NFT_REG32_00 + 1, NFT_REG32_00 + 2,
		NFT_REG32_00 + 3, NFT_REG32_00 + 7,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool write_path = ONE_IN(4);
	__u32 reg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 key = write_path
		? write_keys[rand32() % ARRAY_SIZE(write_keys)]
		: read_keys[rand32() % ARRAY_SIZE(read_keys)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "meta");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_META_KEY, key);
	if (!off)
		return 0;

	if (write_path)
		off = nla_put_be32(buf, off, cap, NFTA_META_SREG, reg);
	else
		off = nla_put_be32(buf, off, cap, NFTA_META_DREG, reg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_lookup
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-expression validator in
 * net/netfilter/nft_lookup.c (nft_lookup_init) — set-binding,
 * sreg/dreg validation, and the map-vs-plain set type check.  Refers
 * to the in-transaction anonymous set already created by build_newset
 * via NFTA_LOOKUP_SET (name) + NFTA_LOOKUP_SET_ID (cookie); the kernel
 * resolves the binding inside the same commit.
 *
 * Roll variants per call:
 *   - SREG always present (key register, NFT_REG32_00..15).
 *   - DREG present 1-in-2 (NFT_REG32_00..15).  DREG is only valid on
 *     map-typed sets — the kernel returns -EOPNOTSUPP for plain sets,
 *     which is exactly the validator path we're trying to cover.
 *   - FLAGS = 0 by default, NFT_LOOKUP_F_INV 1-in-4 (negated lookup).
 */
static size_t build_nft_lookup_expr(unsigned char *buf, size_t off,
				    size_t cap, const char *set_name,
				    __u32 set_id)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg = NFT_REG32_00 + (rand32() % 16);
	__u32 dreg = NFT_REG32_00 + (rand32() % 16);
	__u32 flags = ONE_IN(4) ? NFT_LOOKUP_F_INV : 0;
	bool with_dreg = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "lookup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_LOOKUP_SET, set_name);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_SREG, sreg);
	if (!off)
		return 0;
	if (with_dreg) {
		off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_DREG, dreg);
		if (!off)
			return 0;
	}
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_SET_ID, set_id);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_LOOKUP_FLAGS, flags);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_log
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-attribute validator in
 * net/netfilter/nft_log.c (nft_log_init) — nf_log binding, group /
 * snaplen / qthreshold range checks, and the prefix-string parser.
 *
 * Each optional attribute is coin-flipped in independently so the
 * emitted shape varies per call.  If every coin came up false a
 * single attribute is forced in so the expression is never
 * degenerate-empty (which the kernel would happily accept but which
 * would waste an iteration).
 */
static size_t build_nft_log_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_prefix    = ONE_IN(2);
	bool with_group     = ONE_IN(3);
	bool with_snaplen   = ONE_IN(3);
	bool with_qthresh   = ONE_IN(3);
	bool with_level     = ONE_IN(2);
	bool with_flags     = ONE_IN(3);

	if (!with_prefix && !with_group && !with_snaplen &&
	    !with_qthresh && !with_level && !with_flags) {
		switch (rand32() % 6) {
		case 0: with_prefix  = true; break;
		case 1: with_group   = true; break;
		case 2: with_snaplen = true; break;
		case 3: with_qthresh = true; break;
		case 4: with_level   = true; break;
		default: with_flags  = true; break;
		}
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "log");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_prefix) {
		char prefix[9];
		unsigned int len = (rand32() % 8) + 1;
		unsigned int i;

		for (i = 0; i < len; i++)
			prefix[i] = 'a' + (rand32() % 26);
		prefix[len] = '\0';
		off = nla_put_str(buf, off, cap, NFTA_LOG_PREFIX, prefix);
		if (!off)
			return 0;
	}

	if (with_group) {
		off = nla_put_be16(buf, off, cap, NFTA_LOG_GROUP,
				   (__u16)rand32());
		if (!off)
			return 0;
	}

	if (with_snaplen) {
		off = nla_put_be32(buf, off, cap, NFTA_LOG_SNAPLEN,
				   rand32() % 0x10000);
		if (!off)
			return 0;
	}

	if (with_qthresh) {
		off = nla_put_be16(buf, off, cap, NFTA_LOG_QTHRESHOLD,
				   (__u16)rand32());
		if (!off)
			return 0;
	}

	if (with_level) {
		off = nla_put_be32(buf, off, cap, NFTA_LOG_LEVEL,
				   rand32() % 8);
		if (!off)
			return 0;
	}

	if (with_flags) {
		__u32 flags = ONE_IN(2)
			? NF_LOG_DEFAULT_MASK
			: (rand32() & NF_LOG_DEFAULT_MASK);
		off = nla_put_be32(buf, off, cap, NFTA_LOG_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_bitwise
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the per-op validator + register check in
 * net/netfilter/nft_bitwise.c (nft_bitwise_init) — the policy table
 * nft_bitwise_policy[] gates SREG/DREG/LEN/OP and then the op-specific
 * payload (MASK+XOR for BOOL, DATA shift count for LSHIFT/RSHIFT) is
 * parsed by the per-branch helper.
 *
 * Roll variants per call:
 *   - LEN coin-flips across {1, 2, 4, 8, 16} bytes — the validator
 *     accepts any length up to NFT_REG_SIZE, and each width hits a
 *     different memcpy / register-fold path.
 *   - OP picks NFT_BITWISE_BOOL (mask+xor) ONE_IN(2), else
 *     NFT_BITWISE_LSHIFT or NFT_BITWISE_RSHIFT.
 *   - For BOOL: MASK and XOR are each a nested NFTA_DATA_VALUE of LEN
 *     bytes filled with random data.
 *   - For LSHIFT/RSHIFT: NFTA_BITWISE_DATA is a nested NFTA_DATA_VALUE
 *     carrying a __be32 shift count in 0..31, the range the kernel
 *     accepts before nft_bitwise_init returns -EINVAL.
 */
static size_t build_nft_bitwise_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
	bool boolean_op = ONE_IN(2);
	__u32 op = boolean_op
		? NFT_BITWISE_BOOL
		: ((rand32() & 1) ? NFT_BITWISE_LSHIFT : NFT_BITWISE_RSHIFT);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "bitwise");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_LEN, len_v);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BITWISE_OP, op);
	if (!off)
		return 0;

	if (boolean_op) {
		unsigned char bytes[16];

		/* MASK = nested NFTA_DATA_VALUE = LEN random bytes */
		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_MASK | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);

		/* XOR = nested NFTA_DATA_VALUE = LEN random bytes */
		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_XOR | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);
	} else {
		__u32 shift = rand32() % 32;

		value_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_BITWISE_DATA | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, shift);
		if (!off)
			return 0;
		value = (struct nlattr *)(buf + value_off);
		value->nla_len = (unsigned short)(off - value_off);
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_cmp
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_cmp.c
 * (nft_cmp_init) — the policy table nft_cmp_policy[] gates SREG/OP/DATA
 * and then nft_data_init parses the nested NFTA_DATA_VALUE payload.
 *
 * cmp is the most fundamental nftables expression: every realistic rule
 * compares a freshly-loaded register against a literal.  Roll variants
 * per call:
 *   - SREG picks one of NFT_REG_1..NFT_REG_4 uniformly so cmp consumes
 *     whatever a preceding payload/meta/bitwise emit just stored.
 *   - OP picks NFT_CMP_EQ ONE_IN(2) (matches the dominant real-world
 *     shape), else uniform across NEQ/LT/LTE/GT/GTE so the ordered
 *     comparators get exercised too.
 *   - DATA length coin-flips across {1, 2, 4, 8, 16} bytes — the
 *     validator accepts any length up to NFT_REG_SIZE, and each width
 *     hits a different memcmp / register-fold path.
 *   - DATA bytes are random; the rule will almost never match traffic,
 *     but commit-time validation (the codepath we care about for churn)
 *     runs regardless.
 */
static size_t build_nft_cmp_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 ordered_ops[] = {
		NFT_CMP_NEQ, NFT_CMP_LT, NFT_CMP_LTE,
		NFT_CMP_GT, NFT_CMP_GTE,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
	__u32 op = ONE_IN(2)
		? NFT_CMP_EQ
		: ordered_ops[rand32() % ARRAY_SIZE(ordered_ops)];
	unsigned char bytes[16];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "cmp");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_CMP_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_CMP_OP, op);
	if (!off)
		return 0;

	value_off = off;
	off = nla_put(buf, off, cap, NFTA_CMP_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	generate_rand_bytes(bytes, len_v);
	off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_range
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_range.c
 * (nft_range_init) — the policy table nft_range_policy[] gates
 * SREG/OP/FROM_DATA/TO_DATA and then nft_data_init parses each nested
 * NFTA_DATA_VALUE bound.  The kernel rejects reversed bounds via
 * memcmp(from, to) > 0 before any register check runs, so FROM is
 * rolled and TO is rolled strictly above it.
 *
 * range is the structural cousin of cmp — same SREG-vs-literal model,
 * but takes a [FROM, TO] interval and returns match/no-match per OP.
 * Roll variants per call:
 *   - SREG picks one of NFT_REG_1..NFT_REG_4 uniformly so range consumes
 *     whatever a preceding payload/meta/bitwise emit just stored.
 *   - OP picks NFT_RANGE_EQ ONE_IN(2), else NFT_RANGE_NEQ — the only
 *     two values the kernel enum exposes.
 *   - FROM is a 31-bit random; TO = FROM + 1 + small-random, capped so
 *     the addition can't wrap.  Both bounds are emitted in network
 *     byte order via nla_put_be32(NFTA_DATA_VALUE), which preserves
 *     numeric ordering under the kernel's byte-wise memcmp.
 *
 * LOAD-only: range only reads SREG and the immediate FROM/TO bounds —
 * no DREG, no register write, no datapath state mutation.  Heavier
 * than cmp at commit time (two NFTA_DATA_VALUE parses + a bound-
 * ordering memcmp) but cheap on the runtime side.
 */
static size_t build_nft_range_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data, *value;
	size_t elem_off, expr_data_off, value_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 op = ONE_IN(2) ? NFT_RANGE_EQ : NFT_RANGE_NEQ;
	__u32 from_v = rand32() & 0x7fffffffU;
	__u32 to_v = from_v + 1 + (rand32() % 0x10000);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "range");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_RANGE_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_RANGE_SREG, sreg);
	if (!off)
		return 0;

	value_off = off;
	off = nla_put(buf, off, cap,
		      NFTA_RANGE_FROM_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, from_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	value_off = off;
	off = nla_put(buf, off, cap,
		      NFTA_RANGE_TO_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DATA_VALUE, to_v);
	if (!off)
		return 0;
	value = (struct nlattr *)(buf + value_off);
	value->nla_len = (unsigned short)(off - value_off);

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_byteorder
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_byteorder.c
 * (nft_byteorder_init) — the policy table nft_byteorder_policy[] gates
 * SREG/DREG/OP/LEN/SIZE and every attribute is mandatory (no
 * NLA_F_OPTIONAL on any slot).  After parsing the kernel further
 * enforces SIZE in {2, 4, 8} and LEN a non-zero multiple of SIZE,
 * with LEN capped at FIELD_SIZEOF(struct nft_data, data) == 16.
 *
 * byteorder is a load/store register reformatter — it reads LEN bytes
 * from SREG, byte-swaps each SIZE-wide element through ntoh/hton, and
 * writes the result to DREG.  Roll variants per call:
 *   - SREG and DREG independently pick from NFT_REG_1..NFT_REG_4 so
 *     byteorder consumes whatever a preceding payload/meta/bitwise
 *     emit just stored, and so DREG races other expressions writing
 *     the same register inside one rule.
 *   - OP picks NTOH ONE_IN(2) else HTON — the only two values the
 *     kernel enum exposes.
 *   - SIZE is rolled first from {2, 4, 8}, then LEN is picked as a
 *     multiple of SIZE bounded by 16, so every emit sits inside the
 *     validator's accept range and exercises the per-element swap
 *     loop rather than the EINVAL early-return.
 *
 * LOAD-and-STORE: byteorder writes the destination register, so it
 * also exercises the nft_data store path that purely-readonly
 * expressions like cmp/range never touch.
 */
static size_t build_nft_byteorder_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 sizes[] = { 2, 4, 8 };
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 op = ONE_IN(2) ? NFT_BYTEORDER_NTOH : NFT_BYTEORDER_HTON;
	__u32 size = sizes[rand32() % ARRAY_SIZE(sizes)];
	__u32 max_mult = 16 / size;
	__u32 mult = 1 + (rand32() % max_mult);
	__u32 len = mult * size;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "byteorder");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_SREG, sreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_LEN, len);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_BYTEORDER_SIZE, size);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_socket
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_socket.c
 * (nft_socket_init) — the policy table nft_socket_policy[] gates
 * KEY/DREG/LEVEL, and the init handler enforces a KEY-conditional rule:
 * NFTA_SOCKET_LEVEL is mandatory iff KEY == NFT_SOCKET_CGROUPV2 and
 * rejected for any other KEY.
 *
 * socket reaches into the per-skb socket lookup path: nft_socket_eval
 * resolves the socket via skb->sk (falling back to nf_sk_lookup_slow
 * when missing), normalises through sk_to_full_sk, and then the per-key
 * dispatch reads IP(V6)_TRANSPARENT, sk->sk_mark, the wildcard-bind
 * test or sock_cgroup_ancestor at the requested cgroupv2 level — all
 * load paths that purely-on-skb expressions like payload/byteorder
 * never touch.  Roll variants per call:
 *   - KEY picks uniformly from
 *     {TRANSPARENT, MARK, WILDCARD, CGROUPV2} so each emit lands on a
 *     different per-key load helper.
 *   - DREG picks one of NFT_REG_1..NFT_REG_4 uniformly so the lookup
 *     result lands in whatever register a following cmp/range/bitwise
 *     emit will read.
 *   - LEVEL is rolled in 0..255 (the kernel-accepted range) and is
 *     emitted ONLY when KEY == NFT_SOCKET_CGROUPV2; on any other KEY
 *     LEVEL is omitted so nft_socket_init's "LEVEL with non-CGROUPV2
 *     KEY" early-EINVAL is not the dominant outcome.
 */
static size_t build_nft_socket_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 keys[] = {
		NFT_SOCKET_TRANSPARENT, NFT_SOCKET_MARK,
		NFT_SOCKET_WILDCARD, NFT_SOCKET_CGROUPV2,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 key = keys[rand32() % ARRAY_SIZE(keys)];
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 level = rand32() & 0xff;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "socket");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_SOCKET_KEY, key);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_SOCKET_DREG, dreg);
	if (!off)
		return 0;
	if (key == NFT_SOCKET_CGROUPV2) {
		off = nla_put_be32(buf, off, cap, NFTA_SOCKET_LEVEL, level);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_quota
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_quota.c
 * (nft_quota_init): NFTA_QUOTA_BYTES is mandatory (the cap), FLAGS is
 * optional and only NFT_QUOTA_F_INV is accepted, CONSUMED is optional
 * and pre-seeds the per-rule counter.  All three values are u64/u32 in
 * network byte order.
 *
 * Variants per call:
 *   - BYTES rolls uniformly across orders of magnitude
 *     {tiny, typical, huge} so each emit lands somewhere different on
 *     the cap-not-yet-hit vs cap-immediately-exceeded axis the eval
 *     comparator dispatches on.
 *   - FLAGS is a coin-flip on NFT_QUOTA_F_INV and otherwise omitted, so
 *     the inversion branch in nft_quota_eval gets exercised half the
 *     time without ever feeding an unknown bit (which the parser
 *     rejects with -EOPNOTSUPP before init returns).
 *   - CONSUMED is rolled ONE_IN(2); when present its value sits below
 *     BYTES half the time and above BYTES the other half so the
 *     consumed-vs-cap comparison in nft_quota_eval sees both sides on
 *     the very first packet.
 */
static size_t build_nft_quota_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 byte_caps[] = {
		1ULL,			/* tiny: cap-immediately-hit */
		4096ULL,		/* small */
		1ULL << 20,		/* typical (~1 MiB) */
		1ULL << 32,		/* huge (~4 GiB) */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u64 bytes = byte_caps[rand32() % ARRAY_SIZE(byte_caps)];
	bool with_flags = ONE_IN(2);
	bool with_consumed = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "quota");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be64(buf, off, cap, NFTA_QUOTA_BYTES, bytes);
	if (!off)
		return 0;

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_QUOTA_FLAGS,
				   NFT_QUOTA_F_INV);
		if (!off)
			return 0;
	}

	if (with_consumed) {
		__u64 consumed;

		if (ONE_IN(2)) {
			consumed = bytes ? (rand64() % (bytes + 1)) : 0;
		} else {
			consumed = bytes + 1 + (rand64() & 0xffff);
		}
		off = nla_put_be64(buf, off, cap, NFTA_QUOTA_CONSUMED,
				   consumed);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_objref
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  nft_objref references a previously-registered named
 * object (counter, quota, ct helper, ...) and the expression has two
 * operating modes selected by net/netfilter/nft_objref.c
 * (nft_objref_select_ops): IMM mode dispatches to nft_objref_init,
 * SET mode dispatches to nft_objref_map_init.
 *
 * IMM mode emits NFTA_OBJREF_IMM_NAME (NLA_STRING, bounded by
 * NFT_OBJ_MAXNAMELEN-1) and NFTA_OBJREF_IMM_TYPE (NLA_U32, must match a
 * registered NFT_OBJECT_* family).  The kernel's nft_objref_init runs
 * the policy check first, then calls nft_obj_lookup() — names that
 * miss the lookup return -ENOENT but the NLA validation path
 * (string-length bound, type range) has already executed end-to-end.
 *
 * SET mode emits NFTA_OBJREF_SET_SREG (NLA_U32, validated by
 * nft_parse_register_load against the bound set's klen) plus
 * NFTA_OBJREF_SET_NAME and/or NFTA_OBJREF_SET_ID — the kernel accepts
 * either or both, the lookup uses NAME-then-ID resolution.  Garbage
 * names hit nft_set_lookup_global and bounce out cheaply, again after
 * the policy check has run.  Reaches both nft_objref_init and
 * nft_objref_map_init parser paths under random rolls.
 *
 * Variants per call:
 *   - IMM-vs-SET coin-flip so each emit splits roughly 50/50 between
 *     the two select_ops branches.
 *   - IMM-mode TYPE rolls uniformly across the 9 in-tree NFT_OBJECT_*
 *     constants {COUNTER, QUOTA, CT_HELPER, LIMIT, CONNLIMIT, TUNNEL,
 *     CT_TIMEOUT, SECMARK, CT_EXPECT, SYNPROXY} so the type-range
 *     validation in nft_objref_init sees the full accepted range
 *     (and SYNPROXY exercises the family/hooks gate in
 *     nft_objref_validate_obj_type).
 *   - IMM-mode NAME picks from a small short-name pool — names will
 *     usually miss nft_obj_lookup but the pool keeps the bounded
 *     NLA_STRING test working at expected lengths.
 *   - SET-mode SREG picks NFT_REG_1..NFT_REG_4.
 *   - SET-mode emits NAME and/or ID under coin flips so all three
 *     legal {NAME-only, ID-only, NAME+ID} combinations are reached.
 */
static size_t build_nft_objref_expr(unsigned char *buf, size_t off,
				    size_t cap)
{
	static const __u32 obj_types[] = {
		NFT_OBJECT_COUNTER,	NFT_OBJECT_QUOTA,
		NFT_OBJECT_CT_HELPER,	NFT_OBJECT_LIMIT,
		NFT_OBJECT_CONNLIMIT,	NFT_OBJECT_TUNNEL,
		NFT_OBJECT_CT_TIMEOUT,	NFT_OBJECT_SECMARK,
		NFT_OBJECT_CT_EXPECT,	NFT_OBJECT_SYNPROXY,
	};
	static const char * const obj_names[] = {
		"c1", "q1", "l1", "h1", "ct1", "tun1", "sm1", "sp1",
	};
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool set_mode = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "objref");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (set_mode) {
		__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
		bool with_name = ONE_IN(2);
		bool with_id = with_name ? ONE_IN(2) : true;

		off = nla_put_be32(buf, off, cap,
				   NFTA_OBJREF_SET_SREG, sreg);
		if (!off)
			return 0;
		if (with_name) {
			const char *nm =
				obj_names[rand32() % ARRAY_SIZE(obj_names)];

			off = nla_put_str(buf, off, cap,
					  NFTA_OBJREF_SET_NAME, nm);
			if (!off)
				return 0;
		}
		if (with_id) {
			off = nla_put_be32(buf, off, cap,
					   NFTA_OBJREF_SET_ID, rand32());
			if (!off)
				return 0;
		}
	} else {
		const char *nm =
			obj_names[rand32() % ARRAY_SIZE(obj_names)];
		__u32 type = obj_types[rand32() % ARRAY_SIZE(obj_types)];

		off = nla_put_str(buf, off, cap,
				  NFTA_OBJREF_IMM_NAME, nm);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap,
				   NFTA_OBJREF_IMM_TYPE, type);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_limit
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_limit.c
 * (nft_limit_init): NFTA_LIMIT_RATE and NFTA_LIMIT_UNIT are mandatory,
 * BURST/TYPE/FLAGS are optional.  TYPE picks between
 * NFT_LIMIT_PKTS (default) and NFT_LIMIT_PKT_BYTES which dispatches to
 * nft_limit_pkts_init vs nft_limit_bytes_init for token-bucket setup.
 * RATE == 0 is rejected outright; unknown TYPE / unknown FLAGS bits are
 * rejected with -EOPNOTSUPP.  All values go on the wire u64/u32 in
 * network byte order.
 *
 * Variants per call:
 *   - RATE rolls uniformly across orders of magnitude
 *     {small, typical, huge} so the token-bucket arithmetic in
 *     nft_limit_eval (nfs / rate, with the divide_s64 in
 *     nft_limit_init) sees both fast-refill and slow-refill regimes.
 *     RATE is forced non-zero so init does not bail at the rate==0
 *     guard before the bucket math runs.
 *   - UNIT picks one of {1, 60, 3600} seconds — the per-second,
 *     per-minute, and per-hour windows real rulesets use — so the
 *     unit*NSEC_PER_SEC multiplication in nft_limit_init exercises a
 *     spread of nfs values feeding the credit/refill divide.
 *   - BURST is coin-flipped present, value rolled small/medium/large so
 *     the optional widening of the bucket capacity is hit half the time
 *     without ever omitting the more interesting refill path.
 *   - TYPE is coin-flipped between PKTS and PKT_BYTES so both
 *     dispatch arms (per-packet credit decrement vs per-skb-len credit
 *     decrement in nft_limit_eval) see traffic.
 *   - FLAGS is a coin-flip on NFT_LIMIT_F_INV and otherwise omitted, so
 *     the inverted-budget branch in nft_limit_eval gets exercised half
 *     the time without ever feeding an unknown bit (which the parser
 *     rejects with -EOPNOTSUPP before init returns).
 */
static size_t build_nft_limit_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 rates[] = {
		1ULL,			/* small: bucket immediately drained */
		1024ULL,		/* typical */
		1ULL << 20,		/* huge */
	};
	static const __u64 units[] = {
		1ULL,			/* per-second */
		60ULL,			/* per-minute */
		3600ULL,		/* per-hour */
	};
	static const __u32 bursts[] = {
		0U,			/* small */
		128U,			/* medium */
		65535U,			/* large */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u64 rate = rates[rand32() % ARRAY_SIZE(rates)];
	__u64 unit = units[rand32() % ARRAY_SIZE(units)];
	bool with_burst = ONE_IN(2);
	bool with_type = ONE_IN(2);
	bool with_flags = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "limit");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be64(buf, off, cap, NFTA_LIMIT_RATE, rate);
	if (!off)
		return 0;
	off = nla_put_be64(buf, off, cap, NFTA_LIMIT_UNIT, unit);
	if (!off)
		return 0;

	if (with_burst) {
		__u32 burst = bursts[rand32() % ARRAY_SIZE(bursts)];

		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_BURST, burst);
		if (!off)
			return 0;
	}

	if (with_type) {
		__u32 type = ONE_IN(2) ? NFT_LIMIT_PKTS : NFT_LIMIT_PKT_BYTES;

		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_TYPE, type);
		if (!off)
			return 0;
	}

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_LIMIT_FLAGS,
				   NFT_LIMIT_F_INV);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_numgen
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_numgen.c via
 * the nft_ng_policy[] parser: NFTA_NG_DREG, NFTA_NG_MODULUS and
 * NFTA_NG_TYPE are mandatory, NFTA_NG_OFFSET is optional.  The TYPE
 * value dispatches to nft_ng_inc_init (NFT_NG_INCREMENTAL: atomic
 * counter mod modulus) or nft_ng_random_init (NFT_NG_RANDOM: PRNG mod
 * modulus); both reject modulus == 0 with -ERANGE, and any TYPE outside
 * {INCREMENTAL, RANDOM} is rejected with -EOPNOTSUPP before the
 * type-specific init runs.  The deprecated NFTA_NG_SET_NAME /
 * NFTA_NG_SET_ID anonymous-set variants are intentionally not emitted
 * here — they need their own slice with care around the .set policy
 * gate.
 *
 * Variants per call:
 *   - DREG uniform across NFT_REG_1..NFT_REG_4 so the destination
 *     register validation in nft_parse_register_store sees the full
 *     legacy-register spread.
 *   - MODULUS rolls uniformly across {2, 16, 256, 65536} so both the
 *     small-modulus per-byte fan-out (the natural per-byte hash spread)
 *     and the wide-modulus per-port-style fan-out land on the eval-time
 *     reciprocal_scale path.  All four values are > 0 so the
 *     -ERANGE guard in both init helpers never fires before the
 *     type-specific init runs.
 *   - TYPE is coin-flipped between NFT_NG_INCREMENTAL and
 *     NFT_NG_RANDOM so both dispatch arms (atomic counter increment vs
 *     prandom_u32_state in nft_ng_random_eval) see traffic.
 *   - OFFSET is coin-flipped present, value uniform over
 *     {0, 1, 0x100, 0xffff}; when present the eval-time u32 add of
 *     (counter % modulus) + offset exercises the offset-fold path
 *     including the wrap that 0xffff + small-modulus produces.
 */
static size_t build_nft_numgen_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 moduli[] = {
		2U,			/* small: per-byte fan-out */
		16U,
		256U,
		65536U,			/* wide: per-port-style fan-out */
	};
	static const __u32 offsets[] = {
		0U, 1U, 0x100U, 0xffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 modulus = moduli[rand32() % ARRAY_SIZE(moduli)];
	__u32 type = ONE_IN(2) ? NFT_NG_INCREMENTAL : NFT_NG_RANDOM;
	bool with_offset = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "numgen");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_NG_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_NG_MODULUS, modulus);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_NG_TYPE, type);
	if (!off)
		return 0;

	if (with_offset) {
		__u32 offset = offsets[rand32() % ARRAY_SIZE(offsets)];

		off = nla_put_be32(buf, off, cap, NFTA_NG_OFFSET, offset);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_hash
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_hash.c via the
 * nft_hash_policy[] parser, which dispatches on NFTA_HASH_TYPE:
 * NFT_HASH_JENKINS (nft_jhash_init) consumes a contiguous LEN-byte
 * window starting at SREG, jhashes it with SEED and reduces mod MODULUS
 * (plus OFFSET if present); NFT_HASH_SYM (nft_symhash_init) reduces the
 * skb hash mod MODULUS and stores at DREG, ignoring SREG/LEN/SEED — the
 * parser actively rejects those attributes on the symhash path with
 * -EINVAL.  Both inits reject MODULUS == 0 with -ERANGE and any TYPE
 * outside {JENKINS, SYM} with -EOPNOTSUPP before the type-specific init
 * runs.  TYPE is emitted explicitly even though absent defaults to
 * JENKINS, so the on-wire shape is unambiguous regardless of which arm
 * we picked.  The deprecated NFTA_HASH_SET_NAME / NFTA_HASH_SET_ID
 * map-lookup variants are intentionally not emitted here — they need
 * their own slice with care around the .set policy gate.
 *
 * Variants per call:
 *   - TYPE coin-flips between NFT_HASH_JENKINS and NFT_HASH_SYM so both
 *     dispatch arms (per-packet jhash of an SREG window vs the precomputed
 *     skb->hash reduction) see traffic.  Per-arm attribute sets are
 *     emitted strictly: jhash carries SREG + LEN + optional SEED, symhash
 *     carries neither so the -EINVAL guard never fires before init.
 *   - DREG uniform across NFT_REG_1..NFT_REG_4 so the destination
 *     register validation in nft_parse_register_store sees the full
 *     legacy-register spread.
 *   - SREG (jhash only) uniform across NFT_REG_1..NFT_REG_4 so the
 *     source register validation in nft_parse_register_load lands on
 *     each of the legacy registers.
 *   - LEN (jhash only) rolls uniformly across {1, 4, 8, 16, 32}, all
 *     within the 1..NFT_REG_SIZE*4 == 1..64 range the parser enforces;
 *     the spread covers both single-byte and multi-register windows.
 *   - MODULUS rolls uniformly across {2, 16, 256, 65536} so both the
 *     small-modulus per-byte fan-out and the wide-modulus per-port-style
 *     fan-out land on the eval-time reciprocal_scale path.  All four
 *     values are > 0 so the -ERANGE guard never fires.
 *   - SEED (jhash only) is coin-flipped present, value uniform u32; when
 *     absent the kernel synthesises one via prandom at init time, so
 *     both seeded and self-seeded init paths get coverage.
 *   - OFFSET is coin-flipped present, value uniform over
 *     {0, 1, 0x100, 0xffff}; when present the eval-time u32 add of
 *     (hash % modulus) + offset exercises the offset-fold path including
 *     the wrap that 0xffff + small-modulus produces.
 */
static size_t build_nft_hash_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 lens[] = { 1U, 4U, 8U, 16U, 32U };
	static const __u32 moduli[] = {
		2U,			/* small: per-byte fan-out */
		16U,
		256U,
		65536U,			/* wide: per-port-style fan-out */
	};
	static const __u32 offsets[] = {
		0U, 1U, 0x100U, 0xffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 modulus = moduli[rand32() % ARRAY_SIZE(moduli)];
	__u32 type = ONE_IN(2) ? NFT_HASH_JENKINS : NFT_HASH_SYM;
	bool with_offset = ONE_IN(2);
	bool with_seed = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "hash");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_HASH_DREG, dreg);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_HASH_MODULUS, modulus);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_HASH_TYPE, type);
	if (!off)
		return 0;

	if (type == NFT_HASH_JENKINS) {
		__u32 sreg = regs[rand32() % ARRAY_SIZE(regs)];
		__u32 len = lens[rand32() % ARRAY_SIZE(lens)];

		off = nla_put_be32(buf, off, cap, NFTA_HASH_SREG, sreg);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_HASH_LEN, len);
		if (!off)
			return 0;

		if (with_seed) {
			off = nla_put_be32(buf, off, cap, NFTA_HASH_SEED,
					   rand32());
			if (!off)
				return 0;
		}
	}

	if (with_offset) {
		__u32 offset = offsets[rand32() % ARRAY_SIZE(offsets)];

		off = nla_put_be32(buf, off, cap, NFTA_HASH_OFFSET, offset);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_synproxy
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_synproxy.c
 * via the nft_synproxy_policy[] parser and nft_synproxy_do_init().
 *
 * Each of the three attributes is individually OPTIONAL in do_init
 * (each is gated by `if (tb[...])` in the init body), so any subset is
 * accepted by the parser.  Per-attr coin-flips drive presence; if all
 * three coin-flips would produce the empty payload, MSS is forced
 * present so the priv struct does not stay at default-zero — which
 * leaves every option-emit path in nft_synproxy_eval cold.
 *
 * Variants per call:
 *   - NFTA_SYNPROXY_MSS (NLA_U16, big-endian on wire — the kernel reads
 *     it via ntohs(nla_get_be16())) is the TCP MSS the synproxy hands
 *     back to the backend.  The policy has no validator beyond the
 *     type, so values roll uniformly across {0, 536, 1460, 9000} —
 *     covering the degenerate zero, the IPv4 minimum, the typical
 *     ethernet MSS, and the jumbo-frame end of the range.  All four
 *     fit in 16 bits, so the truncation guard is never reached.
 *   - NFTA_SYNPROXY_WSCALE (NLA_U8) is the TCP window-scale shift.
 *     The policy is NLA_POLICY_MAX(NLA_U8, TCP_MAX_WSCALE) where
 *     TCP_MAX_WSCALE == 14, so the parser rejects values > 14 with
 *     -EINVAL before do_init runs.  WSCALE rolls uniformly across the
 *     full valid 0..14 range, exercising both the unscaled (0) and
 *     fully-scaled (14) ends of the SYN/ACK option emit path.
 *   - NFTA_SYNPROXY_FLAGS (NLA_BE32) is the option mask the synproxy
 *     reflects into its SYN/ACK.  The policy is
 *     NLA_POLICY_MASK(NLA_BE32, NF_SYNPROXY_OPT_MASK) where the mask is
 *     MSS | WSCALE | SACK_PERM | TIMESTAMP == 0x0F.  NF_SYNPROXY_OPT_ECN
 *     (0x10) is intentionally excluded from the mask and rejected by
 *     the parser — so FLAGS rolls uniformly across 0..0x0F to stay
 *     structurally valid and never trip the mask guard.  All sixteen
 *     combinations of the four allowed bits get reached, including the
 *     zero-bits payload that suppresses every per-option emit branch
 *     and the all-four-set payload that exercises every emit branch in
 *     one shot.
 *
 * The parser is a single-arm dispatch (no NFTA_*_TYPE selector picking
 * between sub-inits the way nft_hash and nft_numgen have).  Chain
 * context (LOCAL_IN / FORWARD priority on a base chain) is enforced by
 * nft_synproxy_validate at validate-hook time, NOT inside do_init — so
 * a NEWRULE carrying this expression on any chain still drives the
 * policy walker and do_init reliably; the validate-hook -EOPNOTSUPP
 * (when present) fires after the structurally-interesting work the
 * slice is here to exercise.
 */
static size_t build_nft_synproxy_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u16 mss_values[] = {
		0U,				/* degenerate zero */
		536U,				/* IPv4 minimum */
		1460U,				/* typical ethernet */
		9000U,				/* jumbo frame */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_mss = ONE_IN(2);
	bool with_wscale = ONE_IN(2);
	bool with_flags = ONE_IN(2);

	/* At least one attr keeps the priv struct off default-zero. */
	if (!with_mss && !with_wscale && !with_flags)
		with_mss = true;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "synproxy");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_mss) {
		__u16 mss = mss_values[rand32() % ARRAY_SIZE(mss_values)];

		off = nla_put_be16(buf, off, cap, NFTA_SYNPROXY_MSS, mss);
		if (!off)
			return 0;
	}

	if (with_wscale) {
		__u8 wscale = (__u8)(rand32() % (TCP_MAX_WSCALE + 1));

		off = nla_put(buf, off, cap, NFTA_SYNPROXY_WSCALE,
			      &wscale, sizeof(wscale));
		if (!off)
			return 0;
	}

	if (with_flags) {
		__u32 flags = rand32() & (NF_SYNPROXY_OPT_MSS |
					  NF_SYNPROXY_OPT_WSCALE |
					  NF_SYNPROXY_OPT_SACK_PERM |
					  NF_SYNPROXY_OPT_TIMESTAMP);

		off = nla_put_be32(buf, off, cap, NFTA_SYNPROXY_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_counter
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_counter.c
 * (nft_counter_init): both NFTA_COUNTER_BYTES and NFTA_COUNTER_PACKETS
 * are individually OPTIONAL u64 attributes (each gated by `if (tb[...])`
 * in the init body) and are read off the wire as big-endian via
 * be64_to_cpu(nla_get_be64()).  Whichever attrs are present become the
 * starting byte / packet counts for the per-cpu counter that
 * nft_counter_eval increments per matched skb.  The policy has no
 * bounds (any u64 is accepted), no flag mask, and no chain-context
 * restriction (no validate hook beyond standard expression validation).
 *
 * Variants per call:
 *   - BYTES rolls across {0, small, INT_MAX (0x7fffffff), U32_MAX
 *     (0xffffffff), near-U64_MAX} via a rand64()-shifted bucket pick so
 *     the per-cpu-counter add arithmetic in nft_counter_eval and the
 *     accumulating dump path in nft_counter_dump see both the
 *     freshly-zeroed counter and the wraparound-imminent counter on the
 *     very first matched packet.
 *   - PACKETS rolls across the same {0, small, INT_MAX, U32_MAX,
 *     near-U64_MAX} spread for the same reason on the packet-count
 *     accumulator.
 *
 * Each attribute is coin-flipped present independently.  If the
 * coin-flips would emit zero attrs the priv struct ends up at
 * default-zero — which is a valid path through the parser but skips the
 * nft_be64_set storage path entirely; PACKETS is forced present in
 * that case so at least one be64 actually flows through the init body.
 */
static size_t build_nft_counter_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_bytes = ONE_IN(2);
	bool with_packets = ONE_IN(2);

	/* At least one attr keeps init off the all-default-zero shortcut. */
	if (!with_bytes && !with_packets)
		with_packets = true;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "counter");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_bytes) {
		__u64 r = rand64();
		__u64 bytes;

		switch (r & 0x7) {
		case 0:
			bytes = 0ULL;
			break;
		case 1:
			bytes = (r >> 3) & 0xffffULL;
			break;
		case 2:
		case 3:
			bytes = 0x7fffffffULL;	/* INT_MAX */
			break;
		case 4:
		case 5:
			bytes = 0xffffffffULL;	/* U32_MAX */
			break;
		default:
			bytes = ~0ULL - ((r >> 3) & 0xffffULL);
			break;
		}
		off = nla_put_be64(buf, off, cap, NFTA_COUNTER_BYTES, bytes);
		if (!off)
			return 0;
	}

	if (with_packets) {
		__u64 r = rand64();
		__u64 packets;

		switch (r & 0x7) {
		case 0:
			packets = 0ULL;
			break;
		case 1:
			packets = (r >> 3) & 0xffffULL;
			break;
		case 2:
		case 3:
			packets = 0x7fffffffULL;	/* INT_MAX */
			break;
		case 4:
		case 5:
			packets = 0xffffffffULL;	/* U32_MAX */
			break;
		default:
			packets = ~0ULL - ((r >> 3) & 0xffffULL);
			break;
		}
		off = nla_put_be64(buf, off, cap, NFTA_COUNTER_PACKETS, packets);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_connlimit
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_connlimit.c
 * (nft_connlimit_do_init): NFTA_CONNLIMIT_COUNT (NLA_U32, big-endian on
 * wire — read via ntohl(nla_get_be32())) is REQUIRED — the kernel
 * returns -EINVAL when the attribute is missing — and seeds the per-rule
 * connection-count cap that nft_connlimit_do_eval's `count > limit`
 * gate compares against.  NFTA_CONNLIMIT_FLAGS (NLA_U32, big-endian) is
 * OPTIONAL: the only legal bit is NFT_CONNLIMIT_F_INV (0x01); any other
 * bit fails `flags & ~NFT_CONNLIMIT_F_INV` with -EOPNOTSUPP before the
 * priv struct is initialised.  When set, the inversion flag flips the
 * eval comparator's verdict via XOR so the over-cap branch becomes the
 * matching side instead of the rejecting side.
 *
 * Variants per call:
 *   - COUNT rolls across {0, 1, small, INT_MAX, U32_MAX} via a rand32()
 *     bucket pick so the eval-time `count > limit` comparator and the
 *     `(count > limit) ^ invert` verdict flip see both the
 *     trivially-tripped (0/1) and the can-never-trip (U32_MAX) ends of
 *     the spectrum on the very first conntrack-bearing skb.
 *   - FLAGS is coin-flipped present.  When present, the value stays
 *     within {0, NFT_CONNLIMIT_F_INV} so do_init's policy walker
 *     reaches the priv-struct setup instead of bailing at the EOPNOTSUPP
 *     gate every time.  ONE_IN(8) of the flag-present emissions
 *     deliberately set an out-of-mask byte (0x02..0xff) so the
 *     EOPNOTSUPP rejection path through the same `flags & ~MASK` check
 *     also gets exercised.
 */
static size_t build_nft_connlimit_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 count_buckets[] = {
		0U,			/* trivially tripped */
		1U,			/* trivially tripped on the second conn */
		8U,			/* small */
		0x7fffffffU,		/* INT_MAX */
		0xffffffffU,		/* U32_MAX — can-never-trip */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 count = count_buckets[rand32() % ARRAY_SIZE(count_buckets)];
	bool with_flags = ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "connlimit");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_CONNLIMIT_COUNT, count);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NFT_CONNLIMIT_F_INV` ->
			 * -EOPNOTSUPP rejection path: pick any non-zero
			 * byte from the disallowed range. */
			flags = 0x02U + (rand32() % 0xfeU);
		} else {
			flags = ONE_IN(2) ? NFT_CONNLIMIT_F_INV : 0U;
		}
		off = nla_put_be32(buf, off, cap, NFTA_CONNLIMIT_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_masq
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_masq.c
 * (nft_masq_init, shared by the nft_masq_ipv4 / nft_masq_ipv6 /
 * nft_masq_inet modules via the same nft_masq_policy[]).  All three
 * attributes are OPTIONAL:
 *   - NFTA_MASQ_FLAGS (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) is a subset of nf_nat_range flags.  The
 *     legal bits are NF_NAT_RANGE_PROTO_RANDOM (0x4),
 *     NF_NAT_RANGE_PERSISTENT (0x8) and NF_NAT_RANGE_PROTO_RANDOM_FULLY
 *     (0x10), i.e. NF_NAT_RANGE_MASK == 0x1c.  Any other bit fails the
 *     `flags & ~NF_NAT_RANGE_MASK` check with -EINVAL before the priv
 *     struct is initialised.
 *   - NFTA_MASQ_REG_PROTO_MIN / NFTA_MASQ_REG_PROTO_MAX (NLA_U32,
 *     big-endian) are register references (NFT_REG_*) bracketing the
 *     source-port rewrite range loaded at eval time.  If MIN is present
 *     and MAX is absent the kernel defaults MAX to MIN; MAX present
 *     without MIN is rejected with -EINVAL.
 * All three attributes absent leaves the expression at zero flags / no
 * port range — a legal but uninteresting pass-through, which is why the
 * coin-flips below favour at least one attribute being present most of
 * the time without forcing it.
 *
 * Variants per call:
 *   - FLAGS coin-flipped present (ONE_IN(2)).  When present, the value
 *     normally stays masked against NF_NAT_RANGE_MASK so do_init's
 *     policy walker reaches the priv-struct setup.  ONE_IN(8) of the
 *     flag-present emissions deliberately use a raw rand32() so the
 *     out-of-mask -EINVAL rejection path through the same
 *     `flags & ~NF_NAT_RANGE_MASK` check also gets exercised.
 *   - MIN coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - MAX is gated on MIN being present (ONE_IN(2) of the MIN-present
 *     emissions): emitting MAX without MIN would always trip the
 *     -EINVAL rejection that is NOT the intended coverage target here.
 */
static size_t build_nft_masq_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_flags = ONE_IN(2);
	bool with_min = ONE_IN(3);
	bool with_max = with_min && ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "masq");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NF_NAT_RANGE_MASK` ->
			 * -EINVAL rejection path with raw garbage that
			 * almost always lights up an out-of-mask bit. */
			flags = rand32();
		} else {
			flags = rand32() & 0x1cU;
		}
		off = nla_put_be32(buf, off, cap, NFTA_MASQ_FLAGS, flags);
		if (!off)
			return 0;
	}

	if (with_min) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_MASQ_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_MASQ_REG_PROTO_MAX, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_redir
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_redir.c
 * (nft_redir_init, shared by the nft_redir_ipv4 / nft_redir_ipv6 /
 * nft_redir_inet modules via the same nft_redir_policy[]).  All three
 * attributes are OPTIONAL:
 *   - NFTA_REDIR_REG_PROTO_MIN / NFTA_REDIR_REG_PROTO_MAX (NLA_U32,
 *     big-endian) are register references (NFT_REG_*) bracketing the
 *     destination-port rewrite range loaded at eval time.  If MIN is
 *     present and MAX is absent the kernel defaults MAX to MIN; MAX
 *     present without MIN is rejected with -EINVAL.
 *   - NFTA_REDIR_FLAGS (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) is a subset of nf_nat_range flags drawn
 *     from the same NF_NAT_RANGE_MASK == 0x1c surface as nft_masq
 *     (NF_NAT_RANGE_PROTO_RANDOM 0x4, NF_NAT_RANGE_PERSISTENT 0x8,
 *     NF_NAT_RANGE_PROTO_RANDOM_FULLY 0x10).  Any other bit fails the
 *     `flags & ~NF_NAT_RANGE_MASK` check with -EINVAL before the priv
 *     struct is initialised.
 * All three attributes absent leaves the expression at zero flags / no
 * port range — a legal but uninteresting pass-through, which is why the
 * coin-flips below favour at least one attribute being present most of
 * the time without forcing it.
 *
 * Variants per call:
 *   - FLAGS coin-flipped present (ONE_IN(2)).  When present, the value
 *     normally stays masked against NF_NAT_RANGE_MASK so do_init's
 *     policy walker reaches the priv-struct setup.  ONE_IN(8) of the
 *     flag-present emissions deliberately use a raw rand32() so the
 *     out-of-mask -EINVAL rejection path through the same
 *     `flags & ~NF_NAT_RANGE_MASK` check also gets exercised.
 *   - MIN coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - MAX is gated on MIN being present (ONE_IN(2) of the MIN-present
 *     emissions): emitting MAX without MIN would always trip the
 *     -EINVAL rejection that is NOT the intended coverage target here.
 */
static size_t build_nft_redir_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_flags = ONE_IN(2);
	bool with_min = ONE_IN(3);
	bool with_max = with_min && ONE_IN(2);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "redir");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_flags) {
		__u32 flags;

		if (ONE_IN(8)) {
			/* Drive the `flags & ~NF_NAT_RANGE_MASK` ->
			 * -EINVAL rejection path with raw garbage that
			 * almost always lights up an out-of-mask bit. */
			flags = rand32();
		} else {
			flags = rand32() & 0x1cU;
		}
		off = nla_put_be32(buf, off, cap, NFTA_REDIR_FLAGS, flags);
		if (!off)
			return 0;
	}

	if (with_min) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_REDIR_REG_PROTO_MIN, reg);
		if (!off)
			return 0;
	}

	if (with_max) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_REDIR_REG_PROTO_MAX, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_tproxy
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_tproxy.c
 * (nft_tproxy_init), which walks nft_tproxy_policy[]:
 *   - NFTA_TPROXY_FAMILY (NLA_U32, big-endian on wire — read via
 *     ntohl(nla_get_be32())) carries the address family of the proxied
 *     destination.  Only NFPROTO_IPV4 (2) and NFPROTO_IPV6 (10) are
 *     accepted; any other value is rejected with -EINVAL before the
 *     priv struct is initialised.
 *   - NFTA_TPROXY_REG_ADDR / NFTA_TPROXY_REG_PORT (NLA_U32, big-endian)
 *     are register references (NFT_REG_*) bracketing the rewritten
 *     dst-addr / dst-port loaded at eval time.  Out-of-range register
 *     values are rejected with -ERANGE through nft_parse_register_load.
 * The kernel allows REG_ADDR and REG_PORT independently when the
 * family-resolution path is OK, so neither is gated on the other.
 *
 * Variants per call:
 *   - FAMILY: ONE_IN(2) emit IPV4 (2), else IPV6 (10) — the two
 *     accepted values that drive the priv-struct setup path.
 *     ONE_IN(8) of the FAMILY emissions deliberately uses a raw
 *     rand32() so the bad-family -EINVAL rejection path also gets
 *     exercised.
 *   - REG_ADDR coin-flipped present (ONE_IN(3)) with the value picked
 *     uniformly across NFT_REG_1..NFT_REG_4.
 *   - REG_PORT coin-flipped present (ONE_IN(3)), same register pick.
 *     Not gated on REG_ADDR — kernel accepts either independently.
 */
static size_t build_nft_tproxy_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_addr = ONE_IN(3);
	bool with_port = ONE_IN(3);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "tproxy");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	{
		__u32 family;

		if (ONE_IN(8)) {
			/* Drive the bad-family -EINVAL rejection path
			 * with raw garbage that almost never lands on
			 * NFPROTO_IPV4 or NFPROTO_IPV6. */
			family = rand32();
		} else if (ONE_IN(2)) {
			family = NFPROTO_IPV4;
		} else {
			family = NFPROTO_IPV6;
		}
		off = nla_put_be32(buf, off, cap, NFTA_TPROXY_FAMILY, family);
		if (!off)
			return 0;
	}

	if (with_addr) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_TPROXY_REG_ADDR, reg);
		if (!off)
			return 0;
	}

	if (with_port) {
		__u32 reg = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap,
				   NFTA_TPROXY_REG_PORT, reg);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_xfrm
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_xfrm.c
 * (nft_xfrm_get_init), which walks nft_xfrm_policy[] and requires all
 * three of NFTA_XFRM_KEY, NFTA_XFRM_DIR and NFTA_XFRM_DREG to be
 * present (-EINVAL otherwise).  ctx->family must be NFPROTO_IPV4 /
 * NFPROTO_IPV6 / NFPROTO_INET (-EOPNOTSUPP otherwise) and is enforced
 * before the policy walk.  NFTA_XFRM_SPNUM (NLA_POLICY_MAX(NLA_BE32,
 * 255)) is OPTIONAL — secpath array index, kernel ntohl()s the wire
 * value.
 *
 * Variants per call:
 *   - KEY: ONE_IN(7) for each of the six valid enum values
 *     (DADDR_IP4=1, DADDR_IP6=2, SADDR_IP4=3, SADDR_IP6=4, REQID=5,
 *     SPI=6) — these drive the success path through the init switch.
 *     ONE_IN(8) of the KEY emissions instead drops a raw rand32()
 *     capped at 255 so UNSPEC (0) and any value above the enum max
 *     exercise the -EINVAL leg.
 *   - DIR: ONE_IN(2) emit XFRM_POLICY_IN (0), else XFRM_POLICY_OUT
 *     (1) — the two accepted values.  ONE_IN(8) of the DIR emissions
 *     instead drops a raw u8 through to exercise the bad-direction
 *     -EINVAL rejection path.
 *   - DREG picked uniformly across NFT_REG_1..NFT_REG_4 inline,
 *     matching the cmp / range / numgen / hash / masq / redir / tproxy
 *     sibling pattern in this file (no shared helper).
 *   - SPNUM coin-flipped present (ONE_IN(3)).  When emitted, ONE_IN(2)
 *     small (0..7) else raw rand32() capped at 255 so both the
 *     reasonable-index and the policy-mask boundary get exercise.
 */
static size_t build_nft_xfrm_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 key;
	__u8 dir;

	if (ONE_IN(8)) {
		/* Drive UNSPEC(0) / >MAX -EINVAL legs through the
		 * NLA_POLICY_MAX cap and the init switch. */
		key = rand32() & 0xff;
	} else {
		switch (rand32() % 7) {
		case 0:
			key = NFT_XFRM_KEY_DADDR_IP4;
			break;
		case 1:
			key = NFT_XFRM_KEY_DADDR_IP6;
			break;
		case 2:
			key = NFT_XFRM_KEY_SADDR_IP4;
			break;
		case 3:
			key = NFT_XFRM_KEY_SADDR_IP6;
			break;
		case 4:
			key = NFT_XFRM_KEY_REQID;
			break;
		case 5:
			key = NFT_XFRM_KEY_SPI;
			break;
		default:
			/* Bucket 6: another raw-cap shot at the
			 * rejection path so the bad-key coverage is
			 * not entirely gated on the ONE_IN(8) above. */
			key = rand32() & 0xff;
			break;
		}
	}

	if (ONE_IN(8)) {
		dir = (__u8)(rand32() & 0xff);
	} else if (ONE_IN(2)) {
		dir = XFRM_POLICY_IN;
	} else {
		dir = XFRM_POLICY_OUT;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "xfrm");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_XFRM_KEY, key);
	if (!off)
		return 0;
	off = nla_put(buf, off, cap, NFTA_XFRM_DIR, &dir, sizeof(dir));
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_XFRM_DREG, dreg);
	if (!off)
		return 0;

	if (ONE_IN(3)) {
		__u32 spnum;

		if (ONE_IN(2))
			spnum = rand32() & 0x7;
		else
			spnum = rand32() & 0xff;
		off = nla_put_be32(buf, off, cap, NFTA_XFRM_SPNUM, spnum);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_netdev expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/netfilter/nft_dup_netdev.c (nft_dup_netdev_init), which walks
 * nft_dup_netdev_policy[] and requires NFTA_DUP_SREG_DEV — a NLA_U32
 * register reference resolved through nft_parse_register_load with
 * NFT_DATA_VALUE size sizeof(int).  Missing returns -EINVAL,
 * out-of-range register values return -ERANGE.  The expression is
 * registered for NFPROTO_NETDEV table family only; emissions in any
 * other family get rejected at expression-type lookup before init
 * runs, which exercises the lookup-side rejection path on top of the
 * netdev-family success path.
 *
 * Variants per call:
 *   - SREG_DEV picked uniformly across NFT_REG_1..NFT_REG_4 inline,
 *     matching the cmp / range / numgen / hash / masq / redir /
 *     tproxy / xfrm sibling pattern in this file (no shared helper).
 *   - ONE_IN(8) of the SREG_DEV emissions instead drops a raw
 *     rand32() so out-of-range register values exercise the -ERANGE
 *     rejection leg in nft_parse_register_load.
 */
static size_t build_nft_dup_netdev_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 sreg_dev;

	if (ONE_IN(8))
		sreg_dev = rand32();
	else
		sreg_dev = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_ipv4 expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/ipv4/netfilter/nft_dup_ipv4.c (nft_dup_ipv4_init), which walks
 * nft_dup_ipv4_policy[] and consumes:
 *   - NFTA_DUP_SREG_ADDR (NLA_U32) — REQUIRED — source register
 *     loading a __be32 IPv4 gateway address (sizeof(struct in_addr)),
 *     resolved through nft_parse_register_load.  Missing returns
 *     -EINVAL, out-of-range register values return -ERANGE.
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — OPTIONAL — source register
 *     loading the int oif; absent leaves oif == -1 in the kernel
 *     branch.
 *
 * The expression is registered for NFPROTO_IPV4 table family only and
 * shares the "dup" expression name with the NFPROTO_NETDEV sibling in
 * net/netfilter/nft_dup_netdev.c — the expression-type lookup
 * disambiguates by ctx->family.  Emissions on non-IPv4 chains get
 * rejected at lookup before init runs, exercising the -ENOPROTOOPT
 * leg on top of the IPv4-family success path.  The dispatch loop in
 * this file is family-blind today; the family-mismatch coverage is
 * intentional kernel-side gating.
 *
 * Variants per call:
 *   - SREG_ADDR always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev
 *     sibling pattern in this file (no shared helper).
 *     ONE_IN(8) instead drops a raw rand32() so out-of-range register
 *     values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load.
 *   - SREG_DEV coin-flipped present (ONE_IN(2)).  When emitted,
 *     picked uniformly across NFT_REG_1..NFT_REG_4 with the same
 *     ONE_IN(8) raw-rand32() escape hatch for -ERANGE coverage.
 */
static size_t build_nft_dup_ipv4_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_dev = ONE_IN(2);
	__u32 sreg_addr, sreg_dev;

	if (ONE_IN(8))
		sreg_addr = rand32();
	else
		sreg_addr = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_ADDR, sreg_addr);
	if (!off)
		return 0;

	if (with_dev) {
		if (ONE_IN(8))
			sreg_dev = rand32();
		else
			sreg_dev = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_dup_ipv6 expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/ipv6/netfilter/nft_dup_ipv6.c (nft_dup_ipv6_init), which walks
 * nft_dup_ipv6_policy[] and consumes:
 *   - NFTA_DUP_SREG_ADDR (NLA_U32) — REQUIRED — source register
 *     loading a struct in6_addr IPv6 gateway address
 *     (sizeof(struct in6_addr) == 16), resolved through
 *     nft_parse_register_load with NFT_DATA_VALUE.  Missing returns
 *     -EINVAL up front; out-of-range register values are rejected
 *     with -ERANGE inside nft_parse_register_load, and the
 *     16-byte load size makes -ERANGE easier to hit than the
 *     IPv4 sibling because high register indices have less room
 *     left in the register file.
 *   - NFTA_DUP_SREG_DEV (NLA_U32) — OPTIONAL — source register
 *     loading the int oif; absent leaves oif == -1 in the kernel
 *     branch.
 *
 * The expression is registered for NFPROTO_IPV6 table family only and
 * shares the "dup" expression name with the NFPROTO_NETDEV and
 * NFPROTO_IPV4 siblings in net/netfilter/nft_dup_netdev.c and
 * net/ipv4/netfilter/nft_dup_ipv4.c — the expression-type lookup
 * disambiguates by ctx->family.  Emissions on non-IPv6 chains
 * (ipv4 / inet / arp / bridge / netdev) get rejected at
 * expression-type lookup with -ENOPROTOOPT before init runs, which
 * exercises the family-mismatch leg on top of the IPv6-family success
 * path.  The dispatch loop in this file is family-blind today; the
 * family-mismatch coverage is intentional kernel-side gating.
 *
 * Variants per call:
 *   - SREG_ADDR always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev /
 *     dup_ipv4 sibling pattern in this file (no shared helper).
 *     ONE_IN(8) instead drops a raw rand32() so out-of-range register
 *     values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load — particularly relevant here because
 *     the 16-byte in6_addr load tightens the upper bound on which
 *     register indices fit.
 *   - SREG_DEV coin-flipped present (ONE_IN(2)).  When emitted,
 *     picked uniformly across NFT_REG_1..NFT_REG_4 with the same
 *     ONE_IN(8) raw-rand32() escape hatch for -ERANGE coverage.
 */
static size_t build_nft_dup_ipv6_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_dev = ONE_IN(2);
	__u32 sreg_addr, sreg_dev;

	if (ONE_IN(8))
		sreg_addr = rand32();
	else
		sreg_addr = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dup");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_ADDR, sreg_addr);
	if (!off)
		return 0;

	if (with_dev) {
		if (ONE_IN(8))
			sreg_dev = rand32();
		else
			sreg_dev = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_DUP_SREG_DEV, sreg_dev);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid
 * nft_fwd_netdev expression into buf at off, returning the new offset
 * (or 0 on overflow).  Reaches the validator in
 * net/netfilter/nft_fwd_netdev.c, which has two init paths sharing
 * the NFTA_FWD_* uapi enum:
 *   - nft_fwd_netdev_init (bare-forward arm): consumes only
 *     NFTA_FWD_SREG_DEV (NLA_U32) — REQUIRED — source register loading
 *     the int oif, resolved through nft_parse_register_load with
 *     NFT_DATA_VALUE size sizeof(int).  Missing returns -EINVAL up
 *     front; out-of-range register values are rejected with -ERANGE.
 *   - nft_fwd_neigh_init (forward-with-neigh-resolve arm): selected
 *     by the kernel when NFTA_FWD_SREG_ADDR is present.  Consumes
 *     NFTA_FWD_SREG_DEV (REQUIRED, same as above), NFTA_FWD_SREG_ADDR
 *     (NLA_U32) — source register loading struct in_addr (4 bytes)
 *     or struct in6_addr (16 bytes), and NFTA_FWD_NFPROTO (NLA_U32) —
 *     REQUIRED for this arm — carrying NFPROTO_IPV4 or NFPROTO_IPV6
 *     to pick the address load size.  Other family values are
 *     rejected on the address-load side.
 *
 * The expression is registered for NFPROTO_NETDEV table family only
 * and uses the expression name "fwd" (distinct from the "dup" name
 * shared by the nft_dup_* siblings).  Emissions on any other table
 * family are rejected at expression-type lookup with -ENOPROTOOPT
 * before init runs — that exercises the family-mismatch leg on top of
 * the netdev-family success path.  The dispatch loop in this file is
 * family-blind today; the family-mismatch coverage is intentional
 * kernel-side gating.
 *
 * Variants per call:
 *   - SREG_DEV always emitted (the required-gate); picked uniformly
 *     across NFT_REG_1..NFT_REG_4 inline, matching the cmp / range /
 *     numgen / hash / masq / redir / tproxy / xfrm / dup_netdev /
 *     dup_ipv4 / dup_ipv6 sibling pattern in this file (no shared
 *     helper).  ONE_IN(8) instead drops a raw rand32() so out-of-range
 *     register values exercise the -ERANGE rejection leg in
 *     nft_parse_register_load.
 *   - with_neigh coin-flipped (ONE_IN(2)).  When false, only SREG_DEV
 *     is emitted and the kernel takes the bare-forward init path;
 *     when true, SREG_ADDR + NFPROTO are also emitted and the kernel
 *     switches to nft_fwd_neigh_init.  Both arms are interesting.
 *     SREG_ADDR uses the same NFT_REG_1..NFT_REG_4 / ONE_IN(8) raw
 *     rand32() escape hatch as SREG_DEV.  NFPROTO is picked uniformly
 *     across {NFPROTO_IPV4, NFPROTO_IPV6}, with a ONE_IN(8) raw
 *     rand32() escape that hands the kernel a bogus family so the
 *     address-load size selection rejects it.
 */
static size_t build_nft_fwd_netdev_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool with_neigh = ONE_IN(2);
	__u32 sreg_dev, sreg_addr, nfproto;

	if (ONE_IN(8))
		sreg_dev = rand32();
	else
		sreg_dev = NFT_REG_1 + (rand32() % 4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "fwd");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_FWD_SREG_DEV, sreg_dev);
	if (!off)
		return 0;

	if (with_neigh) {
		if (ONE_IN(8))
			sreg_addr = rand32();
		else
			sreg_addr = NFT_REG_1 + (rand32() % 4);

		off = nla_put_be32(buf, off, cap, NFTA_FWD_SREG_ADDR, sreg_addr);
		if (!off)
			return 0;

		if (ONE_IN(8))
			nfproto = rand32();
		else if (ONE_IN(2))
			nfproto = NFPROTO_IPV4;
		else
			nfproto = NFPROTO_IPV6;

		off = nla_put_be32(buf, off, cap, NFTA_FWD_NFPROTO, nfproto);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_last
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_last.c
 * (nft_last_init) — both attributes are OPTIONAL.  NFTA_LAST_SET
 * (NLA_U32, big-endian on wire — read via ntohl(nla_get_be32())) is a
 * 0/1 flag controlling whether the 'last seen' state is pre-seeded as
 * already set.  NFTA_LAST_MSECS (NLA_U64, big-endian on wire — fed
 * through nf_msecs_to_jiffies64, which rejects negative-from-jiffies
 * wraps and oversized future-jiffies values) is only consumed when
 * SET == 1; init treats MSECS-with-SET==0 as a no-op for the seed.
 * The eval path just stores `jiffies` and bumps `set`, and dump
 * round-trips both fields, so the interesting validator coverage is
 * at init time.
 *
 * Bucket distribution per call (rand32() % 8):
 *   - both attributes absent (~1/4): default-init path, neither
 *     attribute seeds anything.
 *   - SET only present, value 0 (~1/8): policy walker consumes SET
 *     but the seed branch stays dormant.
 *   - SET only present, value 1 (~1/4): seeds 'set' with the default
 *     jiffies offset since MSECS is missing.
 *   - SET == 1 + MSECS small {0, 1, 1000} (~1/4): drives the
 *     fast-path through nf_msecs_to_jiffies64 with values that round
 *     to a sub-second jiffies offset.
 *   - SET == 1 + MSECS large {INT_MAX, U32_MAX, U64_MAX} as a 64-bit
 *     BE value (~1/8): drives nf_msecs_to_jiffies64's range-rejection
 *     paths for oversized future-jiffies and negative-from-jiffies
 *     wraps.
 */
static size_t build_nft_last_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u64 msecs_small[] = { 0ULL, 1ULL, 1000ULL };
	static const __u64 msecs_large[] = {
		0x7fffffffULL,		/* INT_MAX */
		0xffffffffULL,		/* U32_MAX */
		0xffffffffffffffffULL,	/* U64_MAX */
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 bucket = rand32() & 0x7;
	bool with_set = false;
	bool with_msecs = false;
	__u32 set_val = 0;
	__u64 msecs_val = 0;

	switch (bucket) {
	case 0:
	case 1:
		/* both attributes absent — default-init shape */
		break;
	case 2:
		with_set = true;
		set_val = 0;
		break;
	case 3:
	case 4:
		with_set = true;
		set_val = 1;
		break;
	case 5:
	case 6:
		with_set = true;
		set_val = 1;
		with_msecs = true;
		msecs_val = msecs_small[rand32() % ARRAY_SIZE(msecs_small)];
		break;
	default:
		with_set = true;
		set_val = 1;
		with_msecs = true;
		msecs_val = msecs_large[rand32() % ARRAY_SIZE(msecs_large)];
		break;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "last");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (with_set) {
		off = nla_put_be32(buf, off, cap, NFTA_LAST_SET, set_val);
		if (!off)
			return 0;
	}

	if (with_msecs) {
		off = nla_put_be64(buf, off, cap, NFTA_LAST_MSECS, msecs_val);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_rt
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_rt.c
 * (nft_rt_init -> priv->key dispatch, then nft_rt_validate at commit
 * time).  Both NFTA_RT_DREG (NLA_U32) and NFTA_RT_KEY
 * (NLA_POLICY_MAX(NLA_BE32, 255)) are MANDATORY.
 *
 * KEY distribution per call (rand32() % 8):
 *   - CLASSID  ~1/4 (buckets 0,1): always valid across IPv4/IPv6/INET.
 *   - NEXTHOP4 ~1/4 (buckets 2,3): always valid.
 *   - NEXTHOP6 ~1/4 (buckets 4,5): always valid.
 *   - XFRM     ~1/8 (bucket  6):   always valid.
 *   - TCPMSS   ~1/8 (bucket  7):   only valid in FORWARD/LOCAL_OUT/
 *     POST_ROUTING hooks; nft_rt_validate rejects other hooks with
 *     -EOPNOTSUPP, which is the rejection-path coverage we want.
 *
 * DREG is picked uniformly from NFT_REG_1..NFT_REG_4 inline since the
 * existing emitters in this file each open-code their own register
 * pick (no shared helper).  No upper-bound clamping on KEY beyond what
 * the kernel mask enforces — picking from the valid enum exercises
 * the success path, and the kernel's own switch statement in
 * nft_rt_init rejects out-of-enum keys with -EINVAL when stale-host
 * headers expand to unknown values.
 */
static size_t build_nft_rt_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 bucket = rand32() & 0x7;
	__u32 key;

	switch (bucket) {
	case 0:
	case 1:
		key = NFT_RT_CLASSID;
		break;
	case 2:
	case 3:
		key = NFT_RT_NEXTHOP4;
		break;
	case 4:
	case 5:
		key = NFT_RT_NEXTHOP6;
		break;
	case 6:
		key = NFT_RT_XFRM;
		break;
	default:
		key = NFT_RT_TCPMSS;
		break;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "rt");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_RT_KEY, key);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_RT_DREG, dreg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_fib
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_fib.c
 * (nft_fib_init -> cross-field constraint checks, then nft_fib_validate
 * at commit time for hook restrictions).  All three of NFTA_FIB_DREG
 * (NLA_U32), NFTA_FIB_RESULT (NLA_U32), and NFTA_FIB_FLAGS (NLA_U32)
 * are MANDATORY.
 *
 * RESULT distribution per call (rand32() % 3) — roughly 1/3 each:
 *   - OIF       (1): valid only on PRE_ROUTING/LOCAL_IN/FORWARD/
 *     LOCAL_OUT/POST_ROUTING hooks (nft_fib_validate -> -EOPNOTSUPP
 *     elsewhere).
 *   - OIFNAME   (2): same hook restriction as OIF.
 *   - ADDRTYPE  (3): no hook restriction unless OIF flag is set; the
 *     only RESULT that legally combines with NFTA_FIB_F_PRESENT.
 *
 * FLAGS distribution per call:
 *   - SADDR / DADDR slot (rand32() % 16): bucket 0 leaves NEITHER set
 *     (~1/16, drives -EINVAL in nft_fib_init), bucket 1 sets BOTH
 *     (~1/16, also -EINVAL), buckets 2..15 set exactly one (14/16
 *     total, split 7/7 between SADDR and DADDR by parity for a clean
 *     50/50 inside the in-policy slice).
 *   - MARK (~1/4 via ONE_IN(4)): legal when CONFIG_NF_CONNTRACK_MARK
 *     is on; rejected with -EOPNOTSUPP otherwise.
 *   - IIF / OIF (mutually exclusive, ~1/8 each via rand32() % 16
 *     buckets 0,1 -> IIF and 2,3 -> OIF; the kernel rejects -EINVAL
 *     if both are ever set, which can't happen here).
 *   - PRESENT (~1/4 via ONE_IN(4)) ONLY when RESULT=ADDRTYPE; on the
 *     other two RESULT values nft_fib_init returns -EOPNOTSUPP, so we
 *     deliberately leave PRESENT off to keep that bucket exercising
 *     the success path.
 *
 * DREG is picked uniformly from NFT_REG_1..NFT_REG_4 inline since the
 * existing emitters in this file each open-code their own register
 * pick (no shared helper).  No upper-bound clamping on RESULT or FLAGS
 * beyond what the kernel mask enforces — out-of-enum RESULT values
 * are rejected by nft_fib_init's switch statement with -EINVAL, which
 * is intended coverage if a stale-host header expands an unknown
 * value.
 */
static size_t build_nft_fib_expr(unsigned char *buf, size_t off, size_t cap)
{
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	__u32 result_bucket = rand32() % 3;
	__u32 saddr_daddr_bucket = rand32() % 16;
	__u32 iif_oif_bucket = rand32() % 16;
	__u32 result;
	__u32 flags = 0;

	switch (result_bucket) {
	case 0:
		result = NFT_FIB_RESULT_OIF;
		break;
	case 1:
		result = NFT_FIB_RESULT_OIFNAME;
		break;
	default:
		result = NFT_FIB_RESULT_ADDRTYPE;
		break;
	}

	switch (saddr_daddr_bucket) {
	case 0:
		break;
	case 1:
		flags |= NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR;
		break;
	default:
		if (saddr_daddr_bucket & 1)
			flags |= NFTA_FIB_F_DADDR;
		else
			flags |= NFTA_FIB_F_SADDR;
		break;
	}

	if (ONE_IN(4))
		flags |= NFTA_FIB_F_MARK;

	switch (iif_oif_bucket) {
	case 0:
	case 1:
		flags |= NFTA_FIB_F_IIF;
		break;
	case 2:
	case 3:
		flags |= NFTA_FIB_F_OIF;
		break;
	default:
		break;
	}

	if (result == NFT_FIB_RESULT_ADDRTYPE && ONE_IN(4))
		flags |= NFTA_FIB_F_PRESENT;

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "fib");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_FIB_RESULT, result);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_FIB_FLAGS, flags);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_FIB_DREG, dreg);
	if (!off)
		return 0;

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_exthdr
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the 4-arm parser in net/netfilter/nft_exthdr.c —
 * nft_exthdr_init dispatches on NFTA_EXTHDR_OP to one of
 * nft_exthdr_ipv6_init (OP_IPV6, the default when the attr is absent),
 * nft_exthdr_tcp_init (OP_TCPOPT, the only arm with a write variant via
 * NFTA_EXTHDR_SREG), nft_exthdr_ipv4_init (OP_IPV4) and
 * nft_exthdr_sctp_init (OP_SCTP).  Mandatory wire attrs are TYPE
 * (NLA_U8 — semantics depend on OP), OFFSET (NLA_U32 big-endian, byte
 * offset within the parsed header), LEN (NLA_U32 big-endian, validator
 * clamps at 127) plus exactly one of DREG (read) or SREG (write).
 *
 * OP distribution per call (rand32() % 4) — uniform across the four
 * kernel arms so each init helper sees an equal share of inbound
 * messages.  TYPE per arm is picked from an arm-appropriate set so the
 * post-OP switch lands on a recognised value:
 *   - OP_IPV6   : HOPOPT(0), ROUTING(43), FRAGMENT(44), DSTOPT(60),
 *                 MOBILITY(135) — drives nft_exthdr_ipv6_eval's
 *                 ipv6_find_hdr lookup with a real protocol number.
 *   - OP_TCPOPT : NOP(1), MSS(2), WSCALE(3), SACK_PERM(4), SACK(5),
 *                 TIMESTAMP(8), MD5SIG(19), AO(29), FASTOPEN(34) —
 *                 the kinds nft_exthdr_tcp_eval inspects.
 *   - OP_IPV4   : EOL(0), NOP(1), RR(7), TS(68), RA(148) — reachable
 *                 IPv4 option types parsed by nft_exthdr_ipv4_eval.
 *   - OP_SCTP   : DATA(0), INIT(1), INIT_ACK(2), SACK(3), HEARTBEAT(4),
 *                 HEARTBEAT_ACK(5) — chunk types walked by
 *                 nft_exthdr_sctp_eval.
 *
 * OFFSET is 0..63 (well within every arm's accept range) and LEN is
 * 1..16 (clear of the validator's 127 clamp).  DREG vs SREG split:
 * SREG is legal only on OP_TCPOPT, so for any other OP DREG is forced;
 * on OP_TCPOPT a coin flip (ONE_IN(4)) picks SREG to drive the write
 * arm, otherwise DREG drives the read arm.  Register value is uniform
 * across NFT_REG_1..NFT_REG_4 inline (no shared helper, matching the
 * surrounding emitters).  FLAGS is read-only territory: NFT_EXTHDR_F_PRESENT
 * is emitted ONE_IN(4) but only when SREG is NOT set — combining FLAGS
 * with SREG fails -EINVAL, and the rejection-path bucket is intentionally
 * kept narrow so the success path dominates.
 *
 * History: CVE-2022-1015 was a signed-integer wrap in nft_exthdr_init's
 * register-bound check on this expression; this emitter keeps the
 * validator path warm so any future regression in the same area
 * surfaces under fuzz.
 */
static size_t build_nft_exthdr_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u8 ipv6_types[] = { 0, 43, 44, 60, 135 };
	static const __u8 tcpopt_types[] = { 1, 2, 3, 4, 5, 8, 19, 29, 34 };
	static const __u8 ipv4_types[] = { 0, 1, 7, 68, 148 };
	static const __u8 sctp_types[] = { 0, 1, 2, 3, 4, 5 };
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 op_bucket = rand32() % 4;
	__u32 op;
	__u8 type;
	__u32 offset = rand32() % 64;
	__u32 len = 1 + (rand32() % 16);
	__u32 reg = NFT_REG_1 + (rand32() % 4);
	bool use_sreg = false;
	bool emit_flags;

	switch (op_bucket) {
	case 0:
	default:
		op = NFT_EXTHDR_OP_IPV6;
		type = ipv6_types[rand32() % ARRAY_SIZE(ipv6_types)];
		break;
	case 1:
		op = NFT_EXTHDR_OP_TCPOPT;
		type = tcpopt_types[rand32() % ARRAY_SIZE(tcpopt_types)];
		use_sreg = ONE_IN(4);
		break;
	case 2:
		op = NFT_EXTHDR_OP_IPV4;
		type = ipv4_types[rand32() % ARRAY_SIZE(ipv4_types)];
		break;
	case 3:
		op = NFT_EXTHDR_OP_SCTP;
		type = sctp_types[rand32() % ARRAY_SIZE(sctp_types)];
		break;
	}

	emit_flags = !use_sreg && ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "exthdr");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (use_sreg)
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_SREG, reg);
	else
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_DREG, reg);
	if (!off)
		return 0;

	off = nla_put(buf, off, cap, NFTA_EXTHDR_TYPE, &type, sizeof(type));
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_OFFSET, offset);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_LEN, len);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_OP, op);
	if (!off)
		return 0;

	if (emit_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_EXTHDR_FLAGS,
				   NFT_EXTHDR_F_PRESENT);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_osf
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_osf.c
 * (nft_osf_init): NFTA_OSF_DREG is mandatory (NLA_BE32 register
 * destination capped at NFT_REG32_MAX, written across two 16-byte
 * register slots so the genre string up to NFT_OSF_MAXGENRELEN fits),
 * NFTA_OSF_TTL is optional (NLA_U8 — init only accepts 0..2, any value
 * above 2 trips -EINVAL) and NFTA_OSF_FLAGS is optional (NLA_BE32 —
 * init only accepts the exact value NFT_OSF_F_VERSION (0x01); any other
 * bit pattern, including 0, is rejected with -EINVAL).  nft_osf is
 * built CONFIG_NFT_OSF=m on the fuzz-box, so the policy validation
 * path only runs once the module is loaded — the emitter still produces
 * structurally-valid netlink either way.
 *
 * Variants per call:
 *   - DREG picks uniformly from NFT_REG_1..NFT_REG_4 so the genre
 *     string lands in whatever register a following cmp/range/bitwise
 *     emit will read against.
 *   - TTL is rolled ONE_IN(2); when attached the in-policy values
 *     {0, 1, 2} are weighted at ~7/8 (uniform across the three) so the
 *     success path dominates, with ~1/8 falling out to a uniform draw
 *     across the rejection range 3..255 to keep the -EINVAL bucket in
 *     nft_osf_init warm.
 *   - FLAGS is rolled ONE_IN(3); when attached the in-policy value
 *     NFT_OSF_F_VERSION is weighted at ~3/4 and the remaining ~1/4
 *     rolls a uniform draw across out-of-policy values
 *     {0, 0x2, 0x80, 0xff, 0xffffffff} so the exact-equals check in
 *     nft_osf_init also sees rejection traffic.
 */
static size_t build_nft_osf_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 bad_flags[] = {
		0, 0x2, 0x80, 0xff, 0xffffffffU,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 dreg = NFT_REG_1 + (rand32() % 4);
	bool with_ttl = ONE_IN(2);
	bool with_flags = ONE_IN(3);
	__u8 ttl;
	__u32 flags;

	if (with_ttl) {
		if (ONE_IN(8))
			ttl = 3 + (rand32() % 253);	/* 3..255: -EINVAL */
		else
			ttl = (__u8)(rand32() % 3);	/* 0..2: in policy */
	} else {
		ttl = 0;
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = bad_flags[rand32() % ARRAY_SIZE(bad_flags)];
		else
			flags = NFT_OSF_F_VERSION;
	} else {
		flags = 0;
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "osf");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_OSF_DREG, dreg);
	if (!off)
		return 0;

	if (with_ttl) {
		off = nla_put(buf, off, cap, NFTA_OSF_TTL, &ttl, sizeof(ttl));
		if (!off)
			return 0;
	}

	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_OSF_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Emit one NFTA_LIST_ELEM containing a structurally-valid nft_queue
 * expression into buf at off, returning the new offset (or 0 on
 * overflow).  Reaches the validator in net/netfilter/nft_queue.c — a
 * two-arm parser dispatched by nft_queue_init on whether
 * NFTA_QUEUE_SREG_QNUM is present:
 *
 *   STATIC arm (no SREG_QNUM):
 *     NFTA_QUEUE_NUM is mandatory (NLA_U16, BE16 on wire — the queue
 *     index).  NFTA_QUEUE_TOTAL is optional (NLA_U16, BE16 on wire,
 *     default 1, fanout count).  Init enforces
 *     priv->queuenum + priv->queues_total - 1 <= USHRT_MAX or
 *     -ERANGE.  NFTA_QUEUE_FLAGS is optional (NLA_U16, BE16 on wire);
 *     init checks (flags & ~NFT_QUEUE_FLAG_MASK) == 0 — any bit
 *     outside NFT_QUEUE_FLAG_BYPASS | NFT_QUEUE_FLAG_CPU_FANOUT trips
 *     -EINVAL.
 *
 *   SREG arm (SREG_QNUM present, no NUM):
 *     nft_queue_sreg_init reads NFTA_QUEUE_SREG_QNUM as a u32 register
 *     source (validated by nft_parse_register_load against
 *     NFT_REG32_00..NFT_REG32_15).  FLAGS still optional and validated
 *     against NFT_QUEUE_FLAG_MASK on this path too.
 *
 *   NUM and SREG_QNUM are mutually exclusive — passing both yields
 *   -EINVAL.  This emitter never produces that shape; the rejection
 *   path is left for a future bad-shape childop.
 *
 * Variants per call:
 *   - Arm picked uniformly via ONE_IN(2): STATIC vs SREG.
 *   - STATIC.NUM: drawn so NUM + (TOTAL ? TOTAL : 1) - 1 <= USHRT_MAX.
 *     With no TOTAL, NUM is uniform 0..0xFFFE.  With TOTAL = T, NUM is
 *     uniform 0..(0xFFFF - T) so the success path stays in policy.
 *   - STATIC.TOTAL: ONE_IN(2); when attached, uniform 1..16 to keep
 *     fanout small while still exercising the multi-queue path.
 *   - STATIC/SREG.FLAGS: ONE_IN(3); when attached, ~3/4 a uniform
 *     in-policy draw across {0, NFT_QUEUE_FLAG_BYPASS,
 *     NFT_QUEUE_FLAG_CPU_FANOUT, NFT_QUEUE_FLAG_MASK} so the success
 *     path dominates, and ~1/4 a uniform out-of-policy draw across
 *     {0x04, 0x08, 0x40, 0x80, 0xff, 0xfffe, 0xffff} to keep the
 *     ~NFT_QUEUE_FLAG_MASK rejection bucket in nft_queue_init warm.
 *   - SREG.SREG_QNUM: uniform across NFT_REG32_00..NFT_REG32_15.
 */
static size_t build_nft_queue_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u16 good_flags[] = {
		0,
		NFT_QUEUE_FLAG_BYPASS,
		NFT_QUEUE_FLAG_CPU_FANOUT,
		NFT_QUEUE_FLAG_MASK,
	};
	static const __u16 bad_flags[] = {
		0x04, 0x08, 0x40, 0x80, 0xff, 0xfffe, 0xffff,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool sreg_arm = ONE_IN(2);
	bool with_total = !sreg_arm && ONE_IN(2);
	bool with_flags = ONE_IN(3);
	__u16 num = 0, total = 0, flags = 0;
	__u32 sreg_qnum = 0;

	if (sreg_arm) {
		sreg_qnum = NFT_REG32_00 + (rand32() % 16);
	} else {
		if (with_total) {
			total = (__u16)(1 + (rand32() % 16));
			num = (__u16)(rand32() % (0x10000U - total));
		} else {
			num = (__u16)(rand32() % 0xFFFFU);
		}
	}

	if (with_flags) {
		if (ONE_IN(4))
			flags = bad_flags[rand32() % ARRAY_SIZE(bad_flags)];
		else
			flags = good_flags[rand32() % ARRAY_SIZE(good_flags)];
	}

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "queue");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (sreg_arm) {
		off = nla_put_be32(buf, off, cap, NFTA_QUEUE_SREG_QNUM,
				   sreg_qnum);
		if (!off)
			return 0;
	} else {
		off = nla_put_be16(buf, off, cap, NFTA_QUEUE_NUM, num);
		if (!off)
			return 0;
		if (with_total) {
			off = nla_put_be16(buf, off, cap, NFTA_QUEUE_TOTAL,
					   total);
			if (!off)
				return 0;
		}
	}

	if (with_flags) {
		off = nla_put_be16(buf, off, cap, NFTA_QUEUE_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_immediate expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "immediate"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_IMMEDIATE_DREG = NFT_REG_VERDICT | NFT_REG_1..NFT_REG_4
 *       NFTA_IMMEDIATE_DATA (nested)
 *         if DREG == NFT_REG_VERDICT:
 *           NFTA_DATA_VERDICT (nested)
 *             NFTA_VERDICT_CODE = NF_DROP|NF_ACCEPT|NFT_RETURN|NFT_CONTINUE
 *         else:
 *           NFTA_DATA_VALUE = LEN bytes random
 *
 * DREG picks NFT_REG_VERDICT (verdict carrier) ONE_IN(2), else uniform
 * across NFT_REG_1..NFT_REG_4 (constant-data loader).  When carrying a
 * verdict, terminal verdict codes are picked uniformly from
 * {NF_DROP, NF_ACCEPT, NFT_RETURN, NFT_CONTINUE} — this exercises the
 * non-jumping verdict branches in nft_immediate_eval that the hard-coded
 * NFT_JUMP/NFT_GOTO verdict element below never visits.  Constant-data
 * width coin-flips across {1, 2, 4, 8, 16} matching the cmp/bitwise
 * register-width spread.
 */
static size_t build_nft_immediate_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 lens[] = { 1, 2, 4, 8, 16 };
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 verdicts[] = {
		NF_DROP, NF_ACCEPT, NFT_RETURN, NFT_CONTINUE,
	};
	struct nlattr *elem, *expr_data, *imm_data;
	size_t elem_off, expr_data_off, imm_data_off;
	__u32 dreg = ONE_IN(2)
		? NFT_REG_VERDICT
		: regs[rand32() % ARRAY_SIZE(regs)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "immediate");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_be32(buf, off, cap, NFTA_IMMEDIATE_DREG, dreg);
	if (!off)
		return 0;

	imm_data_off = off;
	off = nla_put(buf, off, cap, NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (dreg == NFT_REG_VERDICT) {
		struct nlattr *verdict;
		size_t verdict_off;
		__u32 code = verdicts[rand32() % ARRAY_SIZE(verdicts)];

		verdict_off = off;
		off = nla_put(buf, off, cap,
			      NFTA_DATA_VERDICT | NLA_F_NESTED, NULL, 0);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_VERDICT_CODE, code);
		if (!off)
			return 0;
		verdict = (struct nlattr *)(buf + verdict_off);
		verdict->nla_len = (unsigned short)(off - verdict_off);
	} else {
		__u32 len_v = lens[rand32() % ARRAY_SIZE(lens)];
		unsigned char bytes[16];

		generate_rand_bytes(bytes, len_v);
		off = nla_put(buf, off, cap, NFTA_DATA_VALUE, bytes, len_v);
		if (!off)
			return 0;
	}

	imm_data = (struct nlattr *)(buf + imm_data_off);
	imm_data->nla_len = (unsigned short)(off - imm_data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_dynset expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "dynset"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_DYNSET_SET_NAME = anon set built by build_newset
 *       NFTA_DYNSET_SET_ID   = matching cookie (in-batch resolution)
 *       NFTA_DYNSET_OP       = ADD | UPDATE | DELETE
 *       NFTA_DYNSET_SREG_KEY = NFT_REG_1..NFT_REG_4
 *       NFTA_DYNSET_SREG_DATA (1-in-2)  = NFT_REG_1..NFT_REG_4
 *       NFTA_DYNSET_TIMEOUT  (1-in-3)   = small u64 ms
 *       NFTA_DYNSET_FLAGS    (1-in-4)   = NFT_DYNSET_F_INV
 *
 * Reaches the validator in net/netfilter/nft_dynset.c (nft_dynset_init)
 * — set-binding lookup, op enum range check, sreg/timeout validation,
 * and the inv-flag gate that only makes sense for OP_DELETE.  dynset is
 * the runtime-mutating set update primitive used by conntrack helpers,
 * rate limiters, and the limit/quota convenience expressions; it has
 * been a recurring fuzz target (race against set teardown is the same
 * commit-vs-datapath window CVE-2024-1086 hung off).  Heavier weight
 * than the logging exprs because dynset mutates kernel state on every
 * datapath packet rather than just emitting a side effect.
 *
 * NFTA_DYNSET_EXPR / NFTA_DYNSET_EXPRESSIONS (nested expression
 * containers attached to each new set element) are intentionally not
 * emitted here — they need their own slice with care around the
 * stateful-vs-stateless expression policy.
 */
static size_t build_nft_dynset_expr(unsigned char *buf, size_t off,
				    size_t cap, const char *set_name,
				    __u32 set_id)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 ops[] = {
		NFT_DYNSET_OP_ADD,
		NFT_DYNSET_OP_UPDATE,
		NFT_DYNSET_OP_DELETE,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	__u32 op = ops[rand32() % ARRAY_SIZE(ops)];
	__u32 sreg_key = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 sreg_data = regs[rand32() % ARRAY_SIZE(regs)];
	__u32 flags = ONE_IN(4) ? NFT_DYNSET_F_INV : 0;
	bool with_sreg_data = ONE_IN(2);
	bool with_timeout = ONE_IN(3);
	bool with_flags = ONE_IN(4);

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "dynset");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_DYNSET_SET_NAME, set_name);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_SET_ID, set_id);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_OP, op);
	if (!off)
		return 0;
	off = nla_put_be32(buf, off, cap, NFTA_DYNSET_SREG_KEY, sreg_key);
	if (!off)
		return 0;
	if (with_sreg_data) {
		off = nla_put_be32(buf, off, cap,
				   NFTA_DYNSET_SREG_DATA, sreg_data);
		if (!off)
			return 0;
	}
	if (with_timeout) {
		__u64 timeout_ms = (__u64)((rand32() % 1000) + 1);
		__u64 be_t = ((__u64)htonl((__u32)(timeout_ms >> 32))) |
			     (((__u64)htonl((__u32)timeout_ms)) << 32);

		off = nla_put(buf, off, cap, NFTA_DYNSET_TIMEOUT,
			      &be_t, sizeof(be_t));
		if (!off)
			return 0;
	}
	if (with_flags) {
		off = nla_put_be32(buf, off, cap, NFTA_DYNSET_FLAGS, flags);
		if (!off)
			return 0;
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * Structurally-valid nft_ct expression element.  Net layout:
 *   NFTA_LIST_ELEM (nested)
 *     NFTA_EXPR_NAME = "ct"
 *     NFTA_EXPR_DATA (nested)
 *       NFTA_CT_KEY = NFT_CT_*
 *       LOAD mode:
 *         NFTA_CT_DREG = NFT_REG_1..NFT_REG_4
 *         NFTA_CT_DIRECTION (1-in-2 for tuple keys) = ORIGINAL|REPLY
 *       STORE mode:
 *         NFTA_CT_SREG = NFT_REG_1..NFT_REG_4
 *
 * Reaches the validator in net/netfilter/nft_ct.c (nft_ct_get_init for
 * LOAD, nft_ct_set_init for STORE).  The per-key dispatch table maps
 * NFTA_CT_KEY to a load/store helper; STORE is rejected outright on
 * read-only keys, and the tuple-key handlers honour NFTA_CT_DIRECTION
 * to pick origin- vs reply-side conntrack tuple data.
 *
 * nft_ct is one of the most-used expressions in real rulesets —
 * connection tracking is foundational, every stateful firewall touches
 * it.  Hot kernel path with per-key dispatch logic, direction handling,
 * and LOAD/STORE asymmetry — all attractive bug surfaces.  Heavier
 * weight than the logging exprs because ct expressions touch live
 * conntrack state on every datapath packet.
 *
 * STORE-eligible keys mirror the nft_ct_set_keys[] table in the
 * kernel: NFT_CT_MARK, NFT_CT_LABELS, NFT_CT_EVENTMASK, NFT_CT_ZONE.
 * Tuple keys (direction-meaningful) are SRC/DST/PROTO_SRC/PROTO_DST
 * plus the explicit IPv4/IPv6 SRC_IP/DST_IP variants and the L3/L4
 * protocol pair.
 */
static size_t build_nft_ct_expr(unsigned char *buf, size_t off, size_t cap)
{
	static const __u32 regs[] = {
		NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4,
	};
	static const __u32 load_keys[] = {
		NFT_CT_STATE, NFT_CT_DIRECTION, NFT_CT_STATUS,
		NFT_CT_MARK, NFT_CT_SECMARK, NFT_CT_EXPIRATION,
		NFT_CT_HELPER, NFT_CT_L3PROTOCOL, NFT_CT_PROTOCOL,
		NFT_CT_SRC, NFT_CT_DST, NFT_CT_PROTO_SRC, NFT_CT_PROTO_DST,
		NFT_CT_LABELS, NFT_CT_PKTS, NFT_CT_BYTES, NFT_CT_AVGPKT,
		NFT_CT_ZONE, NFT_CT_EVENTMASK,
		NFT_CT_SRC_IP, NFT_CT_DST_IP,
		NFT_CT_SRC_IP6, NFT_CT_DST_IP6,
		NFT_CT_ID,
	};
	static const __u32 store_keys[] = {
		NFT_CT_MARK, NFT_CT_LABELS, NFT_CT_EVENTMASK, NFT_CT_ZONE,
	};
	struct nlattr *elem, *expr_data;
	size_t elem_off, expr_data_off;
	bool store_mode = ONE_IN(2);
	__u32 key;
	__u32 reg = regs[rand32() % ARRAY_SIZE(regs)];

	elem_off = off;
	off = nla_put(buf, off, cap, NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	off = nla_put_str(buf, off, cap, NFTA_EXPR_NAME, "ct");
	if (!off)
		return 0;

	expr_data_off = off;
	off = nla_put(buf, off, cap, NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return 0;

	if (store_mode) {
		key = store_keys[rand32() % ARRAY_SIZE(store_keys)];
		off = nla_put_be32(buf, off, cap, NFTA_CT_KEY, key);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_CT_SREG, reg);
		if (!off)
			return 0;
	} else {
		bool tuple_key;

		key = load_keys[rand32() % ARRAY_SIZE(load_keys)];
		off = nla_put_be32(buf, off, cap, NFTA_CT_KEY, key);
		if (!off)
			return 0;
		off = nla_put_be32(buf, off, cap, NFTA_CT_DREG, reg);
		if (!off)
			return 0;

		tuple_key = (key == NFT_CT_SRC || key == NFT_CT_DST ||
			     key == NFT_CT_PROTO_SRC ||
			     key == NFT_CT_PROTO_DST ||
			     key == NFT_CT_SRC_IP || key == NFT_CT_DST_IP ||
			     key == NFT_CT_SRC_IP6 || key == NFT_CT_DST_IP6);
		if (tuple_key && ONE_IN(2)) {
			__u8 dir = (rand32() & 1) ? IP_CT_DIR_REPLY
						  : IP_CT_DIR_ORIGINAL;

			off = nla_put(buf, off, cap, NFTA_CT_DIRECTION,
				      &dir, sizeof(dir));
			if (!off)
				return 0;
		}
	}

	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	return off;
}

/*
 * NFT_MSG_NEWRULE on (table, chain) carrying one immediate-verdict
 * expression that jumps/gotos to target_chain.  The expression list
 * layout is:
 *   NFTA_RULE_EXPRESSIONS (nested)
 *     NFTA_LIST_ELEM (nested)
 *       NFTA_EXPR_NAME = "immediate"
 *       NFTA_EXPR_DATA (nested)
 *         NFTA_IMMEDIATE_DREG = NFT_REG_VERDICT
 *         NFTA_IMMEDIATE_DATA (nested)
 *           NFTA_DATA_VERDICT (nested)
 *             NFTA_VERDICT_CODE = verdict_code
 *             NFTA_VERDICT_CHAIN = target_chain
 *
 * If position > 0, NFTA_RULE_POSITION carries it (insert-at-handle
 * semantics) and NLM_F_CREATE alone is used (no NLM_F_EXCL — the
 * existing rule referenced by the position keeps living after the
 * insert).  Otherwise the rule is appended to the chain.
 */
static int build_newrule(int fd, __u8 family, const char *table_name,
			 const char *chain_name, const char *target_chain,
			 __u32 verdict_code, __u64 position, bool with_payload,
			 bool with_meta, bool with_lookup, bool with_log,
			 bool with_bitwise, bool with_cmp, bool with_range,
			 bool with_byteorder, bool with_socket,
			 bool with_quota, bool with_limit,
			 bool with_numgen, bool with_hash,
			 bool with_synproxy,
			 bool with_counter,
			 bool with_connlimit,
			 bool with_masq,
			 bool with_redir,
			 bool with_tproxy,
			 bool with_xfrm,
			 bool with_dup_netdev,
			 bool with_dup_ipv4,
			 bool with_dup_ipv6,
			 bool with_fwd_netdev,
			 bool with_last,
			 bool with_rt,
			 bool with_fib,
			 bool with_exthdr,
			 bool with_osf,
			 bool with_queue,
			 bool with_immediate,
			 bool with_dynset, bool with_ct,
			 bool with_objref,
			 const char *set_name, __u32 set_id)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *imm_data, *verdict;
	size_t off, exprs_off, elem_off, expr_data_off, imm_data_off, verdict_off;
	__u16 flags = NLM_F_CREATE;

	memset(buf, 0, sizeof(buf));
	if (position == 0)
		flags |= NLM_F_APPEND;
	off = nfnl_hdr(buf, NFT_MSG_NEWRULE, flags, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;

	if (position > 0) {
		__u64 be_pos = ((__u64)htonl((__u32)(position >> 32))) |
			       (((__u64)htonl((__u32)position)) << 32);
		off = nla_put(buf, off, sizeof(buf), NFTA_RULE_POSITION,
			      &be_pos, sizeof(be_pos));
		if (!off)
			return -EIO;
	}

	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	if (with_payload) {
		off = build_nft_payload_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_meta) {
		off = build_nft_meta_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_lookup) {
		off = build_nft_lookup_expr(buf, off, sizeof(buf),
					    set_name, set_id);
		if (!off)
			return -EIO;
	}

	if (with_log) {
		off = build_nft_log_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_bitwise) {
		off = build_nft_bitwise_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_cmp) {
		off = build_nft_cmp_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_range) {
		off = build_nft_range_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_byteorder) {
		off = build_nft_byteorder_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_socket) {
		off = build_nft_socket_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_quota) {
		off = build_nft_quota_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_limit) {
		off = build_nft_limit_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_numgen) {
		off = build_nft_numgen_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_hash) {
		off = build_nft_hash_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_synproxy) {
		off = build_nft_synproxy_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_counter) {
		off = build_nft_counter_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_connlimit) {
		off = build_nft_connlimit_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_masq) {
		off = build_nft_masq_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_redir) {
		off = build_nft_redir_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_tproxy) {
		off = build_nft_tproxy_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_xfrm) {
		off = build_nft_xfrm_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_dup_netdev) {
		off = build_nft_dup_netdev_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_dup_ipv4) {
		off = build_nft_dup_ipv4_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_dup_ipv6) {
		off = build_nft_dup_ipv6_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_fwd_netdev) {
		off = build_nft_fwd_netdev_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_last) {
		off = build_nft_last_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_rt) {
		off = build_nft_rt_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_fib) {
		off = build_nft_fib_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_exthdr) {
		off = build_nft_exthdr_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_osf) {
		off = build_nft_osf_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_queue) {
		off = build_nft_queue_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_immediate) {
		off = build_nft_immediate_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_dynset) {
		off = build_nft_dynset_expr(buf, off, sizeof(buf),
					    set_name, set_id);
		if (!off)
			return -EIO;
	}

	if (with_ct) {
		off = build_nft_ct_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	if (with_objref) {
		off = build_nft_objref_expr(buf, off, sizeof(buf));
		if (!off)
			return -EIO;
	}

	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_EXPR_NAME, "immediate");
	if (!off)
		return -EIO;

	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_be32(buf, off, sizeof(buf),
			   NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
	if (!off)
		return -EIO;

	imm_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	verdict_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_DATA_VERDICT | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_be32(buf, off, sizeof(buf),
			   NFTA_VERDICT_CODE, verdict_code);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_VERDICT_CHAIN, target_chain);
	if (!off)
		return -EIO;

	verdict = (struct nlattr *)(buf + verdict_off);
	verdict->nla_len = (unsigned short)(off - verdict_off);
	imm_data = (struct nlattr *)(buf + imm_data_off);
	imm_data->nla_len = (unsigned short)(off - imm_data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * NFT_MSG_DELRULE on (table, chain) with no NFTA_RULE_HANDLE — the
 * kernel treats this as "delete every rule in chain".  Races any
 * in-flight skb still draining through the input hook.
 */
static int build_delrule(int fd, __u8 family, const char *table_name,
			 const char *chain_name)
{
	unsigned char buf[512];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_DELRULE, 0, family);

	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table_name);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;

	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Pick a random nf_tables family per call.  inet (covers v4+v6),
 * bridge (link-layer), netdev (ingress).  Each family registers its
 * own afinfo and exercises a different commit-time path inside
 * nf_tables_api.
 */
static __u8 pick_family(void)
{
	static const __u8 families[] = {
		NFPROTO_INET, NFPROTO_BRIDGE, NFPROTO_NETDEV,
	};

	return families[rand32() % ARRAY_SIZE(families)];
}

/*
 * Drive the per-hook .validate path on xt-compat targets translated
 * through nft_compat.  Build a base chain at HOOKNUM and append a rule
 * carrying an NFTA_EXPR "target" wrapping TARGET_NAME with a zeroed
 * info blob.  Many (target, hook) combinations are per-target invalid:
 * pre-fix, the kernel translated the xt target without invoking the
 * per-hook .validate the native expression path runs, so a mismatched
 * pair could be accepted at commit and crash on first packet.  Upstream
 * 2f768d638d97 ("netfilter: nft_compat: enforce per-hook .validate on
 * xt-compat targets") closes that.  Returns the kernel reply code.
 */
static int nft_compat_pair_install(int fd, __u8 family, const char *table,
				   const char *chain_name, __u32 hooknum,
				   const char *target_name)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr, *exprs, *elem, *expr_data;
	size_t off, hook_off, exprs_off, elem_off, expr_data_off;
	unsigned char info[64];
	int rc;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_EXCL, family);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain_name);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM, hooknum);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY, 0);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	nfnl_finalize(buf, off);
	rc = nfnl_send_recv(fd, buf, off);
	if (rc != 0)
		return rc;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWRULE,
		       NLM_F_CREATE | NLM_F_APPEND, family);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain_name);
	if (!off)
		return -EIO;
	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_LIST_ELEM | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "target");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  NFTA_TARGET_NAME, target_name);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TARGET_REV, 0);
	if (!off)
		return -EIO;
	memset(info, 0, sizeof(info));
	off = nla_put(buf, off, sizeof(buf), NFTA_TARGET_INFO,
		      info, sizeof(info));
	if (!off)
		return -EIO;
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);
	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);
	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

/*
 * Sweep every (xt-compat target, NF_INET_* hook) pair against a fresh
 * IPv4 table, latching ns_unsupported_nft_compat_validate on the first
 * EOPNOTSUPP/EPROTONOSUPPORT (compat module absent or family not
 * registered) so sibling probes stop cheaply.
 */
static void nft_compat_validate_sweep(int fd)
{
	static const char * const targets[] = {
		"MASQUERADE", "SNAT", "DNAT", "TPROXY", "LOG", "MARK",
	};
	static const __u32 hooks[] = {
		NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
		NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
	};
	char table_name[32];
	char chain_name[32];
	size_t ti, hi;
	int rc;

	snprintf(table_name, sizeof(table_name), "trcompat%u",
		 (unsigned int)(rand32() & 0xffffu));
	rc = build_newtable(fd, NFPROTO_IPV4, table_name);
	if (rc != 0) {
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT)
			ns_unsupported_nft_compat_validate = true;
		return;
	}

	for (ti = 0; ti < ARRAY_SIZE(targets); ti++) {
		for (hi = 0; hi < ARRAY_SIZE(hooks); hi++) {
			snprintf(chain_name, sizeof(chain_name),
				 "cc_%zu_%zu", ti, hi);
			rc = nft_compat_pair_install(fd, NFPROTO_IPV4,
						     table_name, chain_name,
						     hooks[hi], targets[ti]);
			__atomic_add_fetch(&shm->stats.nft_compat_validate_per_hook_pairs,
					   1, __ATOMIC_RELAXED);
			if (rc == 0) {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_install_ok,
						   1, __ATOMIC_RELAXED);
			} else if (rc == -EOPNOTSUPP ||
				   rc == -EPROTONOSUPPORT) {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_unsupported,
						   1, __ATOMIC_RELAXED);
				ns_unsupported_nft_compat_validate = true;
				goto done;
			} else {
				__atomic_add_fetch(&shm->stats.nft_compat_validate_install_fail,
						   1, __ATOMIC_RELAXED);
			}
		}
	}
done:
	(void)build_deltable(fd, NFPROTO_IPV4, table_name);
}

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

	__atomic_add_fetch(&shm->stats.xt_ct_iters, 1, __ATOMIC_RELAXED);

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
			__atomic_add_fetch(&shm->stats.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == EAFNOSUPPORT ||
			   errno == EPROTONOSUPPORT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_unsupported,
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
			__atomic_add_fetch(&shm->stats.xt_ct_eperm,
					   1, __ATOMIC_RELAXED);
		} else if (errno == ENOENT || errno == EOPNOTSUPP ||
			   errno == ENOPROTOOPT) {
			ns_unsupported_xt_ct = true;
			__atomic_add_fetch(&shm->stats.xt_ct_unsupported,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.xt_ct_set_ok, 1, __ATOMIC_RELAXED);
	if (revision == 2)
		__atomic_add_fetch(&shm->stats.xt_ct_v2_seen,
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
				__atomic_add_fetch(&shm->stats.xt_ct_get_ok,
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

static void nft_xt_ct_usersize_sweep(void)
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
 * Dormant-table abort sub-mode.  Drives the abort path the upstream
 * commit 63bac02786030 ("nf_tables: drop releases of nft_hook from
 * dormant tables on abort") repaired.  Single netlink batch:
 *   BATCH_BEGIN
 *   NEWTABLE flags=NFT_TABLE_F_DORMANT
 *   NEWCHAIN base chain attached to NF_INET_LOCAL_OUT (allocates the
 *     first nft_hook even though dormant tables don't register hooks)
 *   NEWCHAIN NLM_F_REPLACE on the same chain with a different
 *     hooknum/priority -- kernel allocates a fresh nft_hook and queues
 *     the prior one for release on commit
 *   NEWCHAIN NLM_F_REPLACE referencing a bogus NFTA_CHAIN_HANDLE --
 *     kernel rejects -ENOENT, the batch transitions to the abort path
 *   BATCH_END
 * Cleanup: NFT_MSG_DELTABLE outside the batch.
 */
static void nft_dormant_abort_sweep(int fd)
{
	static const __u32 hooks[] = {
		NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
		NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
	};
	unsigned char buf[2048];
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	struct nlmsghdr *nlh;
	struct nfgenmsg_local *nfg;
	struct nlattr *hook_attr;
	char table_name[32];
	const char *chain_name = "dhkc";
	__u8 family = NFPROTO_INET;
	__u32 hk_a = hooks[rand32() % ARRAY_SIZE(hooks)];
	__u32 hk_b = hooks[rand32() % ARRAY_SIZE(hooks)];
	__u64 bogus_handle;
	size_t off = 0, msg_off, hook_off;
	__u16 batch_markers[] = { NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END };
	__u16 chain_flags[]   = { NLM_F_CREATE, NLM_F_REPLACE };
	__u32 chain_hook[]    = { hk_a, hk_b == hk_a ? (hk_a + 1) % 5 : hk_b };
	int i;

	__atomic_add_fetch(&shm->stats.nft_dormant_abort_iters,
			   1, __ATOMIC_RELAXED);

	snprintf(table_name, sizeof(table_name), "trdorm%u",
		 (unsigned int)(rand32() & 0xffffu));
	memset(buf, 0, sizeof(buf));

	/* BATCH_BEGIN with res_id steering the batch at the nftables subsys */
	msg_off = off;
	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = batch_markers[0];
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);
	off += NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
	nlh->nlmsg_len = (__u32)(off - msg_off);

	/* (a) NEWTABLE flags=NFT_TABLE_F_DORMANT */
	msg_off = off;
	off += nfnl_hdr(buf + off, NFT_MSG_NEWTABLE, NLM_F_CREATE, family);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_TABLE_NAME, table_name);
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_TABLE_FLAGS,
			   NFT_TABLE_F_DORMANT);
	if (!off)
		return;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	/* (b) + (c): two NEWCHAINs on the same name, second is REPLACE with
	 * a different hook so the kernel allocates a fresh nft_hook and
	 * detaches the original. */
	for (i = 0; i < 2; i++) {
		msg_off = off;
		off += nfnl_hdr(buf + off, NFT_MSG_NEWCHAIN,
				chain_flags[i], family);
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TABLE, table_name);
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_NAME, chain_name);
		hook_off = off;
		off = nla_put(buf, off, sizeof(buf),
			      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_HOOKNUM, chain_hook[i]);
		off = nla_put_be32(buf, off, sizeof(buf),
				   NFTA_HOOK_PRIORITY, (__u32)(i ? 10 : 0));
		if (!off)
			return;
		hook_attr = (struct nlattr *)(buf + hook_off);
		hook_attr->nla_len = (unsigned short)(off - hook_off);
		off = nla_put_str(buf, off, sizeof(buf),
				  NFTA_CHAIN_TYPE, "filter");
		if (!off)
			return;
		((struct nlmsghdr *)(buf + msg_off))->nlmsg_len =
			(__u32)(off - msg_off);
	}

	/* (d) NEWCHAIN NLM_F_REPLACE on a bogus NFTA_CHAIN_HANDLE.  Kernel
	 * walks lookup, fails -ENOENT, batch enters the abort path. */
	msg_off = off;
	off += nfnl_hdr(buf + off, NFT_MSG_NEWCHAIN, NLM_F_REPLACE, family);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table_name);
	bogus_handle = ((__u64)htonl(0xdeadbeefU) << 32) |
		       (__u64)htonl(0xcafebabeU);
	off = nla_put(buf, off, sizeof(buf), NFTA_CHAIN_HANDLE,
		      &bogus_handle, sizeof(bogus_handle));
	if (!off)
		return;
	((struct nlmsghdr *)(buf + msg_off))->nlmsg_len = (__u32)(off - msg_off);

	/* (e) BATCH_END */
	msg_off = off;
	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = batch_markers[1];
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = next_seq();
	nfg = (struct nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(NFNL_SUBSYS_NFTABLES);
	off += NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));
	nlh->nlmsg_len = (__u32)(off - msg_off);

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;
	iov.iov_base  = buf;
	iov.iov_len   = off;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, 0) < 0) {
		if (errno == EPERM || errno == EOPNOTSUPP) {
			ns_unsupported_nf_tables = true;
			__atomic_add_fetch(&shm->stats.nft_dormant_abort_eperm,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.nft_dormant_abort_emsg,
					   1, __ATOMIC_RELAXED);
		}
		return;
	}

	/* Drain the abort error reply (one nlmsgerr from the rejected
	 * REPLACE).  Block once so we wait for the abort path to complete,
	 * then non-blockingly drain anything coalesced behind it. */
	(void)recv(fd, buf, sizeof(buf), 0);
	while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
		;

	__atomic_add_fetch(&shm->stats.nft_dormant_abort_ok,
			   1, __ATOMIC_RELAXED);

	(void)build_deltable(fd, family, table_name);
}

/*
 * nft_fwd_netdev neigh-forward loop sub-mode (upstream 1d47b55b36d2,
 * 0a0b35f0bf10, 1049970d7583).  Brings up a single veth pair inside the
 * private netns, assigns /24 IPv4 addresses to each peer, installs a
 * netdev-family table with two ingress chains -- one on each end -- whose
 * only rule is "immediate -> NFT_REG_1 = peer-oif" + "fwd sreg_dev=NFT_REG_1".
 * A single ICMP echo on the raw socket then drives the cross-forward path
 * through nft_fwd_netdev_eval / nf_dup_netdev_egress, exercising the
 * recursion / skb headroom / writable-pull windows the upstream commits
 * harden.  Bounded by FWD_LOOP_BUDGET_NS wall-clock.  Latches
 * ns_unsupported_nft_fwd_netdev_loop on the first failure of veth create /
 * addr assign / netdev-table install so a kernel without CONFIG_VETH or
 * CONFIG_NFT_FWD_NETDEV pays the EFAIL once and stops trying.
 */
#define FWD_LOOP_BUDGET_NS	150000000L
#define FWD_LOOP_VP0_ADDR	0x0a7b0101U	/* 10.123.1.1 */
#define FWD_LOOP_VP1_ADDR	0x0a7b0102U	/* 10.123.1.2 */

static int build_veth_pair_create(int fd, const char *a, const char *b)
{
	unsigned char buf[1024];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	struct nlattr *li, *id, *peer;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
	if (!off)
		return -EIO;
	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off)
		return -EIO;
	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;
	peer_off = off;
	off = nla_put(buf, off, sizeof(buf), VETH_INFO_PEER, NULL, 0);
	if (!off)
		return -EIO;
	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off)
		return -EIO;
	peer = (struct nlattr *)(buf + peer_off);
	peer->nla_len = (unsigned short)(off - peer_off);
	id = (struct nlattr *)(buf + id_off);
	id->nla_len = (unsigned short)(off - id_off);
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);
	nlh->nlmsg_len = (__u32)off;
	return nfnl_send_recv(fd, buf, off);
}

static int build_addr_assign(int fd, int idx, __u32 addr_be)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = 0;
	ifa->ifa_index     = (unsigned int)idx;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr_be,
		      sizeof(addr_be));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr_be,
		      sizeof(addr_be));
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;
	return nfnl_send_recv(fd, buf, off);
}

static int build_setlink_up_idx(int fd, int idx)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nfnl_send_recv(fd, buf, off);
}

static int build_netdev_ingress_chain(int fd, const char *table,
				      const char *chain, const char *dev)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_EXCL,
		       NFPROTO_NETDEV);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM,
			   NF_NETDEV_INGRESS);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_HOOK_DEV, dev);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static int build_fwd_loop_rule(int fd, const char *table, const char *chain,
			       __u32 oif)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *exprs, *elem, *expr_data, *data_attr;
	size_t off, exprs_off, elem_off, expr_data_off, data_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND,
		       NFPROTO_NETDEV);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_RULE_CHAIN, chain);
	if (!off)
		return -EIO;
	exprs_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;

	/* immediate: NFT_REG_1 <- oif (host-byte-order, register payload) */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf), NFTA_LIST_ELEM | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "immediate");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_IMMEDIATE_DREG,
			   NFT_REG_1);
	if (!off)
		return -EIO;
	data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_IMMEDIATE_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), NFTA_DATA_VALUE, &oif,
		      sizeof(oif));
	if (!off)
		return -EIO;
	data_attr = (struct nlattr *)(buf + data_off);
	data_attr->nla_len = (unsigned short)(off - data_off);
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	/* fwd: sreg_dev = NFT_REG_1 -- nft_fwd_netdev_eval reads peer oif */
	elem_off = off;
	off = nla_put(buf, off, sizeof(buf), NFTA_LIST_ELEM | NLA_F_NESTED,
		      NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_EXPR_NAME, "fwd");
	if (!off)
		return -EIO;
	expr_data_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_EXPR_DATA | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_FWD_SREG_DEV,
			   NFT_REG_1);
	if (!off)
		return -EIO;
	expr_data = (struct nlattr *)(buf + expr_data_off);
	expr_data->nla_len = (unsigned short)(off - expr_data_off);
	elem = (struct nlattr *)(buf + elem_off);
	elem->nla_len = (unsigned short)(off - elem_off);

	exprs = (struct nlattr *)(buf + exprs_off);
	exprs->nla_len = (unsigned short)(off - exprs_off);
	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static void nft_fwd_netdev_loop_sweep(int nfnl, int rtnl)
{
	char table_name[32];
	char vp0[IFNAMSIZ], vp1[IFNAMSIZ];
	int vp0_idx, vp1_idx;
	int sk = -1;
	bool table_created = false;
	struct timespec t0;
	unsigned int rng = (unsigned int)(rand32() & 0xffffu);

	__atomic_add_fetch(&shm->stats.nft_fwd_loop_runs, 1,
			   __ATOMIC_RELAXED);
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);

	snprintf(vp0, sizeof(vp0), "vp0_%u", rng);
	snprintf(vp1, sizeof(vp1), "vp1_%u", rng);

	if (build_veth_pair_create(rtnl, vp0, vp1) != 0)
		goto fail;
	vp0_idx = (int)if_nametoindex(vp0);
	vp1_idx = (int)if_nametoindex(vp1);
	if (vp0_idx <= 0 || vp1_idx <= 0)
		goto fail;
	if (build_addr_assign(rtnl, vp0_idx,
			      htonl(FWD_LOOP_VP0_ADDR)) != 0 ||
	    build_addr_assign(rtnl, vp1_idx,
			      htonl(FWD_LOOP_VP1_ADDR)) != 0)
		goto fail;
	if (build_setlink_up_idx(rtnl, vp0_idx) != 0 ||
	    build_setlink_up_idx(rtnl, vp1_idx) != 0)
		goto fail;

	snprintf(table_name, sizeof(table_name), "trfwdl%u", rng);
	if (build_newtable(nfnl, NFPROTO_NETDEV, table_name) != 0)
		goto fail;
	table_created = true;

	if (build_netdev_ingress_chain(nfnl, table_name, "ing0", vp0) != 0 ||
	    build_netdev_ingress_chain(nfnl, table_name, "ing1", vp1) != 0)
		goto out;
	if (build_fwd_loop_rule(nfnl, table_name, "ing0",
				(__u32)vp1_idx) != 0 ||
	    build_fwd_loop_rule(nfnl, table_name, "ing1",
				(__u32)vp0_idx) != 0)
		goto out;

	if (ns_since(&t0) >= FWD_LOOP_BUDGET_NS)
		goto out;

	sk = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	if (sk >= 0) {
		struct sockaddr_in dst;
		unsigned char icmp[16];

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_addr.s_addr = htonl(FWD_LOOP_VP1_ADDR);
		memset(icmp, 0, sizeof(icmp));
		icmp[0] = 8;	/* ICMP_ECHO */
		if (sendto(sk, icmp, sizeof(icmp), MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.nft_fwd_loop_probe_sent_ok,
					   1, __ATOMIC_RELAXED);
	}

	__atomic_add_fetch(&shm->stats.nft_fwd_loop_completed_ok, 1,
			   __ATOMIC_RELAXED);
	goto out;

fail:
	ns_unsupported_nft_fwd_netdev_loop = true;
	__atomic_add_fetch(&shm->stats.nft_fwd_loop_ns_setup_failed, 1,
			   __ATOMIC_RELAXED);
out:
	if (sk >= 0)
		close(sk);
	if (table_created)
		(void)build_deltable(nfnl, NFPROTO_NETDEV, table_name);
}

/*
 * L4-aware-on-fragment sub-mode (upstream 952e121c9613, 009d203e56db,
 * 0bf00859d7a5).  These commits hardened nf_socket_lookup, nf_tproxy_*,
 * nf_osf_match and the SCTP exthdr expression after they were observed
 * dereferencing a fragment's truncated transport header on packets that
 * traverse a netfilter chain registered ahead of NF_IP_PRI_CONNTRACK_DEFRAG
 * (-400) -- ip_defrag has not run yet, so the skb still carries an IP
 * fragment whose transport header is either short or absent on the
 * non-first frag.  Reaching the bug requires both:
 *   (a) an nft chain hooked at NF_IP_PRI_RAW_BEFORE_DEFRAG (-450) carrying
 *       at least one of those L4-aware expressions, and
 *   (b) raw IP fragments (MF=1 with payload, then MF=0 with fragoff>0)
 *       hitting that chain before defrag completes.
 * Random per-syscall fuzzing never lines those two up: nft chains it
 * synthesises pick priority 0 / NF_INET_LOCAL_IN, and nothing emits raw
 * fragments into the local hook path.
 *
 * Per invocation: NEWTABLE NFPROTO_IPV4, NEWSET (anonymous, ipv4_addr key
 * for the lookup expression to bind), NEWCHAIN aux (no hook, jump target),
 * NEWCHAIN base hooked at NF_INET_PRE_ROUTING priority -450, NEWRULE on
 * base carrying socket+tproxy+exthdr(SCTP)+osf, then a raw IPv4 fragment
 * pair (MF=1/off=0 then MF=0/off=2) sent into 127.0.0.1 over a SOCK_RAW
 * IPPROTO_RAW socket so the kernel transmits the iphdr verbatim.  Cleanup
 * deletes rule/set/table.  Protocol on the fragments is rolled per call
 * between UDP and SCTP so the SCTP exthdr eval is reached when the SCTP
 * module is loaded; rule install can EOPNOTSUPP-latch silently if SCTP is
 * absent and the per-expression validator rejects the exthdr binding.
 */
#define L4FRAG_FRAG1_PAYLOAD	16U
#define L4FRAG_FRAG2_PAYLOAD	8U
#define L4FRAG_PRIO_PRE_DEFRAG	((__u32)(__s32)-450)

#ifndef IP_MF
#define IP_MF			0x2000
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP		132
#endif

static int build_l4frag_chain(int fd, const char *table, const char *chain)
{
	unsigned char buf[NFNL_BUF_BYTES];
	struct nlattr *hook_attr;
	size_t off, hook_off;

	memset(buf, 0, sizeof(buf));
	off = nfnl_hdr(buf, NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_EXCL,
		       NFPROTO_IPV4);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_NAME, chain);
	if (!off)
		return -EIO;
	hook_off = off;
	off = nla_put(buf, off, sizeof(buf),
		      NFTA_CHAIN_HOOK | NLA_F_NESTED, NULL, 0);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_HOOKNUM,
			   NF_INET_PRE_ROUTING);
	if (!off)
		return -EIO;
	off = nla_put_be32(buf, off, sizeof(buf), NFTA_HOOK_PRIORITY,
			   L4FRAG_PRIO_PRE_DEFRAG);
	if (!off)
		return -EIO;
	hook_attr = (struct nlattr *)(buf + hook_off);
	hook_attr->nla_len = (unsigned short)(off - hook_off);
	off = nla_put_str(buf, off, sizeof(buf), NFTA_CHAIN_TYPE, "filter");
	if (!off)
		return -EIO;
	nfnl_finalize(buf, off);
	return nfnl_send_recv(fd, buf, off);
}

static void l4frag_send_pair(__u8 protocol)
{
	int s = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	unsigned char pkt1[sizeof(struct iphdr) + L4FRAG_FRAG1_PAYLOAD];
	unsigned char pkt2[sizeof(struct iphdr) + L4FRAG_FRAG2_PAYLOAD];
	struct sockaddr_in dst;
	struct iphdr *ip;
	__u16 id_he = (__u16)(rand32() & 0xffffu);
	int i;

	if (s < 0) {
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	memset(pkt1, 0, sizeof(pkt1));
	memset(pkt2, 0, sizeof(pkt2));
	memset(pkt1 + sizeof(struct iphdr), 0xa5, L4FRAG_FRAG1_PAYLOAD);
	memset(pkt2 + sizeof(struct iphdr), 0x5a, L4FRAG_FRAG2_PAYLOAD);

	for (i = 0; i < 2; i++) {
		ip = (struct iphdr *)(i ? pkt2 : pkt1);
		ip->version  = 4;
		ip->ihl      = 5;
		ip->tot_len  = htons((__u16)(i ? sizeof(pkt2) : sizeof(pkt1)));
		ip->id       = htons(id_he);
		/* first frag: IP_MF set, fragoff 0; second: MF clear,
		 * fragoff = first-frag payload / 8 (== 2). */
		ip->frag_off = htons((__u16)(i ? (L4FRAG_FRAG1_PAYLOAD / 8U)
						: IP_MF));
		ip->ttl      = 64;
		ip->protocol = protocol;
		ip->saddr    = htonl(0x7f000002U);
		ip->daddr    = htonl(0x7f000001U);
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_addr.s_addr = htonl(0x7f000001U);

	if (sendto(s, pkt1, sizeof(pkt1), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	if (sendto(s, pkt2, sizeof(pkt2), MSG_DONTWAIT,
		   (struct sockaddr *)&dst, sizeof(dst)) > 0)
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_ok, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.nft_l4frag_send_failed, 1,
				   __ATOMIC_RELAXED);
	close(s);
}

static void nft_l4_aware_frag_sweep(int nfnl)
{
	char table[32], anon_set[32];
	const char *base = "l4base";
	const char *aux  = "l4aux";
	__u32 set_id = rand32();
	__u8 proto = (rand32() & 1) ? IPPROTO_UDP : IPPROTO_SCTP;
	bool table_created = false;

	__atomic_add_fetch(&shm->stats.nft_l4frag_iters, 1, __ATOMIC_RELAXED);

	snprintf(table, sizeof(table), "trl4f%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(anon_set, sizeof(anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));

	if (build_newtable(nfnl, NFPROTO_IPV4, table) != 0)
		return;
	table_created = true;

	(void)build_newset(nfnl, NFPROTO_IPV4, table, anon_set, set_id);
	(void)build_newchain(nfnl, NFPROTO_IPV4, table, aux, false);

	if (build_l4frag_chain(nfnl, table, base) != 0)
		goto out;
	__atomic_add_fetch(&shm->stats.nft_l4frag_install_ok, 1,
			   __ATOMIC_RELAXED);

	/* with_socket, with_tproxy, with_exthdr (SCTP path), with_osf — every
	 * other expression slot disabled so the rule body is exclusively the
	 * L4-aware quartet under test. */
	if (build_newrule(nfnl, NFPROTO_IPV4, table, base, aux, NFT_JUMP, 0,
			  false, false, false, false, false, false, false,
			  false,		/* payload..byteorder */
			  true,			/* with_socket */
			  false, false, false, false, false, false, false,
			  false, false,		/* quota..redir */
			  true,			/* with_tproxy */
			  false, false, false, false, false, false, false,
			  false,		/* xfrm..fib */
			  true,			/* with_exthdr */
			  true,			/* with_osf */
			  false, false, false, false, false,
			  anon_set, set_id) == 0)
		__atomic_add_fetch(&shm->stats.nft_l4frag_rule_ok, 1,
				   __ATOMIC_RELAXED);

	l4frag_send_pair(proto);

	(void)build_delrule(nfnl, NFPROTO_IPV4, table, base);
	(void)build_delset(nfnl, NFPROTO_IPV4, table, anon_set);
out:
	if (table_created)
		(void)build_deltable(nfnl, NFPROTO_IPV4, table);
}

bool nftables_churn(struct childdata *child)
{
	char table_name[32];
	char base_chain[32]  = "chain_in";
	char aux_chain[32]   = "chain_aux";
	char anon_set[32];
	int rtnl = -1;
	int nfnl = -1;
	int udp = -1;
	__u8 family;
	__u32 set_id;
	__u32 verdict;
	bool table_created = false;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.nftables_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_nfnetlink ||
	    ns_unsupported_nf_tables)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	nfnl = nfnl_open();
	if (nfnl < 0) {
		/* EPROTONOSUPPORT here means CONFIG_NF_NETLINK is off
		 * — latch and stop trying.  Other errors (ENOMEM,
		 * EMFILE) are transient; fall through and re-try next
		 * invocation. */
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_nfnetlink = true;
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.nftables_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	if (!lo_brought_up) {
		bring_lo_up(rtnl);
		lo_brought_up = true;
	}

	/* Dormant-table abort sub-mode (upstream 63bac02786030) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Reuses ns_unsupported_nf_tables as the latch on EPERM/EOPNOTSUPP. */
	if (ONE_IN(8)) {
		nft_dormant_abort_sweep(nfnl);
		goto out;
	}

	/* xt_CT v1+v2 usersize sub-mode (upstream 8bedb6c46945) -- rare gate
	 * so the expression-fuzz path below stays the dominant workload.
	 * Independent latch (ns_unsupported_xt_ct) so a missing xt_CT module
	 * doesn't cascade into nf_tables disablement. */
	if (ONE_IN(8) && !ns_unsupported_xt_ct) {
		nft_xt_ct_usersize_sweep();
		goto out;
	}

	/* Per-hook .validate sweep on xt-compat targets, gated separately
	 * so the legacy expression-fuzz path above is undisturbed. */
	if (ONE_IN(2) && !ns_unsupported_nft_compat_validate) {
		nft_compat_validate_sweep(nfnl);
		goto out;
	}

	/* nft_fwd_netdev neigh-forward loop sub-mode (upstream 1d47b55b36d2,
	 * 0a0b35f0bf10, 1049970d7583).  Rare gate so the dominant
	 * expression-fuzz path above stays the primary workload.  Independent
	 * latch (ns_unsupported_nft_fwd_netdev_loop) so a kernel without
	 * CONFIG_VETH or CONFIG_NFT_FWD_NETDEV pays the EFAIL once. */
	if (ONE_IN(8) && !ns_unsupported_nft_fwd_netdev_loop) {
		nft_fwd_netdev_loop_sweep(nfnl, rtnl);
		goto out;
	}

	/* L4-aware-on-fragment sub-mode (upstream 952e121c9613, 009d203e56db,
	 * 0bf00859d7a5).  Rare gate so the dominant expression-fuzz path
	 * above stays the primary workload.  No dedicated latch -- a kernel
	 * without CONFIG_NF_TABLES is already gated by ns_unsupported_nf_tables
	 * upstream; per-expression validators that EOPNOTSUPP just skip the
	 * rule install and the cleanup still drains. */
	if (ONE_IN(8)) {
		nft_l4_aware_frag_sweep(nfnl);
		goto out;
	}

	family = pick_family();
	snprintf(table_name, sizeof(table_name), "trnft%u",
		 (unsigned int)(rand32() & 0xffffu));
	snprintf(anon_set, sizeof(anon_set), "__set%u",
		 (unsigned int)(rand32() & 0xffffu));
	set_id = rand32();
	verdict = (rand32() & 1) ? NFT_JUMP : NFT_GOTO;

	rc = build_newtable(nfnl, family, table_name);
	if (rc != 0) {
		/* EAFNOSUPPORT / EOPNOTSUPP / EPROTONOSUPPORT all mean
		 * "this nf_tables family isn't registered" — most
		 * commonly because the nf_tables module itself is
		 * absent.  Latch the whole op off; nothing else here
		 * will work either. */
		if (rc == -EOPNOTSUPP || rc == -EPROTONOSUPPORT ||
		    rc == -EAFNOSUPPORT)
			ns_unsupported_nf_tables = true;
		goto out;
	}
	table_created = true;
	__atomic_add_fetch(&shm->stats.nftables_churn_table_create_ok,
			   1, __ATOMIC_RELAXED);

	if (build_newset(nfnl, family, table_name, anon_set, set_id) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_set_create_ok,
				   1, __ATOMIC_RELAXED);

	/* aux first so the base-chain rule's NFT_JUMP/NFT_GOTO has a
	 * resolvable target on first commit. */
	if (build_newchain(nfnl, family, table_name, aux_chain, false) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	if (build_newchain(nfnl, family, table_name, base_chain, true) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_chain_create_ok,
				   1, __ATOMIC_RELAXED);

	{
		bool with_payload = ONE_IN(3);
		bool with_meta = ONE_IN(3);
		bool with_lookup = ONE_IN(3);
		bool with_log = ONE_IN(4);
		bool with_bitwise = ONE_IN(4);
		bool with_cmp = ONE_IN(3);
		bool with_range = ONE_IN(3);
		bool with_byteorder = ONE_IN(3);
		bool with_socket = ONE_IN(3);
		bool with_quota = ONE_IN(3);
		bool with_limit = ONE_IN(3);
		bool with_numgen = ONE_IN(3);
		bool with_hash = ONE_IN(3);
		bool with_synproxy = ONE_IN(3);
		bool with_counter = ONE_IN(3);
		bool with_connlimit = ONE_IN(3);
		bool with_masq = ONE_IN(3);
		bool with_redir = ONE_IN(3);
		bool with_tproxy = ONE_IN(3);
		bool with_xfrm = ONE_IN(3);
		bool with_dup_netdev = ONE_IN(3);
		bool with_dup_ipv4 = ONE_IN(3);
		bool with_dup_ipv6 = ONE_IN(3);
		bool with_fwd_netdev = ONE_IN(3);
		bool with_last = ONE_IN(3);
		bool with_rt = ONE_IN(3);
		bool with_fib = ONE_IN(3);
		bool with_exthdr = ONE_IN(3);
		bool with_osf = ONE_IN(3);
		bool with_queue = ONE_IN(3);
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);
		bool with_objref = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 0, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_byteorder, with_socket,
				  with_quota, with_limit, with_numgen,
				  with_hash, with_synproxy, with_counter,
				  with_connlimit,
				  with_masq,
				  with_redir,
				  with_tproxy,
				  with_xfrm,
				  with_dup_netdev,
				  with_dup_ipv4,
				  with_dup_ipv6,
				  with_fwd_netdev,
				  with_last,
				  with_rt,
				  with_fib,
				  with_exthdr,
				  with_osf,
				  with_queue,
				  with_immediate,
				  with_dynset, with_ct,
				  with_objref,
				  anon_set, set_id) == 0) {
			__atomic_add_fetch(&shm->stats.nftables_churn_rule_create_ok,
					   1, __ATOMIC_RELAXED);
			if (with_payload)
				__atomic_add_fetch(&shm->stats.nftables_churn_payload_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_meta)
				__atomic_add_fetch(&shm->stats.nftables_churn_meta_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_lookup)
				__atomic_add_fetch(&shm->stats.nftables_churn_lookup_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_log)
				__atomic_add_fetch(&shm->stats.nftables_churn_log_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_bitwise)
				__atomic_add_fetch(&shm->stats.nftables_churn_bitwise_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_cmp)
				__atomic_add_fetch(&shm->stats.nftables_churn_cmp_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_range)
				__atomic_add_fetch(&shm->stats.nftables_churn_range_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_byteorder)
				__atomic_add_fetch(&shm->stats.nftables_churn_byteorder_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_socket)
				__atomic_add_fetch(&shm->stats.nftables_churn_socket_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_quota)
				__atomic_add_fetch(&shm->stats.nftables_churn_quota_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_limit)
				__atomic_add_fetch(&shm->stats.nftables_churn_limit_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_numgen)
				__atomic_add_fetch(&shm->stats.nftables_churn_numgen_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_hash)
				__atomic_add_fetch(&shm->stats.nftables_churn_hash_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_synproxy)
				__atomic_add_fetch(&shm->stats.nftables_churn_synproxy_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_counter)
				__atomic_add_fetch(&shm->stats.nftables_churn_counter_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_connlimit)
				__atomic_add_fetch(&shm->stats.nftables_churn_connlimit_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_masq)
				__atomic_add_fetch(&shm->stats.nftables_churn_masq_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_redir)
				__atomic_add_fetch(&shm->stats.nftables_churn_redir_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_tproxy)
				__atomic_add_fetch(&shm->stats.nftables_churn_tproxy_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_xfrm)
				__atomic_add_fetch(&shm->stats.nftables_churn_xfrm_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_netdev)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_netdev_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_ipv4)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_ipv4_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_ipv6)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_ipv6_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_fwd_netdev)
				__atomic_add_fetch(&shm->stats.nftables_churn_fwd_netdev_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_last)
				__atomic_add_fetch(&shm->stats.nftables_churn_last_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_rt)
				__atomic_add_fetch(&shm->stats.nftables_churn_rt_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_fib)
				__atomic_add_fetch(&shm->stats.nftables_churn_fib_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_exthdr)
				__atomic_add_fetch(&shm->stats.nftables_churn_exthdr_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_osf)
				__atomic_add_fetch(&shm->stats.nftables_churn_osf_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_queue)
				__atomic_add_fetch(&shm->stats.nftables_churn_queue_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_immediate)
				__atomic_add_fetch(&shm->stats.nftables_churn_immediate_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dynset)
				__atomic_add_fetch(&shm->stats.nftables_churn_dynset_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_ct)
				__atomic_add_fetch(&shm->stats.nftables_churn_ct_expr_emit,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Drive the input hook with loopback UDP traffic.  Each send
	 * ingresses on lo, walks the freshly-installed chain_in ->
	 * chain_aux jump via nf_hook_slow, and exercises the verdict
	 * path that the CVE-2024-1086 lineage hangs off.
	 */
	if (!ns_unsupported_inet) {
		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		}
	}

	if (udp >= 0) {
		struct sockaddr_in dst;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(NFT_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_NFTABLES_CHURN,
				 JITTER_RANGE(NFT_PACKET_BASE));
		if (iters < NFT_PACKET_FLOOR)
			iters = NFT_PACKET_FLOOR;
		if (iters > NFT_PACKET_CAP)
			iters = NFT_PACKET_CAP;

		for (i = 0; i < iters; i++) {
			unsigned char payload[64];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.nftables_churn_packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Mid-traffic insert: NEWRULE at NFTA_RULE_POSITION = 1.  The
	 * position-based insert path is a different commit-time codepath
	 * from the append-only path above; if no rule with handle 1
	 * exists the kernel rejects it cheaply, which is fine — the
	 * commit-time validation still ran.
	 */
	{
		bool with_payload = ONE_IN(3);
		bool with_meta = ONE_IN(3);
		bool with_lookup = ONE_IN(3);
		bool with_log = ONE_IN(4);
		bool with_bitwise = ONE_IN(4);
		bool with_cmp = ONE_IN(3);
		bool with_range = ONE_IN(3);
		bool with_byteorder = ONE_IN(3);
		bool with_socket = ONE_IN(3);
		bool with_quota = ONE_IN(3);
		bool with_limit = ONE_IN(3);
		bool with_numgen = ONE_IN(3);
		bool with_hash = ONE_IN(3);
		bool with_synproxy = ONE_IN(3);
		bool with_counter = ONE_IN(3);
		bool with_connlimit = ONE_IN(3);
		bool with_masq = ONE_IN(3);
		bool with_redir = ONE_IN(3);
		bool with_tproxy = ONE_IN(3);
		bool with_xfrm = ONE_IN(3);
		bool with_dup_netdev = ONE_IN(3);
		bool with_dup_ipv4 = ONE_IN(3);
		bool with_dup_ipv6 = ONE_IN(3);
		bool with_fwd_netdev = ONE_IN(3);
		bool with_last = ONE_IN(3);
		bool with_rt = ONE_IN(3);
		bool with_fib = ONE_IN(3);
		bool with_exthdr = ONE_IN(3);
		bool with_osf = ONE_IN(3);
		bool with_queue = ONE_IN(3);
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);
		bool with_objref = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 1, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_byteorder, with_socket,
				  with_quota, with_limit, with_numgen,
				  with_hash, with_synproxy, with_counter,
				  with_connlimit,
				  with_masq,
				  with_redir,
				  with_tproxy,
				  with_xfrm,
				  with_dup_netdev,
				  with_dup_ipv4,
				  with_dup_ipv6,
				  with_fwd_netdev,
				  with_last,
				  with_rt,
				  with_fib,
				  with_exthdr,
				  with_osf,
				  with_queue,
				  with_immediate,
				  with_dynset, with_ct,
				  with_objref,
				  anon_set, set_id) == 0) {
			__atomic_add_fetch(&shm->stats.nftables_churn_rule_insert_ok,
					   1, __ATOMIC_RELAXED);
			if (with_payload)
				__atomic_add_fetch(&shm->stats.nftables_churn_payload_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_meta)
				__atomic_add_fetch(&shm->stats.nftables_churn_meta_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_lookup)
				__atomic_add_fetch(&shm->stats.nftables_churn_lookup_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_log)
				__atomic_add_fetch(&shm->stats.nftables_churn_log_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_bitwise)
				__atomic_add_fetch(&shm->stats.nftables_churn_bitwise_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_cmp)
				__atomic_add_fetch(&shm->stats.nftables_churn_cmp_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_range)
				__atomic_add_fetch(&shm->stats.nftables_churn_range_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_byteorder)
				__atomic_add_fetch(&shm->stats.nftables_churn_byteorder_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_socket)
				__atomic_add_fetch(&shm->stats.nftables_churn_socket_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_quota)
				__atomic_add_fetch(&shm->stats.nftables_churn_quota_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_limit)
				__atomic_add_fetch(&shm->stats.nftables_churn_limit_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_numgen)
				__atomic_add_fetch(&shm->stats.nftables_churn_numgen_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_hash)
				__atomic_add_fetch(&shm->stats.nftables_churn_hash_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_synproxy)
				__atomic_add_fetch(&shm->stats.nftables_churn_synproxy_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_counter)
				__atomic_add_fetch(&shm->stats.nftables_churn_counter_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_connlimit)
				__atomic_add_fetch(&shm->stats.nftables_churn_connlimit_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_masq)
				__atomic_add_fetch(&shm->stats.nftables_churn_masq_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_redir)
				__atomic_add_fetch(&shm->stats.nftables_churn_redir_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_tproxy)
				__atomic_add_fetch(&shm->stats.nftables_churn_tproxy_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_xfrm)
				__atomic_add_fetch(&shm->stats.nftables_churn_xfrm_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_netdev)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_netdev_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_ipv4)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_ipv4_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dup_ipv6)
				__atomic_add_fetch(&shm->stats.nftables_churn_dup_ipv6_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_fwd_netdev)
				__atomic_add_fetch(&shm->stats.nftables_churn_fwd_netdev_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_last)
				__atomic_add_fetch(&shm->stats.nftables_churn_last_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_rt)
				__atomic_add_fetch(&shm->stats.nftables_churn_rt_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_fib)
				__atomic_add_fetch(&shm->stats.nftables_churn_fib_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_exthdr)
				__atomic_add_fetch(&shm->stats.nftables_churn_exthdr_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_osf)
				__atomic_add_fetch(&shm->stats.nftables_churn_osf_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_queue)
				__atomic_add_fetch(&shm->stats.nftables_churn_queue_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_immediate)
				__atomic_add_fetch(&shm->stats.nftables_churn_immediate_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_dynset)
				__atomic_add_fetch(&shm->stats.nftables_churn_dynset_expr_emit,
						   1, __ATOMIC_RELAXED);
			if (with_ct)
				__atomic_add_fetch(&shm->stats.nftables_churn_ct_expr_emit,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Concurrent with whatever's still draining from the udp send
	 * loop: bulk-delete every rule in chain_in.  This is the
	 * targeted commit-vs-traffic teardown window — the same one the
	 * CVE-2024-1086 nft_verdict UAF exploited.
	 */
	if (build_delrule(nfnl, family, table_name, base_chain) == 0)
		__atomic_add_fetch(&shm->stats.nftables_churn_rule_del_ok,
				   1, __ATOMIC_RELAXED);

	(void)build_delset(nfnl, family, table_name, anon_set);

out:
	if (udp >= 0)
		close(udp);

	if (nfnl >= 0) {
		/* DELTABLE cascades cleanup of any chain/rule/set
		 * survivors via nf_tables_table_destroy, racing the
		 * same in-flight skbs as the explicit DELRULE above. */
		if (table_created) {
			if (build_deltable(nfnl, family, table_name) == 0)
				__atomic_add_fetch(&shm->stats.nftables_churn_table_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		close(nfnl);
	}

	if (rtnl >= 0)
		close(rtnl);

	return true;
}
