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

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
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

#ifndef NFPROTO_INET
#define NFPROTO_INET			1
#endif
#ifndef NFPROTO_NETDEV
#define NFPROTO_NETDEV			5
#endif
#ifndef NFPROTO_BRIDGE
#define NFPROTO_BRIDGE			7
#endif

#ifndef NF_INET_LOCAL_IN
#define NF_INET_LOCAL_IN		1
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
			 bool with_immediate, bool with_dynset, bool with_ct,
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
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 0, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_immediate, with_dynset, with_ct,
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
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 1, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_immediate, with_dynset, with_ct,
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
