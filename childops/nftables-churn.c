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
 * (auto-pulled by CONFIG_NFT_CONNLIMIT=m); test kernel config has it. */
#ifndef NFTA_CONNLIMIT_COUNT
#define NFTA_CONNLIMIT_COUNT		1
#endif
#ifndef NFTA_CONNLIMIT_FLAGS
#define NFTA_CONNLIMIT_FLAGS		2
#endif
#ifndef NFT_CONNLIMIT_F_INV
#define NFT_CONNLIMIT_F_INV		(1 << 0)
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
 * also =m) on the test kernel, so the policy validation path is exercised
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
 * -EINVAL).  nft_queue builds as CONFIG_NFT_QUEUE=m on the test kernel,
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
 * built CONFIG_NFT_OSF=m on the test kernel, so the policy validation
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
			 bool with_last,
			 bool with_rt,
			 bool with_fib,
			 bool with_exthdr,
			 bool with_osf,
			 bool with_queue,
			 bool with_immediate,
			 bool with_dynset, bool with_ct,
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
		bool with_byteorder = ONE_IN(3);
		bool with_socket = ONE_IN(3);
		bool with_quota = ONE_IN(3);
		bool with_limit = ONE_IN(3);
		bool with_numgen = ONE_IN(3);
		bool with_hash = ONE_IN(3);
		bool with_synproxy = ONE_IN(3);
		bool with_counter = ONE_IN(3);
		bool with_connlimit = ONE_IN(3);
		bool with_last = ONE_IN(3);
		bool with_rt = ONE_IN(3);
		bool with_fib = ONE_IN(3);
		bool with_exthdr = ONE_IN(3);
		bool with_osf = ONE_IN(3);
		bool with_queue = ONE_IN(3);
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 0, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_byteorder, with_socket,
				  with_quota, with_limit, with_numgen,
				  with_hash, with_synproxy, with_counter,
				  with_connlimit,
				  with_last,
				  with_rt,
				  with_fib,
				  with_exthdr,
				  with_osf,
				  with_queue,
				  with_immediate,
				  with_dynset, with_ct,
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
		bool with_last = ONE_IN(3);
		bool with_rt = ONE_IN(3);
		bool with_fib = ONE_IN(3);
		bool with_exthdr = ONE_IN(3);
		bool with_osf = ONE_IN(3);
		bool with_queue = ONE_IN(3);
		bool with_immediate = ONE_IN(3);
		bool with_dynset = ONE_IN(3);
		bool with_ct = ONE_IN(3);

		if (build_newrule(nfnl, family, table_name, base_chain,
				  aux_chain, verdict, 1, with_payload,
				  with_meta, with_lookup, with_log,
				  with_bitwise, with_cmp, with_range,
				  with_byteorder, with_socket,
				  with_quota, with_limit, with_numgen,
				  with_hash, with_synproxy, with_counter,
				  with_connlimit,
				  with_last,
				  with_rt,
				  with_fib,
				  with_exthdr,
				  with_osf,
				  with_queue,
				  with_immediate,
				  with_dynset, with_ct,
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
