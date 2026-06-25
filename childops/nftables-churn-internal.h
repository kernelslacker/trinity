/*
 * nftables-churn-internal.h
 *
 * Shared declarations split out of childops/nftables-churn.c to allow
 * the per-nft-expression builders (build_nft_*_expr family) to live in
 * their own translation unit and compile in parallel with the rest of
 * the module.  This header is private to the two TUs that make up
 * nftables-churn — do not include it from anywhere else.
 *
 * Contents:
 *   - the UAPI conditional #includes and their fallback macros, so
 *     both TUs see exactly the same nf_tables symbol values;
 *   - static-inline nla_put_be{32,16,64} netlink helpers, kept inline
 *     so the linker does not see them as external (no real linkage
 *     change);
 *   - forward declarations for every build_nft_*_expr function,
 *     deliberately widened from file-static to external linkage so
 *     the nft_expr_table dispatch in nftables-churn.c can reference
 *     them across the TU boundary.
 */

#ifndef CHILDOPS_NFTABLES_CHURN_INTERNAL_H
#define CHILDOPS_NFTABLES_CHURN_INTERNAL_H

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
#include <stdlib.h>
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
#include "compat.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"

/*
 * UAPI fallbacks.  The header on stripped sysroots may not have
 * nf_tables.h / nfnetlink.h at all — we still want to compile on those
 * systems and let the latches catch the missing kernel support at
 * runtime.  IDs come from the in-tree UAPI and are stable.
 */
#ifndef NFNL_SUBSYS_NFTABLES
#define NFNL_SUBSYS_NFTABLES		10
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
 * CONFIG_NF_NAT (auto-pulled by CONFIG_NFT_MASQ=m); test kernel config has
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
 * on CONFIG_NF_NAT (auto-pulled by CONFIG_NFT_REDIR=m); test kernel
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
 * the test kernel config has. */
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
 * CONFIG_NFT_XFRM=m, which the test kernel config has. */
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
 * CONFIG_NFT_DUP_NETDEV=m, which the test kernel config has. */
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
 * predate it.  Depends on CONFIG_NFT_DUP_IPV4=m, which the test kernel
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
 * the test kernel config has. */
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

/*
 * Small netlink-attribute helpers.  Originally file-static in
 * nftables-churn.c; promoted to static-inline so every TU in the
 * split (nftables-churn.c plus the nftables-churn-exprs-*.c
 * per-family builders) can call them without changing observable
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
 * build_nft_*_expr family.  Definitions live in the per-family
 * nftables-churn-exprs-{data,set,stateful,hash,nat,conn}.c TUs.
 * Linkage widened from static to extern so the nft_expr_table
 * dispatch array in nftables-churn.c can reference them across
 * the TU split.  None of these helpers touch nftables-churn.c
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
