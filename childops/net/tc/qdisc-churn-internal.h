/*
 * tc-qdisc-churn-internal.h
 *
 * Shared declarations split out of childops/net/tc/qdisc-churn.c so the
 * tc-nlmsg builder family (build_*qdisc / build_*tclass / build_*tfilter
 * / build_dummy_create / build_bridge_create / build_veth_pair /
 * build_setlink_master / build_qfq_class / build_newqdisc_opts and the
 * encode_red_opts / encode_tbf_opts TCA_OPTIONS encoders) can live in
 * its own translation unit and compile in parallel with the driver TU.
 * This header is private to the two TUs that make up tc-qdisc-churn —
 * do not include it from anywhere else.
 *
 * Contents:
 *   - the UAPI conditional #includes and their fallback macros, so
 *     both TUs see exactly the same pkt_sched / pkt_cls / rtnetlink
 *     symbol values;
 *   - the RTNL_BUF_BYTES message-buffer ceiling, shared between the
 *     core driver loop and the per-builder scratch buffers;
 *   - the peek_opts_encoder function-pointer typedef, used by both
 *     the encoder family (definition side) and the peek_parents[]
 *     dispatch table in the core TU;
 *   - forward declarations for every build_* and encode_* helper,
 *     deliberately widened from file-static to external linkage so
 *     the driver loop and the peek_parents[] table in tc-qdisc-churn.c
 *     can reference them across the TU boundary.
 */

#ifndef CHILDOPS_TC_QDISC_CHURN_INTERNAL_H
#define CHILDOPS_TC_QDISC_CHURN_INTERNAL_H

#if __has_include(<linux/pkt_sched.h>)
#include <linux/pkt_sched.h>
#endif
#if __has_include(<linux/pkt_cls.h>)
#include <linux/pkt_cls.h>
#endif
#if __has_include(<linux/veth.h>)
#include <linux/veth.h>
#endif

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "childops-netlink.h"
#include "kernel/if_ether.h"

/*
 * UAPI fallbacks.  pkt_sched.h / pkt_cls.h on stripped sysroots may
 * not have all of these; the IDs are stable in the kernel UAPI.  If
 * a header is missing entirely the __has_include gates above keep
 * compilation working and these defines fill in.
 */
#ifndef TC_H_ROOT
#define TC_H_ROOT		(0xFFFFFFFFU)
#endif
#ifndef TC_H_MAJ_MASK
#define TC_H_MAJ_MASK		(0xFFFF0000U)
#endif
#ifndef TC_H_MIN_MASK
#define TC_H_MIN_MASK		(0x0000FFFFU)
#endif

/* TCA_* attribute IDs (kernel UAPI; stable). */
#ifndef TCA_UNSPEC
#define TCA_UNSPEC		0
#define TCA_KIND		1
#define TCA_OPTIONS		2
#endif

/* cls_u32 TCA_OPTIONS attribute IDs (kernel UAPI; stable). */
#ifndef TCA_U32_UNSPEC
#define TCA_U32_UNSPEC		0
#define TCA_U32_CLASSID		1
#define TCA_U32_HASH		2
#define TCA_U32_LINK		3
#define TCA_U32_DIVISOR		4
#define TCA_U32_SEL		5
#define TCA_U32_POLICE		6
#define TCA_U32_ACT		7
#define TCA_U32_INDEV		8
#define TCA_U32_PCNT		9
#define TCA_U32_MARK		10
#define TCA_U32_FLAGS		11
#endif

/* cls filter flags (kernel UAPI; stable).  SKIP_SW alone is valid;
 * only SKIP_HW|SKIP_SW together is rejected by tc_flags_valid(). */
#ifndef TCA_CLS_FLAGS_SKIP_SW
#define TCA_CLS_FLAGS_SKIP_SW	(1 << 1)
#endif

/* sch_qfq per-class TCA_OPTIONS attribute IDs (kernel UAPI; stable). */
#ifndef TCA_QFQ_WEIGHT
#define TCA_QFQ_WEIGHT		1
#define TCA_QFQ_LMAX		2
#endif

/* sch_drr per-class TCA_OPTIONS attribute ID (kernel UAPI; stable). */
#ifndef TCA_DRR_QUANTUM
#define TCA_DRR_QUANTUM		1
#endif

/* TCA_STAB sub-namespace attribute IDs (kernel UAPI; stable). */
#ifndef TCA_STAB_BASE
#define TCA_STAB_BASE		1
#define TCA_STAB_DATA		2
#endif

/* RTM_* qdisc / class / filter message types (kernel UAPI; stable). */
#ifndef RTM_NEWQDISC
#define RTM_NEWQDISC		36
#define RTM_DELQDISC		37
#define RTM_NEWTCLASS		40
#define RTM_DELTCLASS		41
#define RTM_NEWTFILTER		44
#define RTM_DELTFILTER		45
#endif

/* Reasonable ceiling on a single rtnl message + payload.  The
 * NEWTFILTER message with TCA_KIND + TCA_OPTIONS (empty) is the
 * largest we emit; well under 512 B.  2 KiB leaves headroom for
 * future per-kind option blobs without resizing. */
#define RTNL_BUF_BYTES		2048

/*
 * TCA_OPTIONS payload encoder for the peek-stack sub-mode.  Definitions
 * live in tc-qdisc-churn-builders.c (encode_red_opts / encode_tbf_opts);
 * the peek_parents[] dispatch table in tc-qdisc-churn.c stores function
 * pointers of this type, which is why the typedef has to be visible to
 * both TUs.
 */
typedef size_t (*peek_opts_encoder)(unsigned char *buf, size_t cap);

/*
 * tc-nlmsg builder family.  Definitions live in tc-qdisc-churn-builders.c.
 * Linkage widened from static to extern so the driver loop and the
 * peek_parents[] dispatch in tc-qdisc-churn.c can reference them across
 * the TU split.  None of these helpers touch tc-qdisc-churn.c file-scope
 * state; they only consume caller-provided buffers, the netlink ctx, and
 * shared netlink helpers.
 */
int build_dummy_create(struct nl_ctx *ctx, const char *name);
int build_bridge_create(struct nl_ctx *ctx, const char *name);
int build_veth_pair(struct nl_ctx *ctx, const char *name, const char *peer);
int build_setlink_master(struct nl_ctx *ctx, int slave_idx, int master_idx);
int build_newqdisc(struct nl_ctx *ctx, int ifindex, __u32 handle,
		   __u32 parent, const char *kind, __u16 extra_flags);
int build_delqdisc(struct nl_ctx *ctx, int ifindex, __u32 handle,
		   __u32 parent);
int build_newtclass(struct nl_ctx *ctx, int ifindex, __u32 handle,
		    __u32 parent, const char *kind);
int build_newtfilter(struct nl_ctx *ctx, int ifindex, __u32 parent,
		     const char *kind);
int build_deltfilter(struct nl_ctx *ctx, int ifindex, __u32 parent);
int build_newqdisc_opts(struct nl_ctx *ctx, int ifindex, __u32 handle,
			__u32 parent, const char *kind,
			peek_opts_encoder enc,
			unsigned short inner_type, __u16 extra_flags);
int build_qfq_class(struct nl_ctx *ctx, int ifindex, __u32 handle,
		    __u32 parent, __u32 weight, __u32 lmax,
		    __u16 extra_flags);
size_t encode_red_opts(unsigned char *buf, size_t cap);
size_t encode_tbf_opts(unsigned char *buf, size_t cap);

/*
 * build_newqdisc_stab - RTM_NEWQDISC with a TCA_STAB nest appended.
 * Mirrors build_newqdisc but emits TCA_STAB_BASE (struct tc_sizespec
 * with bounded overhead field) and TCA_STAB_DATA (tsize u16 entries)
 * so qdisc_get_stab() can install a valid size table.
 *
 * Safety: overhead drawn from [0, 4095] by default to avoid the
 * multi-second spinlock stall described in qdisc-churn-builders.c.
 */
int build_newqdisc_stab(struct nl_ctx *ctx, int ifindex, __u32 handle,
			__u32 parent, const char *kind, __u16 extra_flags);

/*
 * build_newtclass_with_quantum - RTM_NEWTCLASS with a drawn quantum
 * inside TCA_OPTIONS.  For DRR: TCA_DRR_QUANTUM u32 in [256, 4096]
 * bytes exercises the deficit-accounting path instead of always
 * relying on the driver MTU default.
 */
int build_newtclass_with_quantum(struct nl_ctx *ctx, int ifindex,
				 __u32 handle, __u32 parent,
				 const char *kind, __u32 quantum);

/*
 * u32 filter builders for the SKIP_SW refcount-leak oracle arm.
 * build_u32_divisor: RTM_NEWTFILTER kind="u32", TCA_OPTIONS{ TCA_U32_DIVISOR=1 }
 *   creates an hnode with the given handle (htid encoded in top 12 bits).
 * build_u32_filter_link: RTM_NEWTFILTER kind="u32",
 *   TCA_OPTIONS{ TCA_U32_SEL=<minimal 1-key sel>, TCA_U32_LINK=link_handle,
 *   TCA_U32_FLAGS=flags }.  use_excl controls NLM_F_EXCL.
 * build_deltfilter_handle: RTM_DELTFILTER targeting a specific handle
 *   (rather than the bulk-delete-all form of build_deltfilter).
 */
int build_u32_divisor(struct nl_ctx *ctx, int ifindex, __u32 handle,
		      __u32 parent);
int build_u32_filter_link(struct nl_ctx *ctx, int ifindex, __u32 handle,
			  __u32 parent, __u32 link_handle, __u32 flags,
			  bool use_excl);
int build_deltfilter_handle(struct nl_ctx *ctx, int ifindex, __u32 handle,
			    __u32 parent);

#endif /* CHILDOPS_TC_QDISC_CHURN_INTERNAL_H */
