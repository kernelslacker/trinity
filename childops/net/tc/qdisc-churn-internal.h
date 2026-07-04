/*
 * tc-qdisc-churn-internal.h
 *
 * Shared declarations split out of childops/tc-qdisc-churn.c so the
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
#include "compat.h"
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
		    __u32 parent);
size_t encode_red_opts(unsigned char *buf, size_t cap);
size_t encode_tbf_opts(unsigned char *buf, size_t cap);

#endif /* CHILDOPS_TC_QDISC_CHURN_INTERNAL_H */
