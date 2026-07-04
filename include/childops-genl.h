#pragma once

/*
 * childops-genl: shared genetlink scaffolding for the childops/ tree.
 *
 * A handful of childops open a NETLINK_GENERIC socket, resolve a
 * family id via CTRL_CMD_GETFAMILY, and then build messages with the
 * genlmsghdr framing above nlmsghdr.  The socket bring-up, sequence
 * counter, and Type-A nla_put helpers come from childops-netlink.h;
 * this header adds the genl-specific surface on top.
 *
 * Scope of this layer (intentionally narrow):
 *   - Open / close a NETLINK_GENERIC socket and resolve a single
 *     family id at open time via CTRL_CMD_GETFAMILY.
 *   - Build a genlmsghdr-prefixed nlmsghdr (nlmsg_type =
 *     ctx->family_id, genlmsghdr.cmd, genlmsghdr.version =
 *     ctx->version).
 *   - Single-ack send/recv that treats a non-NLMSG_ERROR reply as
 *     success (genl GETs return data, not an explicit ack).
 *
 * Out of scope (per-childop concerns that stay local):
 *   - Multicast group membership.  Per-family attribute parsing.
 *   - Per-cmd message builders — they are the fuzzing surface and
 *     belong next to their per-op coverage rationale.
 *   - EINPROGRESS retry.  Devlink doesn't retry on it; nl80211 does.
 *     The per-file _retry loops stay local until a clean retry
 *     pattern emerges across several genl callers.
 *   - Dump / streaming receive.  Single-ack callers are the common
 *     case; the one existing dump caller (genl_dump in nl80211-
 *     churn.c) stays local.
 *   - The shared dump-based resolver in net/netlink/genl/families.c
 *     is separate by design — it walks every registered family in
 *     one dump for the genetlink-fuzzer / per-family stats wire-up.
 *     The per-ctx GETFAMILY here is a single-family unicast.
 */

#include <linux/types.h>

#include "childops-netlink.h"

struct genl_ctx {
	struct nl_ctx	nl;		/* underlying NETLINK_GENERIC socket */
	__u16		family_id;	/* resolved at open time */
	__u8		version;	/* family-specific, default 1 */
};

struct genl_open_opts {
	const char	*family_name;	/* required, e.g. "devlink" */
	__u8		version;	/* default 1 if 0 */
	__u32		groups;		/* multicast subscribe mask, 0 = unicast only */
	int		recv_timeo_s;	/* SO_RCVTIMEO seconds; 0 -> default 1 */
};

/*
 * Open NETLINK_GENERIC, resolve family_id via CTRL_CMD_GETFAMILY.
 * Returns 0 on success and stamps ctx->family_id / ctx->version.
 *   -ENOENT          — kernel doesn't know the requested family
 *                      (module not loaded, family stripped from build).
 *                      Caller decides whether this is fatal (devlink
 *                      usually present) or a soft skip.
 *   negated errno    — other NLMSG_ERROR rejection from the CTRL
 *                      handler.
 *   -EIO             — local socket / sendmsg / recv failure or a
 *                      short / malformed reply.
 * On any failure the socket is closed and ctx is left zeroed.
 */
int genl_open(struct genl_ctx *ctx, const struct genl_open_opts *opts);

/*
 * Close ctx->nl.fd and zero the ctx.  Idempotent on an already-closed
 * ctx.
 */
void genl_close(struct genl_ctx *ctx);

/*
 * Build a genlmsghdr-prefixed nlmsghdr at *off into buf (cap bytes
 * total):
 *   nlh->nlmsg_type  = ctx->family_id
 *   nlh->nlmsg_flags = flags | NLM_F_REQUEST | NLM_F_ACK
 *   nlh->nlmsg_seq   = seq
 *   genlmsghdr: cmd, version = ctx->version, reserved = 0
 * Returns the new offset past the genlmsghdr, or 0 on overflow.
 * Callers append per-cmd attrs from there and write nlh->nlmsg_len
 * once the message is complete.
 */
size_t genl_msg_put(unsigned char *buf, size_t off, size_t cap,
		    struct genl_ctx *ctx, __u32 seq,
		    __u8 cmd, __u16 flags);

/*
 * Send msg/len then receive exactly one reply.  Returns:
 *   0                — positive ack (NLMSG_ERROR err == 0) OR any
 *                      non-NLMSG_ERROR reply (genl GETs return data,
 *                      not an ack — same semantic the prior per-file
 *                      devlink_genl_send_recv used).
 *   negated errno    — NLMSG_ERROR rejection.
 *   -EIO             — local sendmsg / recv failure or short recv.
 */
int genl_send_recv(struct genl_ctx *ctx, void *msg, size_t len);
