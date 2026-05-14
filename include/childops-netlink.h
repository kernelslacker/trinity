#pragma once

/*
 * childops-netlink: shared netlink scaffolding for the childops/ tree.
 *
 * Roughly thirty childops each open-coded the same socket+bind+
 * SO_RCVTIMEO sequence, the same per-file static __u32 g_seq + ++g_seq
 * helper, the same {sendmsg, recv, peek-at-NLMSG_ERROR} ack handler,
 * and the same nla_put_*() wrapper family.  This header consolidates
 * the wire-level scaffolding so per-childop code can stay focused on
 * the actual fuzzing payload (message type, attribute selection,
 * ordering) instead of recopying the netlink envelope.
 *
 * Scope of this layer (intentionally narrow):
 *   - Open / close a NETLINK_* socket bound to the kernel, with an
 *     optional multicast subscribe mask and SO_RCVTIMEO.
 *   - Per-context monotonic sequence counter.
 *   - Single-ack send/recv with the majority -EIO-on-non-error
 *     semantic, plus a bounded-retry variant for EAGAIN/EBUSY.
 *   - Type-A nla_put + the typed wrappers used across childops.
 *   - Nested-attribute start/end (the open-coded
 *     ((nlattr *)(buf+li_off))->nla_len = off - li_off; pattern).
 *   - ns_since() monotonic-clock delta.
 *
 * Out of scope (per-childop concerns that stay local):
 *   - Message builders.  These are the fuzzing surface; they belong
 *     next to the per-op coverage rationale.
 *   - genetlink envelope (CTRL_CMD_GETFAMILY, family id, version,
 *     cmd) — wire shape differs enough to deserve its own helper if
 *     and when it lands.
 *   - nfnetlink envelope (subsys + nfgenmsg).  Same.
 *   - Dump / streaming receive.  Single-ack callers are the common
 *     case; dump-style callers live in a couple of files and are
 *     handled per-op for now.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <linux/netlink.h>
#include <linux/types.h>

struct nl_ctx {
	int	fd;
	int	proto;		/* NETLINK_ROUTE, NETLINK_NETFILTER, ... */
	__u32	seq;		/* monotonic per ctx, bumped by nl_seq_next() */
	__u32	groups;		/* multicast subscribe mask, 0 = unicast only */
	int	recv_timeo_s;	/* SO_RCVTIMEO seconds; 0 = no timeout */
};

struct nl_open_opts {
	int	proto;		/* required */
	__u32	groups;		/* default 0 */
	int	recv_timeo_s;	/* default 1 */
};

/*
 * Open a NETLINK_<proto> SOCK_RAW|SOCK_CLOEXEC socket, bind it to the
 * kernel, and set SO_RCVTIMEO if requested.  Initialises *ctx on
 * success.  Returns 0 on success, -1 on failure with errno preserved
 * from socket()/bind().
 */
int nl_open(struct nl_ctx *ctx, const struct nl_open_opts *opts);

/*
 * Close ctx->fd and zero the ctx.  Idempotent on a -1 fd.
 */
void nl_close(struct nl_ctx *ctx);

/*
 * Bump and return the per-ctx sequence counter.  Inline because every
 * message build site calls this on the hot path.
 */
static inline __u32 nl_seq_next(struct nl_ctx *ctx)
{
	return ++ctx->seq;
}

/*
 * Send msg/len then receive exactly one reply.  Returns:
 *   0                — positive ack (NLMSG_ERROR with err == 0).
 *   negated errno    — NLMSG_ERROR rejection.
 *   -EIO             — local sendmsg/recv failure, short recv, or
 *                      any non-NLMSG_ERROR reply (callers that want
 *                      dump-style replies need a different helper).
 */
int nl_send_recv(struct nl_ctx *ctx, void *msg, size_t len);

/*
 * As nl_send_recv() but retries the whole send/recv up to NL_RETRY_MAX
 * times when the kernel returns -EAGAIN or -EBUSY (typical for the
 * config plane when a sibling iteration is mid-teardown).  Other
 * return codes pass through unchanged.
 */
int nl_send_recv_retry(struct nl_ctx *ctx, void *msg, size_t len);

/*
 * Append a netlink attribute at *off in buf (cap bytes total).  Type-A
 * convention: returns the new offset (NLA-aligned), or 0 if the write
 * would overflow cap.  Pads with zeroes between total and aligned len.
 *
 * The typed wrappers below (nla_put_u8/u16/u32/str) all funnel here.
 * Inline so the compiler can fold the trivial cases.
 */
static inline size_t nla_put(unsigned char *buf, size_t off, size_t cap,
			     unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static inline size_t nla_put_u8(unsigned char *buf, size_t off, size_t cap,
				unsigned short type, __u8 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static inline size_t nla_put_u16(unsigned char *buf, size_t off, size_t cap,
				 unsigned short type, __u16 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static inline size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
				 unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static inline size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
				 unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Open a nested attribute of the given type at *off (header only, no
 * payload yet).  Returns the new offset past the bare header, or 0 on
 * overflow.  Caller remembers the start_off it passed in and feeds it
 * back to nla_nest_end() once the nested payload has been appended.
 *
 *   li_off = off;
 *   off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
 *   if (!off) return -EIO;
 *   off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "bridge");
 *   ...
 *   nla_nest_end(buf, li_off, off);
 */
static inline size_t nla_nest_start(unsigned char *buf, size_t off, size_t cap,
				    unsigned short type)
{
	return nla_put(buf, off, cap, type, NULL, 0);
}

/*
 * Patch the nla_len of the nested attribute opened at start_off to
 * reflect everything appended up to end_off.  No-op if end_off ==
 * start_off (empty nest — caller probably hit an overflow, but the
 * nla_len would already be NLA_HDRLEN from nla_nest_start).
 */
static inline void nla_nest_end(unsigned char *buf, size_t start_off,
				size_t end_off)
{
	struct nlattr *nla = (struct nlattr *)(buf + start_off);

	nla->nla_len = (unsigned short)(end_off - start_off);
}

/*
 * Monotonic-clock delta in nanoseconds since *t0.  Returns long long
 * for overflow safety — long is 32 bits on some embedded targets and
 * wraps at ~2.1 s of nanoseconds, which has bitten longer-budget ops.
 * Returns 0 if clock_gettime() fails, matching the per-file copies it
 * replaces.
 */
long long ns_since(const struct timespec *t0);
