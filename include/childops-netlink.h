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
 *     next to the per-op coverage rationale.  The narrow exception
 *     is the rtnl_dellink / rtnl_setlink_up / rtnl_bring_lo_up
 *     triplet below: these are pure boilerplate (one-shot ack'd
 *     RTM_DELLINK / RTM_SETLINK on an ifindex, lo-up dance) that
 *     a dozen-plus ops were copying verbatim with no per-op tuning.
 *   - genetlink envelope (CTRL_CMD_GETFAMILY, family id, version,
 *     cmd) — wire shape differs enough to deserve its own helper if
 *     and when it lands.
 *   - nfnetlink envelope (subsys + nfgenmsg).  Same.
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

/*
 * Safe closed-state initializer for a stack/static nl_ctx.  fd must be
 * -1 so a premature nl_close() is a no-op; a plain { 0 } would leave
 * fd == 0 and close(stdin).  The remaining members read sensibly as
 * zero (no seq, no groups, no timeout) until nl_open() stamps them.
 *
 *   struct nl_ctx ctx = NL_CTX_INIT;
 *   if (nl_open(&ctx, &opts) < 0)
 *           goto out;          // nl_close(&ctx) below stays a no-op
 *   ...
 *   out:
 *           nl_close(&ctx);
 */
#define NL_CTX_INIT	{ .fd = -1 }

/*
 * Companion initializer for struct genl_ctx (defined in
 * include/childops-genl.h).  Mirrors NL_CTX_INIT for the embedded
 * nl_ctx so genl_close() on an unopened ctx is a no-op.
 */
#define GENL_CTX_INIT	{ .nl = NL_CTX_INIT }

struct nl_open_opts {
	int	proto;		/* required */
	__u32	groups;		/* default 0 */
	int	recv_timeo_s;	/* whole seconds; takes precedence if > 0 */
	int	recv_timeo_us;	/* sub-second; used when recv_timeo_s == 0 */
};

/*
 * Open a NETLINK_<proto> SOCK_RAW|SOCK_CLOEXEC socket, bind it to the
 * kernel, and set SO_RCVTIMEO if requested.  ctx->fd is stamped to -1
 * before the first failing syscall, so a partial or failed open leaves
 * a ctx that nl_close() can safely no-op on.  Returns 0 on success,
 * -1 on failure with errno preserved from socket()/bind().
 */
int nl_open(struct nl_ctx *ctx, const struct nl_open_opts *opts);

/*
 * Close ctx->fd and zero the ctx.  Idempotent on a -1 fd; safe to call
 * on a ctx initialised with NL_CTX_INIT even if nl_open() was never
 * invoked.
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
 * Send msg/len then receive exactly one reply, accepting any reply
 * shape as a positive outcome.  Differs from nl_send_recv() only in
 * the non-error reply case: where nl_send_recv() treats RTM_* /
 * payload replies as -EIO, this variant treats them as success.
 * Returns:
 *   0                — any single reply received (NLMSG_ERROR with
 *                      err == 0, or any non-NLMSG_ERROR reply such
 *                      as RTM_NEWLINK / attribute payloads).
 *   negated errno    — NLMSG_ERROR rejection.
 *   -EIO             — local sendmsg/recv failure, short recv, or
 *                      timeout.
 *
 * Canonical caller: altname-thrash, where RTM_GETLINK with
 * IFLA_EXT_MASK=RTEXT_FILTER_VF returns the dump head as a non-error
 * reply and the per-op stat must increment on that case.
 */
int nl_send_recv_any(struct nl_ctx *ctx, void *msg, size_t len);

/*
 * Send msg/len then drain the kernel's reply stream until NLMSG_DONE
 * or NLMSG_ERROR.  Designed for NLM_F_MULTI walkers (RTM_GETLINK
 * dumps and friends).  Replies are not surfaced to the caller — the
 * canonical caller, rtnl-vf-broadcast-getlink, only needs to know
 * the dump completed so the kernel-side walker actually ran.  Add a
 * _dump_cb variant later if a future caller needs per-message
 * inspection.
 *
 * Returns:
 *   0                — dump completed cleanly (NLMSG_DONE seen, or
 *                      NLMSG_ERROR carrying err == 0).
 *   negated errno    — NLMSG_ERROR encountered mid-dump.
 *   -EIO             — local sendmsg/recv failure, short recv,
 *                      timeout, or malformed nlmsghdr stream with no
 *                      DONE/ERROR seen.
 */
int nl_send_recv_dump(struct nl_ctx *ctx, void *msg, size_t len);

/*
 * Send msg/len then drain replies until NLMSG_DONE or NLMSG_ERROR.
 * For every non-terminator nlmsghdr in the stream, invoke
 *   cb(nlh, arg)
 * cb returns 0 to continue, non-zero to abort the dump (returned
 * as -EIO).  Existing nl_send_recv_dump() is unchanged.
 */
int nl_send_recv_dump_cb(struct nl_ctx *ctx, void *msg, size_t len,
			 int (*cb)(const struct nlmsghdr *nlh, void *arg),
			 void *arg);

/*
 * Send msg/len, then drain every queued reply with MSG_DONTWAIT.
 * For every NLMSG_ERROR whose nlmsg_seq matches @expect_seq, invoke
 * on_err(err, arg).  NLMSG_ERROR entries with a different seq are
 * stale acks left in the socket queue by an earlier request (often
 * for a different family) and must not be attributed to this send;
 * they are counted and dropped without firing on_err.  Returns 0
 * once the queue is drained (EAGAIN / EWOULDBLOCK from recv).
 * on_err return value is ignored — drain always runs to completion
 * so the socket queue is clean before the next send.
 */
int nl_send_drain_errors(struct nl_ctx *ctx, void *msg, size_t len,
			 __u32 expect_seq,
			 void (*on_err)(int err, void *arg),
			 void *arg);

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

/*
 * RTM_DELLINK on ifindex.  AF_UNSPEC family, NLM_F_REQUEST|NLM_F_ACK,
 * ifinfomsg payload only.  Returns 0 on positive ack, negated errno
 * on rejection, -EIO on local failure (per nl_send_recv()).
 */
int rtnl_dellink(struct nl_ctx *ctx, int ifindex);

/*
 * RTM_SETLINK on ifindex with ifi_flags=IFF_UP, ifi_change=IFF_UP.
 * AF_UNSPEC family, NLM_F_REQUEST|NLM_F_ACK, ifinfomsg payload only —
 * no flag bits other than IFF_UP are touched.  Return convention is
 * nl_send_recv()'s.
 *
 * The ops that need RTM_NEWLINK semantics on a setlink (vrf-fib,
 * ipv6-pmtu-teardown, vxlan-encap) keep an open-coded copy because
 * the message type is the user-visible behaviour, not boilerplate.
 */
int rtnl_setlink_up(struct nl_ctx *ctx, int ifindex);

/*
 * Bring lo up inside the current netns via RTM_NEWLINK ifi_flags=
 * IFF_UP / ifi_change=IFF_UP.  Resolves "lo" via if_nametoindex();
 * silently returns if lo is absent or the reply is an error — every
 * open-coded copy was best-effort and the rest of the per-op
 * sequence latches on a missing lo naturally.
 */
void rtnl_bring_lo_up(struct nl_ctx *ctx);
