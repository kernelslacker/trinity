/*
 * sock_diag_walker - structured req-builder coverage for the
 * NETLINK_SOCK_DIAG family.
 *
 * The default genetlink fuzzer rarely produces a wire-valid
 * SOCK_DIAG_BY_FAMILY message: each per-family diag handler decodes
 * its own fixed-size request struct followed by NLA-encoded option
 * tail, and a request that fails the early sdiag_family/protocol
 * gate is rejected before any of the interesting per-family parsing
 * is reached.  This walker constructs structurally valid requests
 * for the diag families wired up in the test kernel config and drains
 * the kernel reply, so the per-family parse paths and tail-NLA
 * handlers (which is where the historical OOB / missing-bound
 * defects have lived) actually get executed.
 *
 * Variants (one is picked uniformly per invocation):
 *   - INET (TCP/UDP/UDPLITE/RAW/SCTP/MPTCP for AF_INET and AF_INET6):
 *     struct inet_diag_req_v2 + optional NLA tail with
 *     INET_DIAG_REQ_BYTECODE, INET_DIAG_REQ_PROTOCOL,
 *     INET_DIAG_REQ_SK_BPF_STORAGES.
 *   - UNIX: struct unix_diag_req with random udiag_show mask.
 *   - NETLINK: struct netlink_diag_req with random sdiag_protocol
 *     (valid + invalid) and random ndiag_show mask.
 *   - PACKET: struct packet_diag_req with random pdiag_show mask.
 *   - VSOCK: struct vsock_diag_req.
 *
 * Bytecode emitter: for INET requests we sometimes attach
 * INET_DIAG_REQ_BYTECODE.  The emitter picks a small chain of
 * inet_diag_bc_op entries from the documented opcode set with
 * randomly populated jump offsets and optional inline argument
 * payloads (inet_diag_hostcond, mark/cgroup conds, ifindex).  About
 * 25% of emitted chains are deliberately truncated so the kernel
 * audit walker sees a short message and bytecode whose internal
 * jump offsets can dangle past the end of the chain.  This is the
 * point of the variant -- the validator's run paths are exactly what we
 * want to exercise with malformed-but-plausible programs.
 *
 * Self-bounding: one socket open / one sendto / one bounded recv /
 * one close per invocation.  Receive is non-blocking with a small
 * fixed iteration cap so a busy or chatty kernel can't wedge the
 * child past the alarm(1) cap.  All stack buffers are sized so an
 * NLA tail and the BC payload fit comfortably below RTNL_BUF_BYTES.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/netlink_diag.h>
#include <linux/packet_diag.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <linux/vm_sockets_diag.h>
#include <string.h>
#include <unistd.h>

#include "child.h"
#include "childops-netlink.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/netlink.h"
#include "kernel/socket.h"
#define SD_BUF_BYTES		2048
#define SD_RECV_TIMEO_S		1
#define SD_BC_MAX_OPS		8

enum sd_variant {
	SD_VARIANT_INET = 0,
	SD_VARIANT_UNIX,
	SD_VARIANT_NETLINK,
	SD_VARIANT_PACKET,
	SD_VARIANT_VSOCK,
	NR_SD_VARIANTS,
};

/* Latched once per child if the NETLINK_SOCK_DIAG protocol itself
 * is unavailable (EPROTONOSUPPORT on socket() means the kernel was
 * built without CONFIG_SOCK_DIAG).  No point re-trying every call. */
static bool sd_unsupported;

/*
 * Send `msg`/`len` on ctx->fd and let nl_send_recv_dump() drain the
 * NLM_F_DUMP reply stream until NLMSG_DONE / NLMSG_ERROR (or until
 * the SO_RCVTIMEO=1s recv() returns -EAGAIN, collapsed to -EIO by
 * the helper).  We don't parse the reply -- the goal is to keep the
 * kernel's per-family dump path running long enough to exercise the
 * handler, not to interpret the per-socket entries ourselves.  The
 * dump helper's return code is discarded for the same reason: any
 * non-zero ack just means the kernel's audit / parse path rejected
 * the request, which is itself the bug-class coverage we want.
 */
static void sd_send_drain(struct nl_ctx *ctx, void *msg, size_t len)
{
	(void)nl_send_recv_dump(ctx, msg, len);
}

/*
 * Emit a small bytecode program for INET_DIAG_REQ_BYTECODE.  Each op
 * is a 4-byte struct inet_diag_bc_op header optionally followed by an
 * inline argument payload whose size depends on the opcode.
 *
 * The emitter is deliberately not careful about chain validity:
 * jump targets, inline arg sizes, and chain length are all picked at
 * random within plausible ranges, and ~25% of chains are truncated
 * before the final op completes.  This is the validator's run path's
 * defensive logic the variant is meant to exercise.
 */
static size_t bc_emit(unsigned char *buf, size_t cap)
{
	static const unsigned char op_codes[] = {
		INET_DIAG_BC_NOP,
		INET_DIAG_BC_JMP,
		INET_DIAG_BC_S_GE,
		INET_DIAG_BC_S_LE,
		INET_DIAG_BC_D_GE,
		INET_DIAG_BC_D_LE,
		INET_DIAG_BC_AUTO,
		INET_DIAG_BC_S_COND,
		INET_DIAG_BC_D_COND,
		INET_DIAG_BC_DEV_COND,
		INET_DIAG_BC_MARK_COND,
		INET_DIAG_BC_S_EQ,
		INET_DIAG_BC_D_EQ,
		INET_DIAG_BC_CGROUP_COND,
	};
	unsigned int n_ops;
	unsigned int i;
	size_t off = 0;
	bool truncate;

	n_ops = rnd_modulo_u32(SD_BC_MAX_OPS) + 1;
	truncate = (rand32() & 0x3) == 0;

	for (i = 0; i < n_ops; i++) {
		struct inet_diag_bc_op op;
		unsigned char code = RAND_ARRAY(op_codes);
		size_t arg_len = 0;
		unsigned char arg_buf[24];

		op.code = code;
		/* "yes" branch -- normally length-of-this-op-and-args; the
		 * audit path validates this is in range, so picking random
		 * small values is the point. */
		op.yes  = (unsigned char)(rand32() & 0xff);
		op.no   = (unsigned short)(rand32() & 0xffff);

		switch (code) {
		case INET_DIAG_BC_S_COND:
		case INET_DIAG_BC_D_COND:
		{
			struct inet_diag_hostcond hc;
			memset(&hc, 0, sizeof(hc));
			hc.family     = (rand32() & 1) ? AF_INET : AF_INET6;
			hc.prefix_len = (rand32() & 0x3f);
			hc.port       = (int)(rand32() & 0xffff);
			memcpy(arg_buf, &hc, sizeof(hc));
			arg_len = sizeof(hc);
			break;
		}
		case INET_DIAG_BC_DEV_COND:
		{
			__u32 ifindex = rand32() & 0xff;
			memcpy(arg_buf, &ifindex, sizeof(ifindex));
			arg_len = sizeof(ifindex);
			break;
		}
		case INET_DIAG_BC_MARK_COND:
		{
			struct inet_diag_markcond mk;
			mk.mark = rand32();
			mk.mask = rand32();
			memcpy(arg_buf, &mk, sizeof(mk));
			arg_len = sizeof(mk);
			break;
		}
		case INET_DIAG_BC_CGROUP_COND:
		{
			__u64 cg = ((__u64)rand32() << 32) | rand32();
			memcpy(arg_buf, &cg, sizeof(cg));
			arg_len = sizeof(cg);
			break;
		}
		case INET_DIAG_BC_S_EQ:
		case INET_DIAG_BC_D_EQ:
		{
			/* Small inline arg; the kernel parser pulls a u16
			 * or u32 depending on the surrounding op->yes
			 * value, so we just stuff a few bytes. */
			__u32 v = rand32();
			memcpy(arg_buf, &v, sizeof(v));
			arg_len = sizeof(v);
			break;
		}
		case INET_DIAG_BC_S_GE:
		case INET_DIAG_BC_S_LE:
		case INET_DIAG_BC_D_GE:
		case INET_DIAG_BC_D_LE:
		{
			__u32 port = rand32() & 0xffff;
			memcpy(arg_buf, &port, sizeof(port));
			arg_len = sizeof(port);
			break;
		}
		default:
			break;
		}

		if (off + sizeof(op) + arg_len > cap)
			break;

		memcpy(buf + off, &op, sizeof(op));
		off += sizeof(op);
		if (arg_len) {
			memcpy(buf + off, arg_buf, arg_len);
			off += arg_len;
		}

		/* Truncate mid-chain on the final op so the bytecode walker
		 * sees a header that points past the actual buffer end. */
		if (truncate && i + 1 == n_ops && off > 2)
			off -= 1 + rnd_modulo_u32(2);
	}

	return off;
}

static void variant_inet(struct nl_ctx *ctx)
{
	/* sdiag_protocol is u8; IPPROTO_MPTCP (262) wraps to IPPROTO_TCP (6)
	 * which is what the MPTCP_DIAG handler is registered under anyway,
	 * so the explicit truncation is correct, not a bug. */
	static const __u8 protos[] = {
		IPPROTO_TCP,
		IPPROTO_UDP,
		IPPROTO_UDPLITE,
		IPPROTO_RAW,
		IPPROTO_SCTP,
		(__u8)IPPROTO_MPTCP,
		IPPROTO_DCCP,
	};
	unsigned char buf[SD_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct inet_diag_req_v2 *req;
	size_t off;
	__u32 r = rand32();

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = SOCK_DIAG_BY_FAMILY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	req = (struct inet_diag_req_v2 *)NLMSG_DATA(nlh);
	req->sdiag_family   = (r & 1) ? AF_INET : AF_INET6;
	req->sdiag_protocol = protos[(r >> 1) % (sizeof(protos))];
	req->idiag_ext      = (__u8)(rand32() & 0xff);
	req->pad            = 0;
	/* Rotate the states mask through small valid sets and the
	 * all-states wildcard so the per-state filter paths in
	 * inet_diag_dump_one are reached. */
	req->idiag_states   = (r & 0x4) ? 0xffffu : (1u << rnd_modulo_u32(13));

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));

	/* Optional NLA tail.  Each is independent -- a request with
	 * none, one, two, or all three is valid and exercises a
	 * different branch in the per-family option parser. */
	if (rand32() & 1) {
		unsigned char bc[256];
		size_t bc_len = bc_emit(bc, sizeof(bc));
		if (bc_len)
			off = nla_put(buf, off, sizeof(buf),
					  INET_DIAG_REQ_BYTECODE, bc, bc_len);
	}
	if (rand32() & 1) {
		__u8 proto = RAND_ARRAY(protos);
		off = nla_put(buf, off, sizeof(buf),
				  INET_DIAG_REQ_PROTOCOL, &proto, sizeof(proto));
	}
	if (rand32() & 1) {
		__u32 map_fds[3];
		map_fds[0] = (__u32)(rand32() | 0x80000000u); /* invalid fd */
		map_fds[1] = (__u32)(rand32() & 0xff);
		map_fds[2] = (__u32)(rand32() & 0xff);
		off = nla_put(buf, off, sizeof(buf),
				  INET_DIAG_REQ_SK_BPF_STORAGES,
				  map_fds, sizeof(map_fds));
	}

	if (!off) {
		/* nla_put bailed past the buffer cap -- fall back to
		 * the bare req without tail attributes. */
		off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));
	}
	nlh->nlmsg_len = (__u32)off;

	sd_send_drain(ctx, buf, off);
	__atomic_add_fetch(&shm->stats.sock_diag_walker_inet, 1, __ATOMIC_RELAXED);
}

static void variant_unix(struct nl_ctx *ctx)
{
	unsigned char buf[SD_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct unix_diag_req *req;
	size_t off;
	__u32 show_bits[] = {
		UDIAG_SHOW_NAME, UDIAG_SHOW_VFS, UDIAG_SHOW_PEER,
		UDIAG_SHOW_ICONS, UDIAG_SHOW_RQLEN, UDIAG_SHOW_MEMINFO,
		UDIAG_SHOW_UID,
	};
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = SOCK_DIAG_BY_FAMILY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	req = (struct unix_diag_req *)NLMSG_DATA(nlh);
	req->sdiag_family = AF_UNIX;
	req->udiag_states = (rand32() & 1) ? 0xffffu :
			    (1u << rnd_modulo_u32(13));

	for (i = 0; i < sizeof(show_bits) / sizeof(show_bits[0]); i++) {
		if (rand32() & 1)
			req->udiag_show |= show_bits[i];
	}

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));
	nlh->nlmsg_len = (__u32)off;

	sd_send_drain(ctx, buf, off);
	__atomic_add_fetch(&shm->stats.sock_diag_walker_unix, 1, __ATOMIC_RELAXED);
}

static void variant_netlink(struct nl_ctx *ctx)
{
	unsigned char buf[SD_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct netlink_diag_req *req;
	size_t off;
	__u32 r = rand32();
	__u32 show_bits[] = {
		NDIAG_SHOW_MEMINFO, NDIAG_SHOW_GROUPS,
		NDIAG_SHOW_RING_CFG, NDIAG_SHOW_FLAGS,
	};
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = SOCK_DIAG_BY_FAMILY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	req = (struct netlink_diag_req *)NLMSG_DATA(nlh);
	req->sdiag_family = AF_NETLINK;
	/* NDIAG_PROTO_ALL or any specific netlink protocol number,
	 * including out-of-range values so the per-protocol filter
	 * walks its full range path. */
	req->sdiag_protocol = (r & 1) ? NDIAG_PROTO_ALL :
			      (__u8)(r & 0xff);
	req->ndiag_ino = 0;

	for (i = 0; i < sizeof(show_bits) / sizeof(show_bits[0]); i++) {
		if (rand32() & 1)
			req->ndiag_show |= show_bits[i];
	}

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));
	nlh->nlmsg_len = (__u32)off;

	sd_send_drain(ctx, buf, off);
	__atomic_add_fetch(&shm->stats.sock_diag_walker_netlink, 1, __ATOMIC_RELAXED);
}

static void variant_packet(struct nl_ctx *ctx)
{
	unsigned char buf[SD_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct packet_diag_req *req;
	size_t off;
	__u32 show_bits[] = {
		PACKET_SHOW_INFO, PACKET_SHOW_MCLIST,
		PACKET_SHOW_RING_CFG, PACKET_SHOW_FANOUT,
		PACKET_SHOW_MEMINFO, PACKET_SHOW_FILTER,
	};
	unsigned int i;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = SOCK_DIAG_BY_FAMILY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	req = (struct packet_diag_req *)NLMSG_DATA(nlh);
	req->sdiag_family   = AF_PACKET;
	req->sdiag_protocol = 0;
	req->pdiag_ino      = 0;

	for (i = 0; i < sizeof(show_bits) / sizeof(show_bits[0]); i++) {
		if (rand32() & 1)
			req->pdiag_show |= show_bits[i];
	}

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));
	nlh->nlmsg_len = (__u32)off;

	sd_send_drain(ctx, buf, off);
	__atomic_add_fetch(&shm->stats.sock_diag_walker_packet, 1, __ATOMIC_RELAXED);
}

static void variant_vsock(struct nl_ctx *ctx)
{
	unsigned char buf[SD_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct vsock_diag_req *req;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = SOCK_DIAG_BY_FAMILY;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	req = (struct vsock_diag_req *)NLMSG_DATA(nlh);
	req->sdiag_family   = AF_VSOCK;
	req->sdiag_protocol = 0;
	req->vdiag_states   = (rand32() & 1) ? 0xffffu :
			      (1u << rnd_modulo_u32(13));
	req->vdiag_ino      = 0;
	req->vdiag_show     = 0;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*req));
	nlh->nlmsg_len = (__u32)off;

	sd_send_drain(ctx, buf, off);
	__atomic_add_fetch(&shm->stats.sock_diag_walker_vsock, 1, __ATOMIC_RELAXED);
}

bool sock_diag_walker(struct childdata *child)
{
	struct nl_ctx ctx = { .fd = -1 };
	struct nl_open_opts opts = {
		.proto         = NETLINK_SOCK_DIAG,
		.recv_timeo_s  = SD_RECV_TIMEO_S,
	};
	enum sd_variant v;

	__atomic_add_fetch(&shm->stats.sock_diag_walker_runs, 1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (sd_unsupported)
		return true;

	if (nl_open(&ctx, &opts) < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT) {
			sd_unsupported = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		__atomic_add_fetch(&shm->stats.sock_diag_walker_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	v = (enum sd_variant)rnd_modulo_u32(NR_SD_VARIANTS);
	switch (v) {
	case SD_VARIANT_INET:		variant_inet(&ctx); break;
	case SD_VARIANT_UNIX:		variant_unix(&ctx); break;
	case SD_VARIANT_NETLINK:	variant_netlink(&ctx); break;
	case SD_VARIANT_PACKET:		variant_packet(&ctx); break;
	case SD_VARIANT_VSOCK:		variant_vsock(&ctx); break;
	case NR_SD_VARIANTS:		break;
	}

	nl_close(&ctx);
	return true;
}
