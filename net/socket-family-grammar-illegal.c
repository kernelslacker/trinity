/*
 * Illegal-step machinery for the socket-family grammar executor.
 * Split out of net/socket-family-grammar.c so the invariant-breaking
 * path — the ONE place the coordinator deliberately fires a
 * precondition-violating syscall against ctx->parent_fd / ctx->child_fd
 * — lives in one TU alongside the label publishing, per-family op
 * picker, ordering splicer, and per-op handler.  The coordinator dips
 * in via the prototypes in socket-family-grammar-internal.h with
 * probability ONE_IN(SFG_ILLEGAL_RATE).
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "child.h"
#include "deferred-free.h"
#include "net.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "rnd.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#include "proto-alg-dict.h"

#include "kernel/socket.h"
#ifndef ALG_SET_OP
#define ALG_SET_OP		3
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
#endif
#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT		0
#endif
#endif

#include "socket-family-grammar-internal.h"

const char *sfg_illegal_name(enum sfg_illegal_op op)
{
	switch (op) {
	case SFG_ILLEGAL_NONE:			return "none";
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:	return "accept-non-listener";
	case SFG_ILLEGAL_BIND_AFTER_LISTEN:	return "bind-after-listen";
	case SFG_ILLEGAL_SEND_BEFORE_BIND:	return "send-before-bind";
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:	return "double-shutdown";
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
		return "alg-send-before-setkey";
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
		return "alg-recv-on-empty-tsgl";
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
		return "alg-accept-before-bind";
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
		return "alg-setkey-after-accept";
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
		return "alg-op-direction-mismatch";
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:	return "alg-double-accept";
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		return "alg-set-aead-on-non-aead";
	}
	return "unknown";
}

const char *sfg_conn_state_name(enum sfg_conn_state st)
{
	switch (st) {
	case SFG_CONN_INIT:		return "INIT";
	case SFG_CONN_CREATED:		return "CREATED";
	case SFG_CONN_BOUND:		return "BOUND";
	case SFG_CONN_LISTENING:	return "LISTENING";
	case SFG_CONN_ACCEPTED:		return "ACCEPTED";
	}
	return "UNKNOWN";
}

void sfg_publish_illegal(enum sfg_illegal_op op, enum sfg_conn_state at,
			 int family, int fd)
{
	struct childdata *child = this_child();

	if (child != NULL) {
		child->last_sfg_illegal.op = op;
		child->last_sfg_illegal.at = at;
		child->last_sfg_illegal.family = family;
	}

	output(2, "sfg illegal: %s fd=%d family=%d state=%s\n",
	       sfg_illegal_name(op), fd, family, sfg_conn_state_name(at));
}

enum sfg_illegal_op sfg_pick_illegal_op(int family)
{
	static const enum sfg_illegal_op inet_ops[] = {
		SFG_ILLEGAL_ACCEPT_NON_LISTENER,
		SFG_ILLEGAL_BIND_AFTER_LISTEN,
		SFG_ILLEGAL_SEND_BEFORE_BIND,
		SFG_ILLEGAL_DOUBLE_SHUTDOWN,
	};
#ifdef USE_IF_ALG
	static const enum sfg_illegal_op alg_ops[] = {
		SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY,
		SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL,
		SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND,
		SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT,
		SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH,
		SFG_ILLEGAL_ALG_DOUBLE_ACCEPT,
		SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD,
	};

	if (family == PF_ALG)
		return alg_ops[rnd_modulo_u32(ARRAY_SIZE(alg_ops))];
#endif
	(void)family;
	return inet_ops[rnd_modulo_u32(ARRAY_SIZE(inet_ops))];
}

/*
 * Find the first index of `step` in the ordering, stopping at the
 * SFG_PHASE_END terminator.  Returns -1 if the step is absent (or
 * the ordering is malformed / unterminated within SFG_MAX_PHASES).
 */
static int sfg_find_step(const struct sfg_phase_order *o, unsigned char step)
{
	unsigned int i;

	for (i = 0; i < SFG_MAX_PHASES; i++) {
		if (o->steps[i] == step)
			return (int) i;
		if (o->steps[i] == SFG_PHASE_END)
			return -1;
	}
	return -1;
}

/*
 * Insert `n` step bytes at position `pos`, shifting the rest of the
 * ordering (including the SFG_PHASE_END terminator) right by `n`.
 * Returns false if the resulting ordering would leave no room for
 * the terminator inside SFG_MAX_PHASES.
 */
static bool sfg_insert_steps(struct sfg_phase_order *o, unsigned int pos,
			     const unsigned char *seq, unsigned int n)
{
	unsigned int len = 0;

	while (len < SFG_MAX_PHASES && o->steps[len] != SFG_PHASE_END)
		len++;
	if (len + n >= SFG_MAX_PHASES)
		return false;

	memmove(&o->steps[pos + n], &o->steps[pos],
		(len + 1 - pos) * sizeof(o->steps[0]));
	memcpy(&o->steps[pos], seq, n * sizeof(o->steps[0]));
	return true;
}

/*
 * Splice one illegal step into a legal ordering.  Copies the picked
 * legal order into *out and mutates it in place per the chosen op:
 *
 *   ACCEPT_NON_LISTENER: ILLEGAL inserted immediately BEFORE LISTEN,
 *      so it fires on a BOUND fd that never listen()ed.
 *   BIND_AFTER_LISTEN:   ILLEGAL inserted immediately AFTER LISTEN,
 *      so it fires bind() on a LISTENING fd.
 *   DOUBLE_SHUTDOWN:     ILLEGAL inserted immediately AFTER DATA, so
 *      it fires the double shutdown() on the ACCEPTED child_fd (or
 *      the LISTENING parent_fd if accept never took) once the
 *      coherent walk is otherwise complete.
 *   SEND_BEFORE_BIND:    ILLEGAL + a second DATA inserted immediately
 *      BEFORE BIND.  ILLEGAL publishes the label; the following DATA
 *      step fires sendmsg on the still-CREATED parent_fd (the DATA
 *      case's data_fd fallback resolves to parent_fd when not
 *      ACCEPTED).  The trailing legal DATA leg is untouched.
 *
 * Returns true on successful splice, false if the target step is
 * missing from the input ordering or the insertion would overflow.
 * On false the caller leaves the picked legal ordering unmutated so
 * the walk falls back to a coherent plan.
 */
#ifdef USE_IF_ALG
/*
 * AF_ALG illegal orderings build a fresh hostile plan rather than
 * splicing into a legal one — the AF_ALG preconditions we violate
 * (SETKEY-before-send, non-empty tsgl-before-recv, bind-before-accept)
 * are baked into the LEGAL orderings themselves, so a pure insertion
 * can't achieve "reach ACCEPTED without SETKEY" or "reach RECV without
 * SEND_MORE" shapes.  Overwriting the picked ordering with a bespoke
 * short plan is cleaner than teaching the splicer to remove steps.
 * Every plan starts SOCKET, terminates on SFG_PHASE_ILLEGAL, and stays
 * well inside SFG_MAX_PHASES.
 */
static bool sfg_build_illegal_order_alg(struct sfg_phase_order *out,
					enum sfg_illegal_op op)
{
	static const unsigned char socket_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	static const unsigned char bind_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	static const unsigned char accept_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ALG_ACCEPT, SFG_PHASE_ILLEGAL,
		SFG_PHASE_END };
	static const unsigned char setkey_accept_illegal[] = {
		SFG_PHASE_SOCKET, SFG_PHASE_ALG_BIND,
		SFG_PHASE_ALG_SETKEY, SFG_PHASE_ALG_ACCEPT,
		SFG_PHASE_ILLEGAL, SFG_PHASE_END };
	const unsigned char *src;
	size_t srclen;

	switch (op) {
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
		src = socket_illegal;
		srclen = sizeof(socket_illegal);
		break;
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		/* Fires the SET_AEAD_AUTHSIZE setsockopt after BIND but
		 * before SETKEY, so ctx->fam.alg.type reflects the drawn
		 * algorithm without being masked by later steps. */
		src = bind_illegal;
		srclen = sizeof(bind_illegal);
		break;
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:
		src = accept_illegal;
		srclen = sizeof(accept_illegal);
		break;
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
		src = setkey_accept_illegal;
		srclen = sizeof(setkey_accept_illegal);
		break;
	default:
		return false;
	}
	if (srclen > sizeof(out->steps))
		return false;
	memset(out->steps, 0, sizeof(out->steps));
	memcpy(out->steps, src, srclen);
	return true;
}
#endif /* USE_IF_ALG */

bool sfg_splice_illegal(struct sfg_phase_order *out,
			const struct sfg_phase_order *in,
			enum sfg_illegal_op op)
{
	unsigned char seq[2] = { SFG_PHASE_ILLEGAL, 0 };
	unsigned int nseq = 1;
	int pos;

#ifdef USE_IF_ALG
	switch (op) {
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT:
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD:
		(void)in;
		return sfg_build_illegal_order_alg(out, op);
	default:
		break;
	}
#endif

	*out = *in;

	switch (op) {
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:
		pos = sfg_find_step(out, SFG_PHASE_LISTEN);
		break;
	case SFG_ILLEGAL_BIND_AFTER_LISTEN:
		pos = sfg_find_step(out, SFG_PHASE_LISTEN);
		if (pos >= 0)
			pos++;
		break;
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
		pos = sfg_find_step(out, SFG_PHASE_DATA);
		if (pos >= 0)
			pos++;
		break;
	case SFG_ILLEGAL_SEND_BEFORE_BIND:
		pos = sfg_find_step(out, SFG_PHASE_BIND);
		seq[1] = SFG_PHASE_DATA;
		nseq = 2;
		break;
	default:
		return false;
	}
	if (pos < 0)
		return false;
	return sfg_insert_steps(out, (unsigned int) pos, seq, nseq);
}

/*
 * SFG_PHASE_ILLEGAL handler.  The ONE place in the executor that
 * deliberately bypasses the guard rails the legal phases self-gate
 * with (ACCEPT only when LISTENING; DATA falls back to parent_fd;
 * LISTEN gates on needs_la) — the whole point is to fire the raw
 * illegal syscall against the current fd regardless of conn_state so
 * the kernel path that would normally be unreachable from a coherent
 * walk gets exercised.
 *
 * Publishes labels on both channels (childdata slot + on-wire
 * breadcrumb) IMMEDIATELY BEFORE firing so an oops inside the illegal
 * syscall carries an unambiguous forensic tail on netconsole / logview
 * and lands in the post-mortem summary block via last_sfg_illegal.
 *
 * For SEND_BEFORE_BIND the handler is publish-only: the extra DATA
 * step the splicer put immediately after this pseudo-step fires the
 * actual sendmsg() on the unbound parent_fd (that ordering-only case
 * is what makes SEND_BEFORE_BIND fit the same "one label per walk"
 * contract as the three handler-issued ops).
 */
void sfg_do_illegal_step(struct socket_ctx *ctx,
			 struct socket_triplet *triplet,
			 enum sfg_illegal_op op)
{
	int fd;

	/* Route each op to the fd whose kernel path a real crash would
	 * land on: DOUBLE_SHUTDOWN + the AF_ALG op-fd ops target the
	 * accepted child_fd (falling back to parent_fd if accept never
	 * took); every other op targets the parent_fd (pre-LISTEN accept
	 * / at-LISTEN bind / pre-BIND send / AF_ALG parent-side ops). */
	switch (op) {
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
#ifdef USE_IF_ALG
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY:
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL:
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH:
#endif
		fd = (ctx->child_fd >= 0) ? ctx->child_fd : ctx->parent_fd;
		break;
	default:
		fd = ctx->parent_fd;
		break;
	}

	ctx->illegal_op = op;
	ctx->illegal_at = ctx->conn_state;
	sfg_publish_illegal(op, ctx->conn_state, ctx->family, fd);

	switch (op) {
	case SFG_ILLEGAL_ACCEPT_NON_LISTENER:
		/* accept() on a BOUND-not-LISTENING fd: the guard case in
		 * the legal SFG_PHASE_ACCEPT arm gates on conn_state ==
		 * LISTENING, so no coherent walk ever reaches this kernel
		 * path.  Discard any fd that unexpectedly escapes. */
	{
		int a = accept(fd, NULL, NULL);

		if (a >= 0)
			close(a);
		break;
	}
	case SFG_ILLEGAL_BIND_AFTER_LISTEN: {
		const struct netproto *proto;
		struct sockaddr *addr = NULL;
		socklen_t addrlen = 0;

		if (ctx->family <= 0 || ctx->family >= TRINITY_PF_MAX)
			break;
		proto = net_protocols[ctx->family].proto;
		if (proto == NULL || proto->gen_sockaddr == NULL)
			break;
		/* Fresh sockaddr rather than reusing ctx->bound_addr so a
		 * downstream free path never sees the same pointer twice. */
		proto->gen_sockaddr(triplet, &addr, &addrlen);
		if (addr != NULL) {
			(void) bind(fd, addr, addrlen);
			tracked_free_now(addr);
		}
		break;
	}
	case SFG_ILLEGAL_DOUBLE_SHUTDOWN:
		(void) shutdown(fd, SHUT_RDWR);
		(void) shutdown(fd, SHUT_RDWR);
		break;
	case SFG_ILLEGAL_SEND_BEFORE_BIND:
		/* Publish-only.  The trailing SFG_PHASE_DATA step the
		 * splicer inserted immediately after this pseudo-step
		 * issues the sendmsg on the still-CREATED parent_fd. */
		break;
#ifdef USE_IF_ALG
	case SFG_ILLEGAL_ALG_ACCEPT_BEFORE_BIND:
	case SFG_ILLEGAL_ALG_DOUBLE_ACCEPT: {
		/* accept() on the parent fd.  For ACCEPT_BEFORE_BIND the
		 * parent is CREATED-not-BOUND (af_alg_accept: ask->type is
		 * NULL); for DOUBLE_ACCEPT the parent already yielded one
		 * op fd and a second accept() creates two op sockets
		 * sharing one alg_sock (the refcount edge). */
		int a = accept(fd, NULL, NULL);

		if (a >= 0)
			close(a);
		break;
	}
	case SFG_ILLEGAL_ALG_SEND_BEFORE_SETKEY: {
		/* sendmsg on the ACCEPTED-but-unkeyed op fd.  skcipher /
		 * aead reject unkeyed operations at the ctx->more / setkey
		 * gate in af_alg_sendmsg. */
		unsigned char buf[16];
		struct iovec iov;
		struct msghdr mh;

		generate_rand_bytes(buf, sizeof(buf));
		memset(&mh, 0, sizeof(mh));
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(fd, &mh, MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_RECV_ON_EMPTY_TSGL: {
		/* The documented af_alg_pull_tsgl OOB trigger: recv() on
		 * an ACCEPTED op fd with no accumulated tsgl (walker
		 * skipped SEND_MORE for this walk).  Highest-value member
		 * of the AF_ALG illegal set — exactly the shape upstream
		 * CI has a C reproducer for. */
		unsigned char buf[64];

		(void) recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_SETKEY_AFTER_ACCEPT: {
		/* setsockopt(ALG_SET_KEY) on the parent AFTER the op fd
		 * exists — races af_alg_release_parent refcount
		 * assumptions.  Always fires on ctx->parent_fd (not fd)
		 * because the target is the parent regardless of which fd
		 * the fd-picker returned. */
		unsigned char key[32];

		if (ctx->parent_fd < 0)
			break;
		generate_rand_bytes(key, sizeof(key));
		(void) setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_KEY,
				  key, sizeof(key));
		break;
	}
	case SFG_ILLEGAL_ALG_OP_DIRECTION_MISMATCH: {
		/* sendmsg with ALG_SET_OP=DECRYPT cmsg + random plaintext
		 * -shaped payload.  Feeds aead_recvmsg's length math a
		 * data-vs-authsize mismatch and stresses
		 * crypto_aead_decrypt's -EBADMSG path. */
		unsigned char cbuf[CMSG_SPACE(sizeof(uint32_t))];
		unsigned char payload[64];
		struct iovec iov;
		struct msghdr mh;
		struct cmsghdr *cmsg;
		uint32_t decrypt_op = ALG_OP_DECRYPT;

		memset(cbuf, 0, sizeof(cbuf));
		memset(&mh, 0, sizeof(mh));
		mh.msg_control = cbuf;
		mh.msg_controllen = sizeof(cbuf);
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_OP;
		cmsg->cmsg_len = CMSG_LEN(sizeof(decrypt_op));
		memcpy(CMSG_DATA(cmsg), &decrypt_op, sizeof(decrypt_op));

		generate_rand_bytes(payload, sizeof(payload));
		iov.iov_base = payload;
		iov.iov_len = sizeof(payload);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(fd, &mh, MSG_DONTWAIT);
		break;
	}
	case SFG_ILLEGAL_ALG_SET_AEAD_ON_NON_AEAD: {
		/* ALG_SET_AEAD_AUTHSIZE on a BOUND-but-non-AEAD parent:
		 * the type ->setauthsize hook is NULL.  Fires
		 * unconditionally — a coincidental AEAD draw at bind
		 * would leave this a legal-shape syscall, but the
		 * published label still names the intent so the wire
		 * story is unambiguous. */
		unsigned int authsize;

		if (ctx->parent_fd < 0)
			break;
		authsize = alg_boundary_authsizes[
			rnd_modulo_u32(alg_boundary_authsizes_count)];
		(void) setsockopt(ctx->parent_fd, SOL_ALG,
				  ALG_SET_AEAD_AUTHSIZE, NULL, authsize);
		break;
	}
#endif
	default:
		break;
	}
}
