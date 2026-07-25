/*
 * AF_ALG lifecycle phase handlers for grammar_alg.  Split out of
 * net/socket-family-grammar.c so the ctx-aware AF_ALG state (key_set,
 * alg type, authsize/assoclen staged at SET_AEAD, splice pipe pair)
 * and the AF_ALG-only cmsg / splice helpers live in one TU.  The
 * coordinator (in socket-family-grammar-core.c) dispatches to these
 * from its SFG_PHASE_ALG_* case bodies via the prototypes in
 * socket-family-grammar-internal.h.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "files.h"		/* get_rand_pagecache_fd */
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "rnd.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#include "proto-alg-dict.h"

#include "kernel/fcntl.h"
#include "kernel/splice.h"
#include "kernel/socket.h"
#ifndef ALG_SET_IV
#define ALG_SET_IV		2
#endif
#ifndef ALG_SET_OP
#define ALG_SET_OP		3
#endif
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN	4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
#endif
#ifndef ALG_OP_DECRYPT
#define ALG_OP_DECRYPT		0
#endif
#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT		1
#endif

/* Copy Fail-shaped AEAD name that the retired standalone AF_ALG walker
 * biased at 1-in-8.  Ported here so the CVE-bait probing load stays
 * steady after run_alg_chain retirement.  Kept as a define rather than
 * lifted to a shared header — this is the only site that emits it. */
#define AUTHENCESN_NAME	"authencesn(hmac(sha256),cbc(aes))"

/*
 * Probability (out of 100) that the ALG_SEND_MORE phase substitutes a
 * single splice(tagged_fd -> pipe -> child_fd) pull-from-pagecache for
 * the default N × sendmsg(MSG_MORE) buffer sends.  Re-added from the
 * retired v3 run_alg_chain data leg (ef5622b4ac38 / 1c7259d88947): the
 * splice path reaches alg_sendpage via splice_read_to_pipe, coverage
 * the buffer-sendmsg walk never lands.  Rate matches v3.  On any setup
 * miss (no pagecache fd, pipe2 ENFILE, splice returning <= 0 in
 * either leg) the phase falls through to the buffer sends so the data
 * leg still runs — mirrors alg_chain_iter_drive's discipline.  The
 * pipe pair lives in ctx->fam.alg.splice_pfd (already reserved and
 * initialised to {-1, -1} by the run_grammar_chain designated init)
 * and is torn down unconditionally by the out: label's close gate.
 */
#define SFG_ALG_SPLICE_SUBST_PCT	30

#include "socket-family-grammar-internal.h"

/*
 * AF_ALG phase handlers for grammar_alg (see net/proto/alg.c).  These
 * run as ctx-aware executor case bodies rather than sfg-> callbacks
 * because the stateless (fd, triplet) callback signature can't thread
 * key_set / alg type / staged authsize+assoclen across phases — every
 * handler reads or writes ctx->fam.alg.  The AEAD-only phases self-gate
 * on ctx->fam.alg.type so a non-AEAD algorithm draw at ALG_BIND
 * degenerates cleanly on the full-AEAD ordering.
 *
 * Return true from bind/accept helpers on success; false signals bail
 * to the executor loop so late phases don't run against an unopened fd.
 */

static const struct {
	enum sfg_alg_type sfg;
	enum alg_dict_type dict;
	const char *str;
} sfg_alg_types[] = {
	{ SFG_ALG_TYPE_HASH,	 ALG_DICT_HASH,	    "hash"     },
	{ SFG_ALG_TYPE_SKCIPHER, ALG_DICT_SKCIPHER, "skcipher" },
	{ SFG_ALG_TYPE_AEAD,	 ALG_DICT_AEAD,	    "aead"     },
	{ SFG_ALG_TYPE_RNG,	 ALG_DICT_RNG,	    "rng"      },
};

bool sfg_alg_do_bind(struct socket_ctx *ctx, unsigned int *err_burst)
{
	struct sockaddr_alg *sa = &ctx->fam.alg.sa;
	unsigned int idx;

	if (ctx->conn_state != SFG_CONN_CREATED || ctx->parent_fd < 0)
		return false;

	memset(sa, 0, sizeof(*sa));
	sa->salg_family = AF_ALG;

	if (ONE_IN(8)) {
		/* Copy Fail-shaped bait ported from the retired
		 * run_alg_chain arm: aead/authencesn-with-extended-sn.
		 * Kept on its own 1-in-8 gate so the CVE-bait probing
		 * load stays steady after the standalone AF_ALG walker
		 * went away. */
		strncpy((char *)sa->salg_type, "aead",
			sizeof(sa->salg_type) - 1);
		strncpy((char *)sa->salg_name, AUTHENCESN_NAME,
			sizeof(sa->salg_name) - 1);
		ctx->fam.alg.type = SFG_ALG_TYPE_AEAD;
		__atomic_add_fetch(
			&shm->stats.socket_family_chain.authencesn_attempts,
			1, __ATOMIC_RELAXED);
	} else {
		idx = rnd_modulo_u32(ARRAY_SIZE(sfg_alg_types));
		ctx->fam.alg.type = sfg_alg_types[idx].sfg;
		pick_alg(sfg_alg_types[idx].dict, sfg_alg_types[idx].str, sa);
	}

	if (bind(ctx->parent_fd, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
		/* ENOENT/ESRCH are expected per-alg churn (curated dict
		 * covers algos not built on every kernel); only latch on
		 * signals the AF_ALG surface is unreachable. */
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return false;
	}
	ctx->conn_state = SFG_CONN_BOUND;
	return true;
}

void sfg_alg_do_setkey(struct socket_ctx *ctx)
{
	unsigned char keybuf[4096];
	unsigned int keylen, fill;

	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return;

	/* 70% curated valid 16..47, 30% boundary — same weighting as
	 * alg_socket_setup so grammar walks don't regress key-length
	 * coverage the per-syscall path already delivers. */
	if (rnd_modulo_u32(10) < 7)
		keylen = 16 + rnd_modulo_u32(32);
	else
		keylen = alg_boundary_keylens[
			rnd_modulo_u32(alg_boundary_keylens_count)];
	fill = keylen < sizeof(keybuf) ? keylen : sizeof(keybuf);
	generate_rand_bytes(keybuf, fill);
	if (setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_KEY, keybuf,
		       (socklen_t)keylen) == 0)
		ctx->fam.alg.key_set = true;
	/* rng/akcipher reject ALG_SET_KEY — tolerated; the walk continues
	 * to ACCEPT which may still succeed. */
}

void sfg_alg_do_set_aead(struct socket_ctx *ctx)
{
	static const unsigned int assoclens[] = { 0, 1, 16, 64, 4096, 65536 };
	unsigned int authsize;

	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return;
	/* AEAD-only self-gate: SET_AEAD_AUTHSIZE on a non-aead alg has
	 * type->setauthsize == NULL and returns -ENOPROTOOPT, so firing
	 * it there is noise not coverage. */
	if (ctx->fam.alg.type != SFG_ALG_TYPE_AEAD)
		return;

	authsize = alg_boundary_authsizes[
		rnd_modulo_u32(alg_boundary_authsizes_count)];
	(void) setsockopt(ctx->parent_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
			  NULL, authsize);
	ctx->fam.alg.authsize = authsize;
	ctx->fam.alg.assoclen = assoclens[rnd_modulo_u32(ARRAY_SIZE(assoclens))];
}

bool sfg_alg_do_accept(struct socket_ctx *ctx, unsigned int *err_burst)
{
	if (ctx->conn_state != SFG_CONN_BOUND || ctx->parent_fd < 0)
		return false;

	ctx->child_fd = accept(ctx->parent_fd, NULL, NULL);
	if (ctx->child_fd < 0) {
		if (errno == EPERM || errno == ENOPROTOOPT)
			(*err_burst)++;
		return false;
	}
	ctx->conn_state = SFG_CONN_ACCEPTED;
	return true;
}

/*
 * Push ALG_SET_OP (+ optional ALG_SET_IV + optional
 * ALG_SET_AEAD_ASSOCLEN) as a cmsg batch on an empty-payload
 * sendmsg(MSG_MORE).  Empty-payload MSG_MORE opens the tsgl without
 * committing bytes; the following SEND_MORE case appends the actual
 * plaintext segments.  Assoclen is echoed from the value SET_AEAD
 * staged so aead_recvmsg's assoc-vs-data length math sees a matched
 * pair rather than a random draw.
 */
void sfg_alg_do_cmsg(struct socket_ctx *ctx)
{
	unsigned char cbuf[CMSG_SPACE(sizeof(uint32_t)) +
			   CMSG_SPACE(sizeof(uint32_t) + 32) +
			   CMSG_SPACE(sizeof(uint32_t))];
	struct msghdr mh;
	struct cmsghdr *cmsg;
	uint32_t op, assoclen;
	unsigned char iv_bytes[32];
	uint32_t iv_hdr;
	unsigned int ivlen = 0;
	size_t off = 0;
	bool want_iv = RAND_BOOL();

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	memset(cbuf, 0, sizeof(cbuf));
	memset(&mh, 0, sizeof(mh));

	/* ALG_SET_OP always present. */
	op = RAND_BOOL() ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	cmsg = (struct cmsghdr *)(cbuf + off);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));
	off += CMSG_SPACE(sizeof(op));

	/* ALG_SET_IV: kernel format is af_alg_iv = {u32 ivlen; u8 iv[]}. */
	if (want_iv) {
		ivlen = 8 + rnd_modulo_u32(25);		/* 8..32 */
		iv_hdr = ivlen;
		generate_rand_bytes(iv_bytes, ivlen);
		cmsg = (struct cmsghdr *)(cbuf + off);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(sizeof(iv_hdr) + ivlen);
		memcpy(CMSG_DATA(cmsg), &iv_hdr, sizeof(iv_hdr));
		memcpy(CMSG_DATA(cmsg) + sizeof(iv_hdr), iv_bytes, ivlen);
		off += CMSG_SPACE(sizeof(iv_hdr) + ivlen);
	}

	/* ALG_SET_AEAD_ASSOCLEN: only on AEAD; echoes the value SET_AEAD
	 * staged so aead_recvmsg's assoc-vs-data length math is coherent
	 * (the > sent-length case is exactly the memcpy_sglist GPF shape). */
	if (ctx->fam.alg.type == SFG_ALG_TYPE_AEAD) {
		assoclen = ctx->fam.alg.assoclen;
		cmsg = (struct cmsghdr *)(cbuf + off);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		cmsg->cmsg_len = CMSG_LEN(sizeof(assoclen));
		memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(assoclen));
		off += CMSG_SPACE(sizeof(assoclen));
	}

	mh.msg_control = cbuf;
	mh.msg_controllen = off;
	(void) sendmsg(ctx->child_fd, &mh, MSG_DONTWAIT | MSG_MORE);
}

/*
 * ~SFG_ALG_SPLICE_SUBST_PCT% of the time replace the buffer-sends leg
 * with a splice(tagged_fd -> pipe -> child_fd) pull from a page-cache
 * fd in the OBJ_FD_PAGECACHE pool so the walk reaches alg_sendpage
 * via splice_read_to_pipe -- coverage the buffer-sendmsg path never
 * lands.  Returns true when the splice pair completed and the caller
 * should skip the buffer sends; returns false on any setup miss so
 * the caller falls through.  Bumps socket_family_chain_splice_attempts
 * (retained from the retired run_alg_chain path -- one accounting
 * story for AF_ALG splice attempts, no new stats field) on every
 * attempt regardless of eventual outcome.
 */
static bool sfg_alg_try_splice_send(struct socket_ctx *ctx)
{
	unsigned int sndlen;
	int tagged_fd;
	ssize_t in_n;

	if (rnd_modulo_u32(100) >= SFG_ALG_SPLICE_SUBST_PCT)
		return false;

	tagged_fd = get_rand_pagecache_fd();
	if (tagged_fd < 0)
		return false;

	if (pipe2(ctx->fam.alg.splice_pfd, O_CLOEXEC) < 0)
		return false;

	__atomic_add_fetch(&shm->stats.socket_family_chain.splice_attempts, 1,
			   __ATOMIC_RELAXED);

	sndlen = 16 + rnd_modulo_u32(256 - 16 + 1);
	in_n = splice(tagged_fd, NULL, ctx->fam.alg.splice_pfd[1], NULL,
		      sndlen, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	if (in_n <= 0)
		return false;

	(void) splice(ctx->fam.alg.splice_pfd[0], NULL, ctx->child_fd, NULL,
		      (size_t) in_n, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
	return true;
}

/*
 * N × sendmsg(MSG_MORE) with page-straddling segment sizes.  Drives
 * af_alg_sendmsg's cross-call path: tsgl accumulation across calls,
 * SG-list realloc as the accumulated length crosses the per-tsgl entry
 * cap, page-spanning where a segment's tail lands on a different page
 * from the next segment's head.  Terminal ALG_RECV closes the request
 * with a non-MSG_MORE flush.
 *
 * ~SFG_ALG_SPLICE_SUBST_PCT% of invocations first try a single splice
 * pair via sfg_alg_try_splice_send; on success the buffer-send loop
 * is skipped (the splice already fed the request), on any miss the
 * loop runs so the data leg still lands.
 */
void sfg_alg_do_send_more(struct socket_ctx *ctx)
{
	static const unsigned int seg_sizes[] = {
		1, 4095, 4096, 4097, 8192, 2048, 4096 - 1, 4096 + 1,
	};
	unsigned int n = 2 + rnd_modulo_u32(7);		/* 2..8 */
	unsigned int cap = page_size * 3;
	unsigned char *scratch;
	unsigned int i;

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	if (sfg_alg_try_splice_send(ctx))
		return;

	scratch = zmalloc(cap);
	for (i = 0; i < n; i++) {
		unsigned int seglen = seg_sizes[
			rnd_modulo_u32(ARRAY_SIZE(seg_sizes))];
		struct iovec iov;
		struct msghdr mh;

		if (seglen > cap)
			seglen = cap;
		generate_rand_bytes(scratch, seglen);
		iov.iov_base = scratch;
		iov.iov_len  = seglen;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		(void) sendmsg(ctx->child_fd, &mh, MSG_DONTWAIT | MSG_MORE);
	}
	free(scratch);
}

void sfg_alg_do_recv(struct socket_ctx *ctx)
{
	unsigned char *rcvbuf;
	unsigned int rcvlen;

	if (ctx->conn_state != SFG_CONN_ACCEPTED || ctx->child_fd < 0)
		return;

	rcvlen = 16 + rnd_modulo_u32(4096);
	rcvbuf = zmalloc(rcvlen);
	(void) recv(ctx->child_fd, rcvbuf, rcvlen, MSG_DONTWAIT);
	free(rcvbuf);
}
#endif /* USE_IF_ALG */
