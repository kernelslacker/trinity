/*
 * af_alg_recvmsg_churn -- exercise the AF_ALG send/recv data plane that
 * the existing af_alg_template_probe and af_alg_weak_cipher_probe
 * childops never reach.  Both of those stop at bind+accept; this one
 * drives setkey -> sendmsg(cmsg) -> recvmsg(rotating iov) so the
 * aead_recvmsg memcpy_sglist GPF and af_alg_pull_tsgl slab-OOB shapes
 * upstream CI has C reproducers for actually get hit by the fleet.
 *
 * Per outer iteration:
 *   1. Sample (salg_type, salg_name) from the shared parent-side
 *      alg_dict (net/proto/alg-dict.c) built once at startup from
 *      /proc/crypto + static fallback.  Children inherit the dict via
 *      COW.  Restricted to the aead/skcipher/hash/rng buckets via
 *      ati_to_dict[].
 *   2. socket(AF_ALG, SOCK_SEQPACKET, 0); bind() to (type, name);
 *      accept() the operation fd; SO_RCVTIMEO=1s on the op fd.
 *   3. ONE_IN(2): sendmsg() carrying a CMSG of (SOL_ALG, ALG_SET_KEY)
 *      with a 16-256 byte randomised key (zero length included).
 *   4. ONE_IN(2): sendmsg() carrying a CMSG of (SOL_ALG, ALG_SET_IV)
 *      with an 8-32 byte randomised IV (zero length included).
 *   5. sendmsg() with rotating payload iov layouts -- single-zero,
 *      single-one, 8-iov scatter with a 4096-byte trailer
 *      (af_alg_pull_tsgl shape), oversize 64KB single iov.
 *   6. ALWAYS: a dedicated cmsg-only sendmsg() with empty payload and
 *      no MSG_MORE.  This is the documented af_alg_pull_tsgl trigger
 *      shape -- previously buried as 1-of-5 in the rotating shape
 *      switch, now emitted unconditionally per iter so the slab-OOB
 *      window is hit on every successful bind+accept.
 *   7. recvmsg() with rotating output iov layouts -- 0-length,
 *      oversize, many-small, mismatched-length.  Per-shape counters
 *      (zerolen/oversize) record which path the kernel walked.  All
 *      recv/sendmsg use MSG_DONTWAIT on top of the SO_RCVTIMEO floor.
 *   8. close() both fds.
 *
 * Hard error gate: socket(AF_ALG) returning EAFNOSUPPORT (no
 * CONFIG_CRYPTO_USER_API) latches alg_unsupported for the child's
 * lifetime; the gate flips into the unsupported counter and the op
 * early-returns on subsequent invocations.
 *
 * BUDGETED outer (base 4 / cap 16) with JITTER + 200 ms wall cap.
 * DORMANT in dormant_op_disabled[]; smoke-test before fleet enable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if __has_include(<linux/if_alg.h>)
# include <linux/if_alg.h>
#endif

#include "child.h"
#include "childops-netlink.h"
#include "jitter.h"
#include "proto-alg-dict.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#ifndef ALG_SET_IV
# define ALG_SET_IV			2
#endif

#define ARC_OUTER_BASE			4U
#define ARC_OUTER_CAP			16U
#define ARC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define ARC_RECVMSG_TIMEO_S		1
#define ARC_KEY_MIN			16U
#define ARC_KEY_MAX			256U
#define ARC_IV_MIN			8U
#define ARC_IV_MAX			32U
#define ARC_BIG_IOV_BYTES		(64U * 1024U)
#define ARC_SCATTER_TRAILER		4096U

enum alg_type_idx { ATI_AEAD = 0, ATI_SKCIPHER, ATI_HASH, ATI_RNG, ATI_NR };

static const char * const alg_type_strings[ATI_NR] = {
	"aead", "skcipher", "hash", "rng",
};

/* Map this childop's local type index onto the shared alg_dict bucket
 * built once in the parent by init_alg_template_dict() (called from
 * open_fds() before fork).  Children inherit the dict via COW. */
static const enum alg_dict_type ati_to_dict[ATI_NR] = {
	[ATI_AEAD]	= ALG_DICT_AEAD,
	[ATI_SKCIPHER]	= ALG_DICT_SKCIPHER,
	[ATI_HASH]	= ALG_DICT_HASH,
	[ATI_RNG]	= ALG_DICT_RNG,
};

static bool alg_unsupported;

#ifdef USE_IF_ALG
/* Sample (alg_type, alg_name) from the parent-side dict.  Tries up to
 * ATI_NR random buckets; returns false only if every bucket the
 * childop cares about is empty in the dict (the static fallback in
 * net/proto/alg.c keeps that case unreachable in practice). */
static bool pick_algorithm(enum alg_type_idx *type_out, const char **name_out)
{
	unsigned int attempts;

	for (attempts = 0; attempts < ATI_NR; attempts++) {
		enum alg_type_idx t = (enum alg_type_idx)RAND_RANGE(0, ATI_NR - 1);
		const char **names;
		unsigned int n;

		names = alg_dict_names(ati_to_dict[t], &n);
		if (n == 0)
			continue;
		*type_out = t;
		*name_out = names[rnd_modulo_u32(n)];
		return true;
	}
	return false;
}

/* Send one cmsg-only message carrying (SOL_ALG, op_type, payload).
 * Used for both ALG_SET_KEY and ALG_SET_IV; the kernel consumes the
 * cmsg even when iov is empty.  Caller chooses op (ALG_SET_KEY/IV) and
 * supplies a length that may be zero (the zero-length edge is part of
 * the rotation). */
static void send_cmsg_only(int fd, int op, const void *payload, size_t len)
{
	char buf[CMSG_SPACE(ARC_KEY_MAX)];
	struct msghdr mh = {0};
	struct cmsghdr *cmsg;

	if (len > ARC_KEY_MAX)
		len = ARC_KEY_MAX;

	memset(buf, 0, sizeof(buf));
	mh.msg_control = buf;
	mh.msg_controllen = CMSG_SPACE(len);

	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = op;
	cmsg->cmsg_len = CMSG_LEN(len);
	if (len > 0 && payload != NULL)
		memcpy(CMSG_DATA(cmsg), payload, len);

	(void)sendmsg(fd, &mh, MSG_DONTWAIT);
}

/*
 * Per-child scratch state shared across every iteration of every
 * af_alg_recvmsg_churn() invocation in this child's lifetime.  scratch
 * is sized for the LARGEST single buffer any send/recv shape needs
 * (ARC_BIG_IOV_BYTES, 64K) and is reused by both the send leg (cases
 * that need 4K or 64K) and the recv leg (cases that need up to 64K)
 * because they run strictly sequentially within an iter.  The backing
 * storage is a child-local static lazy-malloc'd on first use and never
 * freed -- post-fork the static lives in COW-private child memory, so
 * each child gets its own buffer and the parent never touches it.
 * Avoids calloc/free of 64K-class buffers on every invocation as well
 * as on the per-iter path; only the random portion is refilled before
 * send (calloc's zero-fill was pure waste -- generate_rand_bytes()
 * overwrites the bytes we actually transmit, and recv writes into the
 * buffer rather than reading from it).
 */
struct alg_recvmsg_child_ctx {
	unsigned char *scratch;
};

/* One sendmsg() with a rotating payload iov.  Returns true iff the
 * chosen layout is the slab-OOB-shaped 8-iov scatter (the
 * af_alg_pull_tsgl trigger shape) so the caller can bump the
 * af_alg_recvmsg_oob_iov counter for operator visibility.  The big
 * scatter trailer and the oversize single iov both live in cctx's
 * per-child scratch (sized for the larger of the two) so the hot
 * send path doesn't calloc/free on every iter. */
static bool send_rotating_payload(int fd, struct alg_recvmsg_child_ctx *cctx)
{
	unsigned char small_buf[1] = {0xa5};
	struct iovec iov[8];
	struct msghdr mh = {0};
	unsigned int shape;
	bool oob = false;
	unsigned int i;

	shape = (unsigned int)RAND_RANGE(0, 3);
	switch (shape) {
	case 0:		/* single zero-length */
		iov[0].iov_base = small_buf;
		iov[0].iov_len = 0;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	case 1:		/* single one-byte */
		iov[0].iov_base = small_buf;
		iov[0].iov_len = 1;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	case 2:		/* 8-iov scatter, mostly empty + 4096B trailer */
		generate_rand_bytes(cctx->scratch, ARC_SCATTER_TRAILER);
		for (i = 0; i < 7; i++) {
			iov[i].iov_base = small_buf;
			iov[i].iov_len = 0;
		}
		iov[7].iov_base = cctx->scratch;
		iov[7].iov_len = ARC_SCATTER_TRAILER;
		mh.msg_iov = iov;
		mh.msg_iovlen = 8;
		oob = true;
		break;
	default:	/* oversize 64KB single iov */
		generate_rand_bytes(cctx->scratch, ARC_BIG_IOV_BYTES);
		iov[0].iov_base = cctx->scratch;
		iov[0].iov_len = ARC_BIG_IOV_BYTES;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	}

	(void)sendmsg(fd, &mh, MSG_DONTWAIT);
	return oob;
}

/* Dedicated trigger for the af_alg_pull_tsgl slab-OOB shape: a
 * cmsg-only sendmsg() with empty payload and no MSG_MORE.  Pulled out
 * of the rotating shape switch so it fires unconditionally per iter
 * rather than 1-of-N -- the trigger is cheap and the shape is the
 * exact one upstream CI has a C reproducer for. */
static void send_empty_cmsg_no_more(int fd)
{
	struct msghdr mh = {0};

	mh.msg_iov = NULL;
	mh.msg_iovlen = 0;
	mh.msg_control = NULL;
	mh.msg_controllen = 0;
	(void)sendmsg(fd, &mh, MSG_DONTWAIT);
}

/* recvmsg() with a rotating output iov.  Mirrors the send shapes so
 * the kernel walks both ends of the sg/tsgl rotation logic.  Each
 * shape is accounted on its own counter so operators can see which
 * recv-side path the kernel actually walked when a crash lands.  The
 * output buffer for every non-zero shape is carved out of cctx's
 * per-child scratch (the many-small case packs 16x64=1024 into the
 * head of the same buffer), so the hot recv path doesn't calloc/free
 * on every iter. */
static void recv_rotating(int fd, struct alg_recvmsg_child_ctx *cctx)
{
	unsigned char tiny[1];
	struct iovec iov[16];
	struct msghdr mh = {0};
	unsigned int shape, i;

	shape = (unsigned int)RAND_RANGE(0, 3);
	switch (shape) {
	case 0:		/* zero-length output */
		iov[0].iov_base = tiny;
		iov[0].iov_len = 0;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.zerolen,
				   1, __ATOMIC_RELAXED);
		break;
	case 1:		/* oversize single iov */
		iov[0].iov_base = cctx->scratch;
		iov[0].iov_len = ARC_BIG_IOV_BYTES;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.oversize,
				   1, __ATOMIC_RELAXED);
		break;
	case 2:		/* many small iovs */
		for (i = 0; i < 16; i++) {
			iov[i].iov_base = cctx->scratch + i * 64;
			iov[i].iov_len = 64;
		}
		mh.msg_iov = iov;
		mh.msg_iovlen = 16;
		break;
	default:	/* mismatched read sizes */
		iov[0].iov_base = cctx->scratch;
		iov[0].iov_len = (size_t)RAND_RANGE(1U, ARC_BIG_IOV_BYTES);
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	}

	(void)recvmsg(fd, &mh, MSG_DONTWAIT);
}

/*
 * Per-invocation state shared across the alg_recvmsg_iter_* helpers.
 * sa is filled by setup and consumed by arm's bind().  parent_fd /
 * child_fd default to -1 via the orchestrator's designated initialiser
 * so the teardown helper's >= 0 gates skip work for fds that were
 * never opened (e.g. when pick_algorithm bails before socket()).
 */
struct alg_recvmsg_iter_ctx {
	struct sockaddr_alg	sa;
	int			parent_fd;
	int			child_fd;
};

/*
 * Phase 1: pick an (alg type, alg name) pair from the shared
 * parent-side alg_dict, open the AF_ALG parent socket, and fill sa
 * with the bind target.  pick_algorithm() returning false (no usable
 * type in the dict, which the static fallback makes effectively
 * unreachable) is a clean bail with no fd to close.  socket(AF_ALG)
 * returning EAFNOSUPPORT latches alg_unsupported so the outer cycle
 * breaks early on the next iter.  Returns 0 on success or -1 to bail
 * to the orchestrator's out: teardown path; on the socket-fail bail
 * parent_fd has captured the -1 from the failed socket() call and the
 * teardown helper's >= 0 gate skips it.  child is threaded in so the
 * EAFNOSUPPORT latch transition records a CHILDOP_LATCH_UNSUPPORTED
 * reason for child->op_type at the same site.
 */
static int alg_recvmsg_iter_setup(struct alg_recvmsg_iter_ctx *ictx,
				  struct childdata *child)
{
	enum alg_type_idx type;
	const char *name;

	if (!pick_algorithm(&type, &name))
		return -1;

	ictx->parent_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ictx->parent_fd < 0) {
		if (errno == EAFNOSUPPORT) {
			alg_unsupported = true;
			/* child->op_type lives in shared memory and can be
			 * scribbled by a poisoned-arena write from a sibling;
			 * bounds-check the snapshot before indexing the
			 * NR_CHILD_OP_TYPES-sized stats array. */
			{
				const enum child_op_type op = child->op_type;
				if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
					__atomic_store_n(&shm->stats.childop.latch_reason[op],
							 CHILDOP_LATCH_UNSUPPORTED,
							 __ATOMIC_RELAXED);
			}
		}
		return -1;
	}

	memset(&ictx->sa, 0, sizeof(ictx->sa));
	ictx->sa.salg_family = AF_ALG;
	strncpy((char *)ictx->sa.salg_type, alg_type_strings[type],
		sizeof(ictx->sa.salg_type) - 1);
	strncpy((char *)ictx->sa.salg_name, name,
		sizeof(ictx->sa.salg_name) - 1);
	return 0;
}

/*
 * Phase 2: bind the parent socket to sa, accept the child fd, and arm
 * SO_RCVTIMEO so a blocking recvmsg in the drive phase trips the
 * 1-second wall instead of stalling the whole inner loop.  bind() /
 * accept() failures bail to the orchestrator's out: which still closes
 * parent_fd via teardown; on success child_fd is owned by the context
 * and teardown closes both.  Returns 0 on success, -1 to bail.
 */
static int alg_recvmsg_iter_arm(struct alg_recvmsg_iter_ctx *ictx)
{
	struct timeval tv;

	if (bind(ictx->parent_fd, (struct sockaddr *)&ictx->sa,
		 sizeof(ictx->sa)) < 0)
		return -1;

	ictx->child_fd = accept(ictx->parent_fd, NULL, NULL);
	if (ictx->child_fd < 0)
		return -1;

	tv.tv_sec = ARC_RECVMSG_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(ictx->child_fd, SOL_SOCKET, SO_RCVTIMEO,
			 &tv, sizeof(tv));
	return 0;
}

/*
 * Phase 3: drive the send leg.  Optional ALG_SET_KEY cmsg (1-in-2,
 * with a 1-in-8 zero-length edge), optional ALG_SET_IV cmsg (same
 * mix), the rotating payload sendmsg() (counter bump on the 8-iov
 * scatter slab-OOB shape), and the dedicated cmsg-only empty-payload
 * trigger that fires unconditionally per iter so the af_alg_pull_tsgl
 * shape lands on every successful arm, not just statistically.  Past
 * the arm() these calls live on the data path the bug class lives in,
 * so per-step failure isn't a kernel-absent signal -- results are
 * ignored.  keybuf/ivbuf are stack-local: only the drive phase reads
 * them, so they don't belong in the cross-phase ictx.
 */
static void alg_recvmsg_iter_drive(struct alg_recvmsg_iter_ctx *ictx,
				   struct alg_recvmsg_child_ctx *cctx)
{
	unsigned char keybuf[ARC_KEY_MAX];
	unsigned char ivbuf[ARC_IV_MAX];

	if (ONE_IN(2)) {
		size_t klen = ONE_IN(8) ? 0 :
			(size_t)RAND_RANGE(ARC_KEY_MIN, ARC_KEY_MAX);

		if (klen > 0)
			generate_rand_bytes(keybuf, klen);
		send_cmsg_only(ictx->child_fd, ALG_SET_KEY, keybuf, klen);
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.setkey_sent,
				   1, __ATOMIC_RELAXED);
	}

	if (ONE_IN(2)) {
		size_t ilen = ONE_IN(8) ? 0 :
			(size_t)RAND_RANGE(ARC_IV_MIN, ARC_IV_MAX);

		if (ilen > 0)
			generate_rand_bytes(ivbuf, ilen);
		send_cmsg_only(ictx->child_fd, ALG_SET_IV, ivbuf, ilen);
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.iv_sent,
				   1, __ATOMIC_RELAXED);
	}

	if (send_rotating_payload(ictx->child_fd, cctx))
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.oob_iov,
				   1, __ATOMIC_RELAXED);

	/* Always emit the af_alg_pull_tsgl trigger shape (cmsg-only,
	 * empty payload, no MSG_MORE) before recvmsg() so the slab-OOB
	 * window is exercised on every iter, not just statistically. */
	send_empty_cmsg_no_more(ictx->child_fd);
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg.empty_cmsg_no_more,
			   1, __ATOMIC_RELAXED);
}

/*
 * Close whichever fds the iteration actually opened.  Runs on every
 * exit path -- success and any early bail from setup or arm.  Both
 * fds default to -1 via the orchestrator's designated initialiser
 * so the >= 0 gates skip work for resources that were never set up.
 * child_fd is closed before parent_fd to match the pre-extraction
 * teardown order (close(op_fd); close(sk)).
 */
static void alg_recvmsg_iter_teardown(struct alg_recvmsg_iter_ctx *ictx)
{
	if (ictx->child_fd >= 0)
		close(ictx->child_fd);
	if (ictx->parent_fd >= 0)
		close(ictx->parent_fd);
}

static void iter_one(struct alg_recvmsg_child_ctx *cctx,
		     struct childdata *child)
{
	struct alg_recvmsg_iter_ctx ictx = {
		.parent_fd = -1,
		.child_fd = -1,
	};

	if (alg_recvmsg_iter_setup(&ictx, child) != 0)
		goto out;

	if (alg_recvmsg_iter_arm(&ictx) != 0)
		goto out;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	alg_recvmsg_iter_drive(&ictx, cctx);
	recv_rotating(ictx.child_fd, cctx);

out:
	alg_recvmsg_iter_teardown(&ictx);
}

bool af_alg_recvmsg_churn(struct childdata *child)
{
	/* Child-local lazy-allocated scratch, sized for the largest
	 * single buffer any send/recv shape uses.  First call mallocs;
	 * subsequent calls (and every iter within them) reuse the same
	 * pointer for the child's lifetime.  Post-fork the static is COW-
	 * private so each child gets its own buffer.  No free() -- the
	 * buffer dies with the child.  malloc (not calloc): only the
	 * random portion is refilled per send and recv writes into the
	 * buffer, so zero-fill would be discarded immediately. */
	static unsigned char *scratch;
	struct alg_recvmsg_child_ctx cctx;
	struct timespec t0;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.af_alg_recvmsg.runs, 1, __ATOMIC_RELAXED);

	if (alg_unsupported) {
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg.unsupported,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (scratch == NULL) {
		scratch = malloc(ARC_BIG_IOV_BYTES);
		if (scratch == NULL)
			return true;
	}
	cctx.scratch = scratch;

	if (clock_gettime(CLOCK_MONOTONIC, &t0) < 0) {
		t0.tv_sec = 0;
		t0.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_AF_ALG_RECVMSG_CHURN,
			       JITTER_RANGE(ARC_OUTER_BASE));
	if (outer_iters > ARC_OUTER_CAP)
		outer_iters = ARC_OUTER_CAP;
	if (outer_iters == 0)
		outer_iters = 1;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t0) >= ARC_WALL_CAP_NS)
			break;
		iter_one(&cctx, child);
		if (alg_unsupported)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/if_alg.h>) */

bool af_alg_recvmsg_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg.runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg.unsupported,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
