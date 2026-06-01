/*
 * af_alg_recvmsg_churn -- exercise the AF_ALG send/recv data plane that
 * the existing af_alg_template_probe and af_alg_weak_cipher_probe
 * childops never reach.  Both of those stop at bind+accept; this one
 * drives setkey -> sendmsg(cmsg) -> recvmsg(rotating iov) so the
 * aead_recvmsg memcpy_sglist GPF and af_alg_pull_tsgl slab-OOB shapes
 * upstream CI has C reproducers for actually get hit by the fleet.
 *
 * Per outer iteration:
 *   1. Sample (salg_type, salg_name) from a /proc/crypto cache built on
 *      first use and refreshed once every ~256 invocations.  Cache
 *      holds up to MAX_ALGS_PER_TYPE = 32 names per
 *      aead/skcipher/hash/rng family.
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
 * Hard error gates: socket(AF_ALG) returning EAFNOSUPPORT (no
 * CONFIG_CRYPTO_USER_API) latches alg_unsupported for the child's
 * lifetime; an unreadable /proc/crypto latches crypto_proc_unsupported
 * separately.  Either gate flips into the unsupported counter and the
 * op early-returns on subsequent invocations.
 *
 * BUDGETED outer (base 4 / cap 16) with JITTER + 200 ms wall cap.
 * DORMANT in dormant_op_disabled[]; smoke-test before fleet enable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#if __has_include(<linux/if_alg.h>)
# include <linux/if_alg.h>
#endif

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#ifndef AF_ALG
# define AF_ALG				38
#endif
#ifndef SOL_ALG
# define SOL_ALG			279
#endif
#ifndef ALG_SET_KEY
# define ALG_SET_KEY			1
#endif
#ifndef ALG_SET_IV
# define ALG_SET_IV			2
#endif

#define ARC_OUTER_BASE			4U
#define ARC_OUTER_CAP			16U
#define ARC_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define ARC_RECVMSG_TIMEO_S		1
#define MAX_ALGS_PER_TYPE		32U
#define ARC_CACHE_REFRESH_PERIOD	256U
#define ARC_KEY_MIN			16U
#define ARC_KEY_MAX			256U
#define ARC_IV_MIN			8U
#define ARC_IV_MAX			32U
#define ARC_BIG_IOV_BYTES		(64U * 1024U)
#define ARC_SCATTER_TRAILER		4096U
#define ARC_NAME_MAX			63U

enum alg_type_idx { ATI_AEAD = 0, ATI_SKCIPHER, ATI_HASH, ATI_RNG, ATI_NR };

static const char * const alg_type_strings[ATI_NR] = {
	"aead", "skcipher", "hash", "rng",
};

static char alg_cache[ATI_NR][MAX_ALGS_PER_TYPE][ARC_NAME_MAX + 1];
static unsigned int alg_cache_count[ATI_NR];
static bool alg_cache_built;
static unsigned int arc_invocation_counter;

static bool alg_unsupported;
static bool crypto_proc_unsupported;

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

#ifdef USE_IF_ALG
/* Rebuild alg_cache[][] from /proc/crypto.  Keep the first
 * MAX_ALGS_PER_TYPE names per type; later entries are silently
 * dropped (the cache is a sample, not an enumeration).  Returns false
 * iff /proc/crypto can't be opened, so the caller can latch
 * crypto_proc_unsupported and skip future cache rebuilds. */
static bool rebuild_alg_cache(void)
{
	FILE *f;
	char line[256];
	char cur_name[ARC_NAME_MAX + 1] = {0};

	f = fopen("/proc/crypto", "re");
	if (f == NULL)
		return false;

	memset(alg_cache_count, 0, sizeof(alg_cache_count));

	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "name", 4) == 0) {
			const char *p = strchr(line, ':');

			cur_name[0] = '\0';
			if (p != NULL) {
				p++;
				while (*p == ' ' || *p == '\t')
					p++;
				snprintf(cur_name, sizeof(cur_name), "%s", p);
				cur_name[strcspn(cur_name, "\r\n")] = '\0';
			}
		} else if (strncmp(line, "type", 4) == 0) {
			const char *p = strchr(line, ':');
			enum alg_type_idx t;

			if (p == NULL || cur_name[0] == '\0')
				continue;
			p++;
			while (*p == ' ' || *p == '\t')
				p++;
			for (t = 0; t < ATI_NR; t++) {
				size_t tlen = strlen(alg_type_strings[t]);

				if (strncmp(p, alg_type_strings[t], tlen) != 0)
					continue;
				if (p[tlen] != '\n' && p[tlen] != '\r' &&
				    p[tlen] != '\0')
					continue;
				if (alg_cache_count[t] >= MAX_ALGS_PER_TYPE)
					break;
				snprintf(alg_cache[t][alg_cache_count[t]],
					 sizeof(alg_cache[t][0]), "%s", cur_name);
				alg_cache_count[t]++;
				break;
			}
		}
	}
	fclose(f);
	alg_cache_built = true;
	return true;
}

static bool pick_algorithm(enum alg_type_idx *type_out, const char **name_out)
{
	unsigned int attempts;

	for (attempts = 0; attempts < ATI_NR; attempts++) {
		enum alg_type_idx t = (enum alg_type_idx)RAND_RANGE(0, ATI_NR - 1);

		if (alg_cache_count[t] == 0)
			continue;
		*type_out = t;
		*name_out = alg_cache[t][rnd_modulo_u32(alg_cache_count[t])];
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

/* One sendmsg() with a rotating payload iov.  Returns true iff the
 * chosen layout is the slab-OOB-shaped 8-iov scatter (the
 * af_alg_pull_tsgl trigger shape) so the caller can bump the
 * af_alg_recvmsg_oob_iov counter for operator visibility. */
static bool send_rotating_payload(int fd)
{
	unsigned char small_buf[1] = {0xa5};
	unsigned char *big = NULL;
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
		big = calloc(1, ARC_SCATTER_TRAILER);
		if (big == NULL)
			return false;
		generate_rand_bytes(big, ARC_SCATTER_TRAILER);
		for (i = 0; i < 7; i++) {
			iov[i].iov_base = small_buf;
			iov[i].iov_len = 0;
		}
		iov[7].iov_base = big;
		iov[7].iov_len = ARC_SCATTER_TRAILER;
		mh.msg_iov = iov;
		mh.msg_iovlen = 8;
		oob = true;
		break;
	default:	/* oversize 64KB single iov */
		big = calloc(1, ARC_BIG_IOV_BYTES);
		if (big == NULL)
			return false;
		generate_rand_bytes(big, ARC_BIG_IOV_BYTES);
		iov[0].iov_base = big;
		iov[0].iov_len = ARC_BIG_IOV_BYTES;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	}

	(void)sendmsg(fd, &mh, MSG_DONTWAIT);
	free(big);
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
 * recv-side path the kernel actually walked when a crash lands. */
static void recv_rotating(int fd)
{
	unsigned char tiny[1];
	unsigned char *big = NULL;
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
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_zerolen,
				   1, __ATOMIC_RELAXED);
		break;
	case 1:		/* oversize single iov */
		big = calloc(1, ARC_BIG_IOV_BYTES);
		if (big == NULL)
			return;
		iov[0].iov_base = big;
		iov[0].iov_len = ARC_BIG_IOV_BYTES;
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_oversize,
				   1, __ATOMIC_RELAXED);
		break;
	case 2:		/* many small iovs */
		big = calloc(16, 64);
		if (big == NULL)
			return;
		for (i = 0; i < 16; i++) {
			iov[i].iov_base = big + i * 64;
			iov[i].iov_len = 64;
		}
		mh.msg_iov = iov;
		mh.msg_iovlen = 16;
		break;
	default:	/* mismatched read sizes */
		big = calloc(1, ARC_BIG_IOV_BYTES);
		if (big == NULL)
			return;
		iov[0].iov_base = big;
		iov[0].iov_len = (size_t)RAND_RANGE(1U, ARC_BIG_IOV_BYTES);
		mh.msg_iov = iov;
		mh.msg_iovlen = 1;
		break;
	}

	(void)recvmsg(fd, &mh, MSG_DONTWAIT);
	free(big);
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
 * Phase 1: pick an (alg type, alg name) pair from the /proc/crypto-
 * backed cache, open the AF_ALG parent socket, and fill sa with the
 * bind target.  pick_algorithm() returning false (no usable type in
 * the cache yet) is a clean bail with no fd to close.  socket(AF_ALG)
 * returning EAFNOSUPPORT latches alg_unsupported so the outer cycle
 * breaks early on the next iter.  Returns 0 on success or -1 to bail
 * to the orchestrator's out: teardown path; on the socket-fail bail
 * parent_fd has captured the -1 from the failed socket() call and the
 * teardown helper's >= 0 gate skips it.
 */
static int alg_recvmsg_iter_setup(struct alg_recvmsg_iter_ctx *ictx)
{
	enum alg_type_idx type;
	const char *name;

	if (!pick_algorithm(&type, &name))
		return -1;

	ictx->parent_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ictx->parent_fd < 0) {
		if (errno == EAFNOSUPPORT)
			alg_unsupported = true;
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

static void iter_one(void)
{
	struct alg_recvmsg_iter_ctx ictx = {
		.parent_fd = -1,
		.child_fd = -1,
	};
	unsigned char keybuf[ARC_KEY_MAX];
	unsigned char ivbuf[ARC_IV_MAX];

	if (alg_recvmsg_iter_setup(&ictx) != 0)
		goto out;

	if (alg_recvmsg_iter_arm(&ictx) != 0)
		goto out;

	if (ONE_IN(2)) {
		size_t klen = ONE_IN(8) ? 0 :
			(size_t)RAND_RANGE(ARC_KEY_MIN, ARC_KEY_MAX);

		if (klen > 0)
			generate_rand_bytes(keybuf, klen);
		send_cmsg_only(ictx.child_fd, ALG_SET_KEY, keybuf, klen);
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_setkey_sent,
				   1, __ATOMIC_RELAXED);
	}

	if (ONE_IN(2)) {
		size_t ilen = ONE_IN(8) ? 0 :
			(size_t)RAND_RANGE(ARC_IV_MIN, ARC_IV_MAX);

		if (ilen > 0)
			generate_rand_bytes(ivbuf, ilen);
		send_cmsg_only(ictx.child_fd, ALG_SET_IV, ivbuf, ilen);
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_iv_sent,
				   1, __ATOMIC_RELAXED);
	}

	if (send_rotating_payload(ictx.child_fd))
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_oob_iov,
				   1, __ATOMIC_RELAXED);

	/* Always emit the af_alg_pull_tsgl trigger shape (cmsg-only,
	 * empty payload, no MSG_MORE) before recvmsg() so the slab-OOB
	 * window is exercised on every iter, not just statistically. */
	send_empty_cmsg_no_more(ictx.child_fd);
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg_empty_cmsg_no_more,
			   1, __ATOMIC_RELAXED);

	recv_rotating(ictx.child_fd);

out:
	alg_recvmsg_iter_teardown(&ictx);
}

bool af_alg_recvmsg_churn(struct childdata *child)
{
	struct timespec t0;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.af_alg_recvmsg_runs, 1, __ATOMIC_RELAXED);

	if (alg_unsupported || crypto_proc_unsupported) {
		__atomic_add_fetch(&shm->stats.af_alg_recvmsg_unsupported,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!alg_cache_built ||
	    (++arc_invocation_counter % ARC_CACHE_REFRESH_PERIOD) == 0) {
		if (!rebuild_alg_cache()) {
			crypto_proc_unsupported = true;
			__atomic_add_fetch(&shm->stats.af_alg_recvmsg_unsupported,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

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
		iter_one();
		if (alg_unsupported)
			break;
	}

	return true;
}

#else  /* !__has_include(<linux/if_alg.h>) */

bool af_alg_recvmsg_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg_runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.af_alg_recvmsg_unsupported,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
