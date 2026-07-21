/*
 * SYSCALL_DEFINE4(statmount, const struct mnt_id_req __user *, req,
 *		struct statmount __user *, buf, size_t, bufsize,
 *		unsigned int, flags)
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "csfu.h"
#include "deferred-free.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "kernel/mount.h"
#include "utils.h"

#if defined(SYS_statmount) || defined(__NR_statmount)
#ifndef SYS_statmount
#define SYS_statmount __NR_statmount
#endif
#define HAVE_SYS_STATMOUNT 1
#endif

static unsigned long statmount_params[] = {
	STATMOUNT_SB_BASIC, STATMOUNT_MNT_BASIC, STATMOUNT_PROPAGATE_FROM,
	STATMOUNT_MNT_ROOT, STATMOUNT_MNT_POINT, STATMOUNT_FS_TYPE,
	STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_OPTS,
#ifdef STATMOUNT_FS_SUBTYPE
	STATMOUNT_FS_SUBTYPE, STATMOUNT_SB_SOURCE,
#endif
#ifdef STATMOUNT_OPT_ARRAY
	STATMOUNT_OPT_ARRAY, STATMOUNT_OPT_SEC_ARRAY,
#endif
#ifdef STATMOUNT_SUPPORTED_MASK
	STATMOUNT_SUPPORTED_MASK,
#endif
#ifdef STATMOUNT_MNT_UIDMAP
	STATMOUNT_MNT_UIDMAP, STATMOUNT_MNT_GIDMAP,
#endif
};

#ifdef HAVE_SYS_STATMOUNT
/*
 * Snapshot of the three statmount input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign req / buf and cannot
 * smear the bufsize bound used to seed the re-issue.  bufsize is a
 * scalar but kept in the snap struct for symmetry with the two
 * pointer fields.
 *
 * magic guards against a sibling scribble of rec->post_state with any
 * heap-shaped pointer that survives looks_like_corrupted_ptr() but
 * belongs to a foreign allocation -- a mismatched cookie rejects the
 * snap before any inner-field deref.  original_buf is the zmalloc()'d
 * pointer handed to deferred_free_enqueue() at post-time: rec->a2 is
 * relocated by avoid_shared_buffer_out() into the writable-address pool,
 * so freeing the relocated address would trip the allocator's
 * heap-bounds gate; original_buf captures the zmalloc ptr for
 * the post handler to release via deferred_free_enqueue().
 * Mirrors the PIPE_POST_STATE_MAGIC pattern at
 * syscalls/pipe.c:57.
 */
#define STATMOUNT_POST_STATE_MAGIC	0x53544D4E545F4D47UL	/* "STMNT_MG" */
struct statmount_post_state {
	unsigned long magic;
	unsigned long req;
	unsigned long buffer;
	unsigned long bufsize;
	void *original_buf;
};
#endif

/*
 * Generous fixed buffer for the kernel's writeback.  struct statmount
 * fixed prefix is ~256 bytes plus the variable-length tail (mountopts
 * strings, fs type, mount root path, opt_array entries).  64KB covers
 * every published mask combination without spilling into -EOVERFLOW
 * for the non-bad-size buckets.
 */
#define STATMOUNT_BUF_BYTES	(64u * 1024u)

/*
 * Cached pool of real mount ids drawn from /proc/self/mountinfo at
 * first use.  Random mnt_id values almost never hit the kernel's
 * find_mnt_by_id() lookup gate; biasing toward real ids steers past
 * that arm into the per-mask copy_to_user paths where the actual
 * coverage of statmount() lives.  16 ids is enough to keep the pool
 * varied without bloating the cache on hosts with hundreds of mounts.
 *
 * Per-process static is fine -- the cache survives fork() and the
 * child inherits the parent's loaded ids; if no child of trinity
 * triggers a load before fork, each child loads its own copy once.
 */
#define STATMOUNT_MNT_ID_POOL_SIZE	16
static __u64 statmount_mnt_id_pool[STATMOUNT_MNT_ID_POOL_SIZE];
static unsigned int statmount_mnt_id_pool_n;
static int statmount_mnt_id_pool_loaded;

static void load_statmount_mnt_id_pool(void)
{
	static char buf[32768];
	ssize_t n;
	char *p, *end;
	int fd;

	statmount_mnt_id_pool_loaded = 1;

	/* Raw open/read instead of fopen/fgets/fclose: avoid stdio's
	 * per-call malloc of the FILE struct + IO buffer.  One bounded read
	 * of /proc/self/mountinfo into a fixed buffer is enough to pull the
	 * first POOL_SIZE mount IDs out -- if mountinfo overflows the
	 * buffer we simply parse fewer lines, which only affects the
	 * biasing distribution, not correctness. */
	fd = open("/proc/self/mountinfo", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	p = buf;
	end = buf + n;
	while (p < end &&
	       statmount_mnt_id_pool_n < STATMOUNT_MNT_ID_POOL_SIZE) {
		unsigned long long id;
		char *nl = memchr(p, '\n', end - p);

		if (nl != NULL)
			*nl = '\0';
		if (sscanf(p, "%llu ", &id) == 1)
			statmount_mnt_id_pool[statmount_mnt_id_pool_n++] =
				(__u64) id;
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

static __u64 pick_statmount_mnt_id(void)
{
	/* 60% draw from the real-mount pool, 40% random u64.  The
	 * random arm keeps the find_mnt_by_id() not-found and the
	 * sign-extension paths warm; the pool arm gets us past
	 * find_mnt_by_id() into the per-mask copy_to_user arms. */
	if (rnd_modulo_u32(10) < 6) {
		if (!statmount_mnt_id_pool_loaded)
			load_statmount_mnt_id_pool();
		if (statmount_mnt_id_pool_n > 0)
			return statmount_mnt_id_pool[
				rnd_modulo_u32(statmount_mnt_id_pool_n)];
	}
	return rand64();
}

/*
 * STATMOUNT_* mask buckets.  Random OR over the full param pool gets
 * stuck on the dominant multi-bit shape -- every call ends up asking
 * for several arms at once and the per-arm copy_to_user coverage
 * blurs together.  Split the dispatch so individual arms get exercised
 * on their own and unmodelled bit patterns still reach the validator.
 */
static __u64 pick_statmount_mask(void)
{
	unsigned int bucket = rnd_modulo_u32(10);
	unsigned int i, n;
	__u64 mask = 0;

	if (bucket < 7) {
		/* 70%: non-empty subset of the legal mask bits. */
		n = 1 + rnd_modulo_u32(ARRAY_SIZE(statmount_params));
		for (i = 0; i < n; i++)
			mask |= statmount_params[
				rnd_modulo_u32(ARRAY_SIZE(statmount_params))];
		return mask;
	}

	if (bucket < 9) {
		/* 20%: a single legal mask bit. */
		return statmount_params[
			rnd_modulo_u32(ARRAY_SIZE(statmount_params))];
	}

	/* 10%: pure random u64 -- exercises the unknown-bit reject path
	 * and any future-mask bits the kernel rolled out after our
	 * statmount_params table was last refreshed. */
	return rand64();
}

static unsigned long pick_statmount_bufsize(void)
{
	/* 90% generous, 10% undersized.  The undersized arm trips the
	 * < sizeof(struct statmount) early-overflow gate, which has its
	 * own validator separate from the per-mask copy_to_user paths. */
	if (rnd_modulo_u32(10) < 9)
		return STATMOUNT_BUF_BYTES;
	return rnd_modulo_u32(sizeof(struct statmount));
}

static unsigned long pick_statmount_flags(void)
{
	/* 90% zero, 10% random.  Random rolls may include
	 * STATMOUNT_BY_FD, which then reinterprets mnt_id as an fd --
	 * the pool-drawn mnt_id will not be a valid fd and the kernel
	 * EBADFs out, but that exercise of the fd-lookup arm is exactly
	 * the coverage the BY_FD bit is there to produce. */
	if (rnd_modulo_u32(10) < 9)
		return 0;
	return rnd_u32();
}

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  The kernel
 * accepts a request whose req->size matches any prior published
 * mnt_id_req version and zero-pads the rest.  The EXACT bucket
 * already covers sizeof(struct mnt_id_req) (== VER1 on current
 * headers), so only VER0 is listed here.
 */
static const size_t statmount_known_sizes[] = {
	MNT_ID_REQ_SIZE_VER0,
};

static const struct csfu_desc desc_statmount = {
	.name = "mnt_id_req",
	.ksize = sizeof(struct mnt_id_req),
	.known_sizes = statmount_known_sizes,
	.n_known_sizes = ARRAY_SIZE(statmount_known_sizes),
	.size_field_off = offsetof(struct mnt_id_req, size),
	.size_field_width = sizeof(((struct mnt_id_req *) 0)->size),
};

static void sanitise_statmount(struct syscallrecord *rec)
{
	struct csfu_buf csfu;
	struct mnt_id_req *req;
	void *buf;
#ifdef HAVE_SYS_STATMOUNT
	struct statmount_post_state *snap;

	rec->post_state = 0;
#endif

	csfu = build_csfu_struct(&desc_statmount);
	req = csfu.ptr;
	if (req == NULL) {
		__atomic_add_fetch(&shm->stats.diag.statmount_setup_fail,
				   1, __ATOMIC_RELAXED);
		return;
	}

	req->mnt_id = pick_statmount_mnt_id();
	req->param = pick_statmount_mask();

	buf = zmalloc_tracked(STATMOUNT_BUF_BYTES);

	rec->a1 = (unsigned long) req;
	rec->a2 = (unsigned long) buf;
	rec->a3 = pick_statmount_bufsize();
	rec->a4 = pick_statmount_flags();

#ifdef HAVE_SYS_STATMOUNT
	/*
	 * Snapshot the three input args for the post oracle, and stash the
	 * original zmalloc()'d buf BEFORE avoid_shared_buffer_out() relocates
	 * rec->a2 into the writable-address pool.  Without this snapshot the
	 * post handler reads rec->aN at post-time, when a sibling syscall may
	 * have scribbled the slots: looks_like_corrupted_ptr() cannot tell a
	 * real-but-wrong heap address from the original user buffer pointers,
	 * so the memcpy / re-issue would touch a foreign allocation.  Without
	 * original_buf the post handler has no way to free the 64 KiB tracked
	 * allocation -- the relocated rec->a2 belongs to a different allocator
	 * and deferred_free_enqueue() would reject it.  post_state is private
	 * to the post handler.  Gated on HAVE_SYS_STATMOUNT to mirror the
	 * .post registration -- on systems without SYS_statmount the post
	 * handler is not registered and a snapshot only the post handler can
	 * free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic        = STATMOUNT_POST_STATE_MAGIC;
	snap->original_buf = buf;
	snap->bufsize      = rec->a3;
#endif

	avoid_shared_buffer_inout(&rec->a1, csfu.usize);
	avoid_shared_buffer_out(&rec->a2, STATMOUNT_BUF_BYTES);

#ifdef HAVE_SYS_STATMOUNT
	/*
	 * Capture req/buffer after relocation -- the post oracle re-reads
	 * the user buffer from the address the kernel actually wrote into,
	 * which is the relocated pool pointer, not the libc-heap zmalloc.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the two
	 * is closed; post_statmount() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap->req    = rec->a1;
	snap->buffer = rec->a2;
	post_state_install(rec, snap);
#endif

	/*
	 * The csfu allocation (`req`) is the libc-heap pointer the kernel
	 * read from; once avoid_shared_buffer_inout has either left rec->a1
	 * pointing at it or relocated it, the local handle is the only path
	 * back to that buffer.  Register it with the per-rec owned-pointer
	 * carrier so the post-dispatch cleanup drain frees it after .post
	 * has re-read snap->req, replacing the deferred-free TTL margin
	 * with a deterministic post-dispatch lifetime.
	 */
	rec_own(rec, req);
}

/*
 * Oracle: statmount(req, buf, bufsize, flags) writes a struct statmount
 * fixed-prefix into the user buffer and returns 0 on success, with the
 * per-mount data anchored at req->mnt_id.  For a stable mount the kernel
 * fields the same struct on a back-to-back re-call, so a byte-identical
 * compare of the fixed-prefix region across two snapshots is the cheapest
 * possible cross-check.  Mount/umount flux or transient -EBUSY/-EINVAL on
 * the re-call is detected via rc < 0 and we silently skip -- only true
 * divergence with a successful re-call is reported.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write: the kernel produced the right answer but a
 *     u64 landed in the wrong slot inside the fixed prefix or arrived torn.
 *   - 32-bit-on-64-bit compat sign-extension on the size_t bufsize word.
 *   - struct layout mismatch between userspace and kernel for the fixed
 *     prefix (a new field inserted in the middle, padding drift).
 *   - sibling-thread scribble of the user req struct or buf payload at
 *     rec->a1/rec->a2 between the original syscall return and our
 *     re-issue via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: the three input args (req, buffer, bufsize) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign req / buf and cannot smear the bufsize
 * bound used to seed the re-issue.  We still snapshot both the request
 * struct and the buf payload into stack-locals before re-issuing, with a
 * fresh private stack request and a fresh private stack buf (do NOT pass
 * the snapshot's req / buffer -- a sibling could mutate the user buffers
 * themselves mid-syscall and forge a clean compare).  The flags arg is
 * forced to zero on the re-call.
 *
 * Per-audit note: only the FIXED prefix (sizeof(struct statmount)) is
 * compared.  The variable-length string area beyond the fixed struct is
 * also stable but harder to bound -- skip it for this first pass.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  No early return on first divergence -- multi-field corruption
 * surfaces in a single sample.
 */
static void post_statmount(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_STATMOUNT
	struct statmount_post_state *snap;
	struct mnt_id_req first_req;
	struct statmount first_buf;
	struct statmount recheck_buf;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, STATMOUNT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_release;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->req == 0 || snap->buffer == 0)
		goto out_release;

	if (snap->bufsize < sizeof(struct statmount))
		goto out_release;

	if (!post_snapshot_or_skip(&first_req, (void *) snap->req,
				   sizeof(first_req)))
		goto out_release;
	if (!post_snapshot_or_skip(&first_buf, (void *) snap->buffer,
				   sizeof(first_buf)))
		goto out_release;

	{
		struct mnt_id_req recheck_req = first_req;

		rc = syscall(SYS_statmount, &recheck_req, &recheck_buf,
			     sizeof(recheck_buf), 0u);
	}

	if (rc < 0)
		goto out_release;

	if (memcmp(&first_buf, &recheck_buf, sizeof(struct statmount)) != 0) {
		const u64 *first_words = (const u64 *) &first_buf;
		const u64 *recheck_words = (const u64 *) &recheck_buf;
		char first_hex[8 * 17 + 1];
		char recheck_hex[8 * 17 + 1];
		size_t off;
		unsigned int nwords;
		unsigned int i;

		nwords = sizeof(struct statmount) / sizeof(u64);
		if (nwords > 8)
			nwords = 8;

		off = 0;
		for (i = 0; i < nwords; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_words[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < nwords; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_words[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:statmount] mnt_id=%llx prefix [%s] vs [%s]\n",
		       (unsigned long long) first_req.mnt_id,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.statmount_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_release:
	/*
	 * Enqueue the original zmalloc()'d buf for deferred free.  rec->a2
	 * was relocated into the writable-address pool by
	 * avoid_shared_buffer_out(); free()ing that address would trip the
	 * tracked-allocator gate.  snap->original_buf is the libc-heap
	 * pointer the allocator knows about.  Read snap->original_buf BEFORE
	 * post_state_release frees the snap struct itself.
	 */
	deferred_free_enqueue(snap->original_buf);
	post_state_release(rec, snap);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_statmount = {
	.name = "statmount",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_STRUCT_SIZE },
	.argname = { [0] = "req", [1] = "buf", [2] = "bufsize", [3] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.flags = KCOV_REMOTE_HEAVY | REEXEC_SANITISE_OK,
	.sanitise = sanitise_statmount,
	.post = post_statmount,
	.bound_arg = 3,
};
