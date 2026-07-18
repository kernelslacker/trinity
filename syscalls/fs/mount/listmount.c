/*
 * SYSCALL_DEFINE4(listmount, const struct mnt_id_req __user *, req,
 *		u64 __user *, mnt_ids, size_t, nr_mnt_ids,
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
#include "arch.h"
#include "csfu.h"
#include "deferred-free.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "kernel/mount.h"
#include "utils.h"

#if defined(SYS_listmount) || defined(__NR_listmount)
#ifndef SYS_listmount
#define SYS_listmount __NR_listmount
#endif
#define HAVE_SYS_LISTMOUNT 1
#endif

/*
 * The mnt_ids output buffer the kernel writes into.  Always allocated
 * at the maximum nr we ever pass so a kernel-side bound bug cannot
 * scribble past a smaller allocation.  The kernel respects the
 * nr_mnt_ids cap and the post oracle catches a retval that exceeds
 * the cap, but the underlying allocation has to be safe regardless.
 */
#define LISTMOUNT_BUF_SLOTS	1024

#define LISTMOUNT_MNT_ID_POOL_SIZE	16

/*
 * Per-process cache of real mount IDs read from /proc/self/mountinfo.
 * Random 64-bit mnt_id values almost never match a live parent and the
 * call EINVALs before the iterator runs.  Pulling real parent IDs from
 * mountinfo steers the bias into the iteration arm where the bulk of
 * the kernel-side work lives.  Per-process static is enough: trinity
 * forks per child and the cache is inherited through the fork.  No
 * fileops in the syscall path -- the cache is populated lazily on the
 * first call.  Duplicated rather than shared with statmount's cache
 * because two callers do not justify a cross-cutting header.
 */
static __u64 listmount_mnt_id_pool[LISTMOUNT_MNT_ID_POOL_SIZE];
static unsigned int listmount_mnt_id_pool_n;
static bool listmount_mnt_id_pool_loaded;

static void load_listmount_mnt_id_pool(void)
{
	static char buf[32768];
	ssize_t n;
	char *p, *end;
	int fd;

	if (listmount_mnt_id_pool_loaded)
		return;
	listmount_mnt_id_pool_loaded = true;

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
	       listmount_mnt_id_pool_n < LISTMOUNT_MNT_ID_POOL_SIZE) {
		unsigned long long id;
		char *nl = memchr(p, '\n', end - p);

		if (nl != NULL)
			*nl = '\0';
		if (sscanf(p, "%llu ", &id) == 1)
			listmount_mnt_id_pool[listmount_mnt_id_pool_n++] =
				(__u64) id;
		if (nl == NULL)
			break;
		p = nl + 1;
	}
}

/*
 * Parent mnt_id picker.  Pool-sourced IDs land us on a real mount
 * whose children the kernel will iterate; LSMT_ROOT exercises the
 * list-all path; mnt_id=1 is the historic "root mount" sentinel; the
 * raw 64-bit random arm keeps the parent-lookup miss path warm.
 */
static __u64 pick_listmount_parent_id(void)
{
	unsigned int bucket;

	load_listmount_mnt_id_pool();

	bucket = rnd_modulo_u32(20);

	if (bucket < 10 && listmount_mnt_id_pool_n > 0)
		return listmount_mnt_id_pool[
			rnd_modulo_u32(listmount_mnt_id_pool_n)];

	if (bucket < 15)
		return LSMT_ROOT;

	if (bucket < 18)
		return (__u64) rnd_u64();

	return 1;
}

/*
 * nr_mnt_ids bucket.  0 trips the early EINVAL gate; 8 / 64 / 1024
 * give the iterator a small / typical / large output bound to honor.
 * The underlying allocation is LISTMOUNT_BUF_SLOTS regardless, so a
 * kernel-side over-write cannot scribble past our buffer.
 */
static unsigned long pick_listmount_nr(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0;
	case 1:  return 8;
	case 2:  return 64;
	default: return LISTMOUNT_BUF_SLOTS;
	}
}

/*
 * Flags bucket.  Real callers pass zero; reverse iteration is the only
 * defined alt-flag; the rand32 arm keeps the flag validator warm
 * against unmodelled high-bit garbage.
 */
static unsigned long pick_listmount_flags(void)
{
	unsigned int bucket = rnd_modulo_u32(20);

	if (bucket < 16)
		return 0;
	if (bucket < 19)
		return LISTMOUNT_REVERSE;
	return rnd_u32();
}

/*
 * mnt_id_req.param is the iteration order cookie.  Kernel currently
 * ignores it, but mismatched-shape requests have caught argument-
 * validation regressions before.  Keep it overwhelmingly zero with a
 * random-tail arm for unmodelled bit patterns.
 */
static __u64 pick_listmount_order(void)
{
	if (rnd_modulo_u32(5) < 4)
		return 0;
	return (__u64) rnd_u64();
}

#ifdef HAVE_SYS_LISTMOUNT
/*
 * Snapshot of the three listmount input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign mount-id buffer or
 * smear the size bound used to seed the re-issue.
 */
#define LISTMOUNT_POST_STATE_MAGIC	0x4C4953544D4E544DUL	/* "LISTMNTM" */
struct listmount_post_state {
	unsigned long magic;
	unsigned long req;
	unsigned long mnt_ids;
	unsigned long nr_mnt_ids;
};
#endif

/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  The kernel
 * accepts a request whose req->size matches any prior published
 * mnt_id_req version and zero-pads the rest.  The EXACT bucket
 * already covers sizeof(struct mnt_id_req) (== VER1 on current
 * headers), so only VER0 is listed here.
 */
static const size_t listmount_known_sizes[] = {
	MNT_ID_REQ_SIZE_VER0,
};

static const struct csfu_desc desc_listmount = {
	.name = "mnt_id_req",
	.ksize = sizeof(struct mnt_id_req),
	.known_sizes = listmount_known_sizes,
	.n_known_sizes = ARRAY_SIZE(listmount_known_sizes),
	.size_field_off = offsetof(struct mnt_id_req, size),
	.size_field_width = sizeof(((struct mnt_id_req *) 0)->size),
};

static void sanitise_listmount(struct syscallrecord *rec)
{
	struct csfu_buf csfu;
	struct mnt_id_req *req;
	__u64 *mnt_ids;
	unsigned long nr;
#ifdef HAVE_SYS_LISTMOUNT
	struct listmount_post_state *snap;
#endif

	csfu = build_csfu_struct(&desc_listmount);
	req = csfu.ptr;
	if (req == NULL)
		return;

	req->mnt_id = pick_listmount_parent_id();
	req->param = pick_listmount_order();

	mnt_ids = (__u64 *) get_writable_address(
		LISTMOUNT_BUF_SLOTS * sizeof(*mnt_ids));
	if (mnt_ids == NULL)
		return;

	nr = pick_listmount_nr();

	rec->a1 = (unsigned long) req;
	rec->a2 = (unsigned long) mnt_ids;
	rec->a3 = nr;
	rec->a4 = pick_listmount_flags();
	avoid_shared_buffer_inout(&rec->a1, csfu.usize);
	avoid_shared_buffer_out(&rec->a2, nr * sizeof(*mnt_ids));

#ifdef HAVE_SYS_LISTMOUNT
	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-issue would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * HAVE_SYS_LISTMOUNT to mirror the .post registration -- on systems
	 * without SYS_listmount the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic      = LISTMOUNT_POST_STATE_MAGIC;
	snap->req        = rec->a1;
	snap->mnt_ids    = rec->a2;
	snap->nr_mnt_ids = rec->a3;
	post_state_install(rec, snap);
#endif

	/*
	 * The csfu allocation (`req`) is a tracked libc-heap pointer rather
	 * than the get_writable_address() pool slot it replaced; without an
	 * explicit handoff here it would dangle until LRU eviction.  The
	 * rec_own carrier frees it after .post runs, which still reads
	 * via snap->req in the same iteration.
	 */
	rec_own(rec, req);
}

/*
 * Oracle: listmount(req, mnt_ids, nr_mnt_ids, flags) writes up to nr_mnt_ids
 * u64 mount IDs into the user buffer and returns the count written, with the
 * iteration anchored at req->mnt_id.  For a stable mount set the kernel
 * iteration order is deterministic, so two back-to-back calls with the same
 * request must produce a byte-identical id array.  Mount/umount flux during
 * the sample window is detected by a count mismatch on the re-call and we
 * silently skip -- only true divergence with a matching count is reported.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write: the kernel produced the right answer but a
 *     u64 landed in the wrong slot in the user buffer or arrived torn.
 *   - 32-bit-on-64-bit compat sign-extension on the size_t nr_mnt_ids word.
 *   - struct mnt_id_req layout mismatch between userspace and kernel.
 *   - sibling-thread scribble of the user req struct or ids buffer at
 *     rec->a1/rec->a2 between the original syscall return and our re-issue
 *     via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: the three input args (req, mnt_ids, nr_mnt_ids) are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign mount-id buffer or smear the size
 * bound.  We still snapshot the request struct and the first N ids into
 * stack-locals before re-issuing, with a fresh private stack request and
 * a fresh private stack ids buffer (do NOT pass the snapshot's req /
 * mnt_ids -- a sibling could scribble the user buffers themselves
 * mid-syscall and forge a clean compare).  The flags arg is forced to
 * zero on the re-call since reverse-iteration would change the ordering.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  No early return on first divergence -- multi-field corruption
 * surfaces in a single sample.
 */
static void post_listmount(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_LISTMOUNT
	struct listmount_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	struct mnt_id_req first_req;
	u64 first_ids[64];
	u64 recheck_ids[64];
	unsigned long n;
	unsigned long buf_slots;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, LISTMOUNT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Kernel ABI: sys_listmount writes at most nr_mnt_ids u64 mount IDs
	 * to the user buffer and returns the count written, capped at the
	 * snapshotted nr_mnt_ids arg.  Failure returns -1UL with EFAULT,
	 * EINVAL, or ENOENT.  Anything > snap->nr_mnt_ids on a non-(-1UL)
	 * return is a structural ABI regression: a sign-extension tear in
	 * the syscall return path, a kernel-side write that spilled past
	 * the user-supplied bound, or a torn read of the iterator counter.
	 * Reject before the ONE_IN(100) re-issue oracle below, which would
	 * otherwise miss 99% of corrupted retvals.  Fall through to
	 * out_release so the post_state ownership bracket is still closed.
	 */
	if (ret != -1L && retval > snap->nr_mnt_ids) {
		outputerr("post_listmount: retval %lu exceeds requested nr_mnt_ids %lu\n",
			  retval, snap->nr_mnt_ids);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (!ONE_IN(100))
		goto out_release;

	if (ret <= 0)
		goto out_release;

	if (snap->req == 0 || snap->mnt_ids == 0 || snap->nr_mnt_ids == 0)
		goto out_release;

	if (!post_snapshot_or_skip(&first_req, (void *) snap->req,
				   sizeof(first_req)))
		goto out_release;

	n = (retval < 64ul) ? retval : 64ul;
	if (!post_snapshot_or_skip(first_ids, (void *) snap->mnt_ids,
				   n * sizeof(u64)))
		goto out_release;

	{
		struct mnt_id_req recheck_req = first_req;

		buf_slots = ((unsigned long) snap->nr_mnt_ids < 64ul)
			? (unsigned long) snap->nr_mnt_ids : 64ul;
		rc = syscall(SYS_listmount, &recheck_req, recheck_ids,
			     buf_slots, 0u);
	}

	if (rc < 0)
		goto out_release;

	if (rc != ret)
		goto out_release;

	if (memcmp(first_ids, recheck_ids, (size_t) rc * sizeof(u64)) != 0) {
		char first_hex[64 * 17 + 1];
		char recheck_hex[64 * 17 + 1];
		size_t off;
		long i;

		off = 0;
		for (i = 0; i < rc; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_ids[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < rc; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_ids[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:listmount] mnt_id=%llx retval=%ld ids [%s] vs [%s]\n",
		       (unsigned long long) first_req.mnt_id,
		       ret, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.listmount_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_listmount = {
	.name = "listmount",
	.num_args = 4,
	.argname = { [0] = "req", [1] = "mnt_ids", [2] = "nr_mnt_ids", [3] = "flags" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.group = GROUP_VFS,
	.flags = KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_listmount,
	.post = post_listmount,
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};
