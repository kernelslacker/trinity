/*
 * SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
 */
#include <stdio.h>
#include "maps.h"
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "testfile.h"
#include "trinity.h"
#include "utils.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (access, chmod, chown, utime, utimensat, xattr-thrash,
 * flock-thrash, ...) touch; cross-process contention concentrates on
 * the same per-inode i_rwsem / notify_change / setattr path.
 */
#define NR_TESTFILES 4

/*
 * Snapshot of the testfile pin captured at sanitise time and consumed
 * by post_truncate.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose, so a sibling syscall scribbling rec->a1 between the
 * syscall returning and the post handler running cannot retarget the
 * mmap invalidation at a foreign basename whose mappings this truncate
 * never touched.
 *
 * testfile_index is 1-based and only set when the in-place pathname
 * rewrite below actually fired; the post handler treats out-of-range
 * values as "nothing to invalidate" via the bounds check in
 * invalidate_testfile_mmaps_for_index().
 */
#define TRUNCATE_POST_STATE_MAGIC	0x54525543UL	/* "TRUC" */
struct truncate_post_state {
	unsigned long magic;
	unsigned long testfile_index;
};

static void sanitise_truncate(struct syscallrecord *rec)
{
	struct truncate_post_state *snap;
	char *path;
	unsigned int index;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- truncate
	 * returns ENOENT at the path walk before ever reaching
	 * do_sys_truncate / do_truncate / notify_change /
	 * inode_operations->setattr and the i_rwsem-guarded per-inode
	 * size-update path.  Classic "high calls, low edges" cold-syscall
	 * shape the chmod/chown/utime families were in before their
	 * testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent truncate lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the
	 * permission check (trinity owns these inodes so the
	 * ownership/permission gates pass), do_truncate, notify_change,
	 * and the per-fs setattr that the i_rwsem guards.  The other
	 * half preserves the slot exactly as the generic draw left it,
	 * so the ENOENT reject arm stays exercised.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	path = (char *) rec->a1;
	if (path == NULL)
		return;

	index = 1 + rnd_modulo_u32(NR_TESTFILES);

	/*
	 * Overwrite the ARG_PATHNAME buffer in place.  generate_pathname()
	 * zmallocs MAX_PATH_LEN (4096) bytes, so the snprintf cap below
	 * cannot overflow.
	 */
	snprintf(path, MAX_PATH_LEN, "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), index);

	/*
	 * Snapshot the chosen basename index so post_truncate can find
	 * every OBJ_FD_TESTFILE entry whose backing inode this call may
	 * have shrunk and soft-invalidate the matching OBJ_MMAP_TESTFILE
	 * mappings before a sibling child draws the now-past-EOF map.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TRUNCATE_POST_STATE_MAGIC;
	snap->testfile_index = index;
	post_state_install(rec, snap);
}

static void post_truncate(struct syscallrecord *rec)
{
	struct truncate_post_state *snap;

	/*
	 * Canonical ownership bracket: shape -> ownership -> magic, in
	 * that order.  post_state_claim_owned() has already cleared
	 * rec->post_state, emitted any outputerr() diagnostic, and bumped
	 * the corruption counter on failure -- just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, TRUNCATE_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (rec->retval != 0)
		goto out_free;

	/*
	 * A successful truncate on a trinity-testfile<N> inode may have
	 * shrunk it below the page_size OBJ_MMAP_TESTFILE mapping
	 * fds/testfiles.c established at startup.  Reading or writing
	 * the post-EOF tail of that mapping SIGBUSes inside trinity
	 * itself, and OBJ_MMAP_TESTFILE is OBJ_GLOBAL, so one child's
	 * shrink poisons the shared writable arg pool fleet-wide.
	 * Soft-invalidate every OBJ_MMAP_TESTFILE entry backed by an fd
	 * open against the matching basename so get_map_with_prot()
	 * cannot hand the entry to the next consumer (memory_pressure /
	 * iouring_* / madvise_pattern_cycler) until the pool refills.
	 *
	 * Mirror post_ftruncate's policy of invalidating unconditionally
	 * on success rather than gating on shrink-vs-grow: a grow is
	 * harmless to invalidate (the next get_map() pick re-populates
	 * the pool), and avoiding the gate keeps the post handler out
	 * of an fstat() syscall on the hot path.
	 */
	invalidate_testfile_mmaps_for_index((unsigned int) snap->testfile_index);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_truncate = {
	.name = "truncate",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN },
	.argname = { [0] = "path", [1] = "length" },
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_truncate,
	.post = post_truncate,
};

/*
 * SYSCALL_DEFINE(truncate64)(const char __user * path, loff_t length)
 */

struct syscallentry syscall_truncate64 = {
	.name = "truncate64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN },
	.argname = { [0] = "path", [1] = "length" },
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_truncate,
	.post = post_truncate,
};
