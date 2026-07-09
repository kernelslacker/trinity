/*
 * SYSCALL_DEFINE1(acct, const char __user *, name)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <unistd.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the random
 * path is almost never a real regular file the caller can open for
 * write -- acct() bounces at the path walk (ENOENT / EACCES) inside
 * filp_open() before ever reaching acct_on() / acct_off() and the
 * BSD accounting engine.  Classic "high calls, low edges" cold-syscall
 * shape the chmod / chown / utime families were in before their
 * testfile-pin fixes.
 *
 * Bias a1 across two curated draws so both toggle arms actually run:
 *
 *   1-in-4 draws: NULL -> acct_off() path, tearing down any accounting
 *   file a previous dispatch pinned.
 *
 *   1-in-4 draws: an absolute path pointing at one of the shared
 *   trinity-testfile<N> inodes the testfile fd pool creates.  Trinity
 *   owns those inodes (regular file, mode 0666), so with NEEDS_ROOT +
 *   CAP_SYS_PACCT filp_open() succeeds and acct_on() reaches the
 *   per-namespace bsd_acct install path and do_acct_process().
 *
 * The other half of the draws inherits whatever ARG_PATHNAME left in
 * the slot so the early-error arm at the path walk stays exercised
 * for coverage of the filp_open() reject edges.
 */
static void sanitise_acct(struct syscallrecord *rec)
{
	unsigned int r = rnd_modulo_u32(4);
	char *path;

	if (r == 0) {
		rec->a1 = 0;
		return;
	}
	if (r >= 2)
		return;

	path = get_testfile_path();
	if (path == NULL)
		return;

	rec->a1 = (unsigned long) path;
}

/*
 * Unconditional teardown: turn accounting off so a successful acct_on()
 * from this dispatch does not leak into the next iteration and pin a
 * trinity-testfile inode across the whole run (the kernel keeps the
 * accounting file open for the lifetime of the enable).
 *
 * acct(NULL) is idempotent: on a dispatch that already handed NULL to
 * the kernel, or that failed at the path walk, this is a cheap no-op;
 * on a dispatch that enabled accounting it releases the file the
 * kernel was holding open for the accounting writer.
 *
 * On kernels without CONFIG_BSD_PROCESS_ACCT the libc wrapper returns
 * ENOSYS and errno is set; the return is intentionally ignored so the
 * fuzzer's own FAIL_RUN_THRESHOLD deactivation stays the sole
 * latch-off mechanism for the syscall as a whole.
 */
static void cleanup_acct(struct syscallrecord *rec)
{
	(void) rec;
	(void) acct(NULL);
}

struct syscallentry syscall_acct = {
	.name = "acct",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "name" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_acct,
	.cleanup = cleanup_acct,
};
