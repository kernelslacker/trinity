/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_readlink(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);
}

#if defined(SYS_readlink) || defined(__NR_readlink)
#ifndef SYS_readlink
#define SYS_readlink __NR_readlink
#endif

/*
 * Oracle: readlink(path, buf, bufsiz) walks `path` WITHOUT following the
 * terminal symlink, copies the symlink's target string into `buf`, and
 * returns the number of bytes written.  The returned bytes are the raw
 * target string -- not NUL-terminated, retval is the exact byte count.
 * Two back-to-back readlinks of the same path from the same task --
 * assuming no sibling unlink+symlink-replace or rename race in between --
 * must produce a byte-identical target of identical length.  A divergence
 * between the original syscall payload and an immediate re-call points
 * at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating the bufsiz int and shipping a
 *     short payload while reporting the full retval.
 *   - dcache race serving the second lookup a different inode for the
 *     same path string (rename/mount-shift, or symlink replacement,
 *     between the two calls resolves the same name to a different
 *     symlink inode whose target string differs at equal length).
 *
 * TOCTOU defeat: both the path string (rec->a1) and the receive buffer
 * (rec->a2) are reachable from sibling trinity children and either could
 * be mutated between the original return and our re-issue.  Snapshot
 * the path bytes into a stack-local string and the first retval bytes
 * of the receive buffer into a stack-local buffer BEFORE re-issuing the
 * syscall.  The re-call MUST target a fresh stack buffer, never rec->a2
 * -- a sibling could mutate the original receive buffer mid-syscall and
 * forge a clean compare.  Drop the sample if the re-call returns <= 0
 * (sibling unlinked the symlink -- benign ENOENT; or replaced it with a
 * regular file -- benign EINVAL) or if it returns a different length
 * (sibling unlink+symlink-replace pointed the same name at a different-
 * length target -- benign size-class drift).  Compare exactly snap_len
 * bytes with memcmp; do not early-return on first divergence so a
 * multi-byte tear surfaces in a single sample, but bump the anomaly
 * counter only once.  Sample one in a hundred to stay in line with the
 * rest of the oracle family.
 *
 * readlink output is NOT NUL-terminated -- the bytes are the symlink
 * target verbatim and retval is the exact byte count.  Do not assume
 * a trailing NUL when copying or comparing.
 */
static void post_readlink(struct syscallrecord *rec)
{
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a1 == 0)
		return;

	if (rec->a2 == 0)
		return;

	strncpy(snap_path, (const char *)(unsigned long) rec->a1,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a2, snap_len);

	rc = syscall(SYS_readlink, snap_path, recheck_buf,
		     sizeof(recheck_buf));

	if (rc <= 0)
		return;

	if ((size_t) rc != snap_len)
		return;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		return;

	{
		char first_hex[32 * 2 + 1];
		char recheck_hex[32 * 2 + 1];
		size_t i, dump_len;

		dump_len = snap_len < 32 ? snap_len : 32;
		for (i = 0; i < dump_len; i++) {
			snprintf(first_hex + i * 2, 3, "%02x",
				 (unsigned char) first_buf[i]);
			snprintf(recheck_hex + i * 2, 3, "%02x",
				 (unsigned char) recheck_buf[i]);
		}
		first_hex[dump_len * 2] = '\0';
		recheck_hex[dump_len * 2] = '\0';

		output(0,
		       "[oracle:readlink] path=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.readlink_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_readlink || __NR_readlink */

struct syscallentry syscall_readlink = {
	.name = "readlink",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "path", [1] = "buf", [2] = "bufsiz" },
	.sanitise = sanitise_readlink,
	.group = GROUP_VFS,
#if defined(SYS_readlink) || defined(__NR_readlink)
	.post = post_readlink,
#endif
};


/*
 * SYSCALL_DEFINE4(readlinkat, int, dfd, const char __user *, pathname,
	 char __user *, buf, int, bufsiz)
 */

static void sanitise_readlinkat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a4 ? rec->a4 : page_size);
}

#if defined(SYS_readlinkat) || defined(__NR_readlinkat)
#ifndef SYS_readlinkat
#define SYS_readlinkat __NR_readlinkat
#endif

/*
 * Oracle: readlinkat(dfd, pathname, buf, bufsiz) is the *at variant of
 * readlink -- pathname is resolved relative to dfd (or AT_FDCWD), the
 * symlink target string is copied verbatim into buf, and retval is the
 * exact byte count.  Output is NOT NUL-terminated.  The return-value
 * semantics are identical to readlink: two back-to-back calls with the
 * same (dfd, pathname) -- absent a sibling rename / symlink-replace /
 * mount-shift on the same dirfd -- must produce a byte-identical target
 * of identical length.  Same failure modes apply: copy_to_user mis-write,
 * sibling buffer scribble, 32-on-64 compat truncation, dcache race.
 *
 * TOCTOU defeat: snapshot pathname (rec->a2) AND the first retval bytes
 * of the receive buffer (rec->a3) into stack-locals BEFORE re-issuing
 * the syscall.  The re-call MUST target a fresh stack buffer, never
 * rec->a3 -- a sibling could mutate the original receive buffer mid-
 * syscall and forge a clean compare.  Drop the sample if the re-call
 * returns <= 0 (sibling unlinked the symlink, dirfd closed mid-flight,
 * EPERM from setuid race -- all benign) or returns a different length
 * (sibling re-symlinked to a different-length target -- benign size-
 * class drift).  Bump the anomaly counter once on byte divergence and
 * emit a hex-dump diagnostic of the first 32 bytes of each.  Sample
 * one in a hundred to stay in line with the rest of the oracle family.
 *
 * Extra gate vs readlink: kernel reporting retval > bufsiz is itself
 * an anomaly (kernel claims to have written more bytes than the buffer
 * could hold).  Bump the counter with a distinct diagnostic and bail
 * without re-issuing -- byte compare is meaningless when the original
 * write length already violates the buffer bound.
 */
static void post_readlinkat(struct syscallrecord *rec)
{
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	int dfd;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a2 == 0)
		return;

	if (rec->a3 == 0)
		return;

	if (rec->a4 == 0)
		return;

	if ((long) rec->retval > (long) rec->a4) {
		output(0,
		       "[oracle:readlinkat] retval=%ld exceeds bufsiz=%ld\n",
		       (long) rec->retval, (long) rec->a4);
		__atomic_add_fetch(&shm->stats.readlinkat_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
		return;
	}

	dfd = (int) rec->a1;

	strncpy(snap_path, (const char *)(unsigned long) rec->a2,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a3, snap_len);

	rc = syscall(SYS_readlinkat, dfd, snap_path, recheck_buf,
		     (int) sizeof(recheck_buf));

	if (rc <= 0)
		return;

	if ((size_t) rc != snap_len)
		return;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		return;

	{
		char first_hex[32 * 2 + 1];
		char recheck_hex[32 * 2 + 1];
		size_t i, dump_len;

		dump_len = snap_len < 32 ? snap_len : 32;
		for (i = 0; i < dump_len; i++) {
			snprintf(first_hex + i * 2, 3, "%02x",
				 (unsigned char) first_buf[i]);
			snprintf(recheck_hex + i * 2, 3, "%02x",
				 (unsigned char) recheck_buf[i]);
		}
		first_hex[dump_len * 2] = '\0';
		recheck_hex[dump_len * 2] = '\0';

		output(0,
		       "[oracle:readlinkat] dfd=%d path=%s len=%zu first %s vs recheck %s\n",
		       dfd, snap_path, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.readlinkat_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_readlinkat || __NR_readlinkat */

struct syscallentry syscall_readlinkat = {
	.name = "readlinkat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "buf", [3] = "bufsiz" },
	.sanitise = sanitise_readlinkat,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
#if defined(SYS_readlinkat) || defined(__NR_readlinkat)
	.post = post_readlinkat,
#endif
};
