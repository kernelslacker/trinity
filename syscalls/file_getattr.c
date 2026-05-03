/*
 * SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#if defined(SYS_file_getattr) || defined(__NR_file_getattr)
#ifndef SYS_file_getattr
#define SYS_file_getattr __NR_file_getattr
#endif
#define HAVE_SYS_FILE_GETATTR 1
#endif

static unsigned long file_getattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_file_getattr(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, rec->a4);
}

/*
 * Oracle: file_getattr(dfd, filename, ufattr, usize, at_flags) writes a
 * struct file_attr describing the inode's filesystem-attribute flags
 * (xflags: immutable, append, sync, no_atime, no_dump, ...; extsize;
 * project id; cow extsize; nextents) into the user buffer.  Every field
 * lives on the inode and is stable across the ~150ms window between the
 * original syscall return and our post-hook re-call -- the only legitimate
 * mutator is a chattr(1)/FS_IOC_FSSETXATTR-class operation, which a sibling
 * trinity child could fire but is rare enough that any divergence we see is
 * far more likely to be one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct file_attr in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension on the size_t usize word.
 *   - struct-layout mismatch shifting fa_xflags into the fa_extsize slot,
 *     or fa_projid into fa_cowextsize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *
 * TOCTOU defeat (two buffers worth of it): both the input pathname and
 * the output file_attr buffer are user memory and a sibling can scribble
 * either between original return and re-issue.  The pathname is the
 * dominant attack surface -- alloc_shared can hand it to another child
 * which then scribbles it; if we re-call with whatever rec->a2 holds by
 * then we may resolve a different file, get different attributes, and
 * report a false divergence.  Snapshot BOTH the path (PATH_MAX stack
 * buffer) and the first usize bytes of the original file_attr result
 * before the re-call.  Re-issue with FRESH private buffers (do NOT pass
 * rec->a3 -- a sibling could mutate it mid-syscall and we want a clean
 * compare).  If the re-call fails, give up rather than report (file may
 * have been unlinked by sibling between calls).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  A real chattr-race divergence is itself an interesting TOCTOU
 * we want to surface; the ONE_IN(100) sampling keeps signal alive without
 * flooding the channel.
 */
static void post_file_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_FILE_GETATTR
	struct file_attr first_attr;
	struct file_attr recheck_attr;
	char path_local[PATH_MAX];
	size_t usize;
	unsigned int at_flags;
	int dfd;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0 || rec->a3 == 0)
		return;

	usize = (size_t) rec->a4;
	if (usize < sizeof(struct file_attr))
		return;
	if (usize > sizeof(struct file_attr))
		usize = sizeof(struct file_attr);

	dfd = (int) rec->a1;
	at_flags = (unsigned int) rec->a5;

	{
		void *ufattr = (void *)(unsigned long) rec->a3;
		void *path = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a3/a2. */
		if (looks_like_corrupted_ptr(ufattr) || looks_like_corrupted_ptr(path)) {
			outputerr("post_file_getattr: rejected suspicious ufattr=%p filename=%p (pid-scribbled?)\n",
				  ufattr, path);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	strncpy(path_local, (const char *) rec->a2, PATH_MAX - 1);
	path_local[PATH_MAX - 1] = '\0';
	if (path_local[0] == '\0')
		return;

	memcpy(&first_attr, (const void *) rec->a3, usize);

	memset(&recheck_attr, 0, sizeof(recheck_attr));
	rc = syscall(SYS_file_getattr, dfd, path_local, &recheck_attr,
		     sizeof(recheck_attr), at_flags);
	if (rc != 0)
		return;

	if (memcmp(&first_attr, &recheck_attr, usize) != 0) {
		const unsigned char *first_bytes = (const unsigned char *) &first_attr;
		const unsigned char *recheck_bytes = (const unsigned char *) &recheck_attr;
		char first_hex[8 * 3 + 1];
		char recheck_hex[8 * 3 + 1];
		size_t off;
		unsigned int i;

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(first_hex + off, sizeof(first_hex) - off,
					"%02x ", first_bytes[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(recheck_hex + off, sizeof(recheck_hex) - off,
					"%02x ", recheck_bytes[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:file_getattr] dfd=%d path=%s usize=%zu [%s] vs [%s]\n",
		       dfd, path_local, usize, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.file_getattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
#else
	(void) rec;
#endif
}

struct syscallentry syscall_file_getattr = {
	.name = "file_getattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_getattr_at_flags),
	.sanitise = sanitise_file_getattr,
	.post = post_file_getattr,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
