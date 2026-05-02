/*
 * SYSCALL_DEFINE3(lookup_dcookie, u64 cookie64, char __user *buf, size_t len)
 *
 * lookup_dcookie resolves an oprofile dcookie (an opaque u64 handle that
 * the kernel hands out to identify a dentry) back into the textual path
 * of that dentry, copying up to `len` bytes into `buf`.  Retval is the
 * number of bytes written.  On most modern kernels CONFIG_PROFILING /
 * oprofile is disabled and the syscall returns -ENOSYS, so the post hook
 * below is a no-op in practice on the common case.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_lookup_dcookie(struct syscallrecord *rec)
{
	/*
	 * On a successful cookie lookup the kernel writes up to len bytes
	 * of the resolved path into buf (a2).  ARG_ADDRESS draws from the
	 * random pool, so a fuzzed pointer can land inside an alloc_shared
	 * region.  Mirror the readlink/getcwd shape: use a3 if it's set,
	 * otherwise fall back to a page.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);
}

#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
#ifndef SYS_lookup_dcookie
#define SYS_lookup_dcookie __NR_lookup_dcookie
#endif

/*
 * Oracle: lookup_dcookie maps a kernel-issued u64 cookie back to the
 * pathname of the dentry the cookie was minted for.  Cookies live for
 * the lifetime of the kernel -- they are stored in a per-cookie cache
 * (see fs/dcookies.c) keyed off the dentry+vfsmount pair, and a cookie
 * value is never recycled while the kernel is up.  Two back-to-back
 * lookups of the same cookie from the same task must therefore produce
 * a byte-identical path string (and identical byte length) in the user
 * receive buffer.  A divergence between the original syscall payload
 * and an immediate re-call of the same syscall points at one of:
 *
 *   - copy_to_user mis-write that left a torn path in user memory
 *     (partial write, wrong-offset fill, residual stack data).
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - dcookie cache lookup returning a different dentry for the same
 *     cookie value (cache key collision, refcount underflow letting an
 *     entry get reused mid-flight).
 *   - dentry rename racing the path build of one of the two calls.
 *
 * TOCTOU defeat: snapshot the cookie argument (rec->a1) and the first
 * retval bytes of the user receive buffer (rec->a2) into stack-locals
 * BEFORE re-issuing the syscall.  The re-call MUST target a fresh
 * stack buffer, never rec->a2 -- a sibling could mutate the original
 * receive buffer mid-syscall and forge a clean compare.  Drop the
 * sample if the re-call returns a different length (could be benign:
 * the dentry got renamed, or the cookie cache got pruned and we now
 * see -ENOENT).  Compare exactly retval bytes with memcmp.  Sample
 * one in a hundred to stay in line with the rest of the oracle family.
 */
static void post_lookup_dcookie(struct syscallrecord *rec)
{
	uint64_t snap_cookie;
	char first[256];
	char recheck[256];
	long rc;
	size_t snap_len;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a2 == 0)
		return;

	if (rec->a3 == 0)
		return;

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first))
		snap_len = sizeof(first);

	snap_cookie = (uint64_t) rec->a1;
	memcpy(first, (void *)(unsigned long) rec->a2, snap_len);

	memset(recheck, 0, sizeof(recheck));
	rc = syscall(SYS_lookup_dcookie, snap_cookie, recheck, sizeof(recheck));

	if (rc != (long) rec->retval)
		return;

	if (memcmp(first, recheck, snap_len) == 0)
		return;

	{
		char first_hex[sizeof(first) * 2 + 1];
		char recheck_hex[sizeof(recheck) * 2 + 1];
		size_t i;

		for (i = 0; i < snap_len; i++) {
			snprintf(first_hex + i * 2, 3, "%02x",
				 (unsigned char) first[i]);
			snprintf(recheck_hex + i * 2, 3, "%02x",
				 (unsigned char) recheck[i]);
		}
		first_hex[snap_len * 2] = '\0';
		recheck_hex[snap_len * 2] = '\0';

		output(0,
		       "[oracle:lookup_dcookie] cookie=0x%llx len=%zu first %s vs recheck %s\n",
		       (unsigned long long) snap_cookie, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.lookup_dcookie_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_lookup_dcookie || __NR_lookup_dcookie */

struct syscallentry syscall_lookup_dcookie = {
	.name = "lookup_dcookie",
	.num_args = 3,
	.argtype = { [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "cookie64", [1] = "buf", [2] = "len" },
	.sanitise = sanitise_lookup_dcookie,
#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
	.post = post_lookup_dcookie,
#endif
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
