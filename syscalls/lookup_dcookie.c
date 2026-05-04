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
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
#ifndef SYS_lookup_dcookie
#define SYS_lookup_dcookie __NR_lookup_dcookie
#endif

/*
 * Snapshot of the three lookup_dcookie input args read by the post
 * oracle, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so
 * a sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot flip the cookie value the re-
 * issue resolves (steering it at a foreign dentry would forge a clean-
 * looking divergence between the two payloads), redirect the source
 * memcpy at a foreign user buffer, or zero the len gate that screens
 * empty receive buffers.
 */
struct lookup_dcookie_post_state {
	uint64_t cookie;
	unsigned long buf;
	unsigned long len;
};
#endif

static void sanitise_lookup_dcookie(struct syscallrecord *rec)
{
#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
	struct lookup_dcookie_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	/*
	 * On a successful cookie lookup the kernel writes up to len bytes
	 * of the resolved path into buf (a2).  ARG_ADDRESS draws from the
	 * random pool, so a fuzzed pointer can land inside an alloc_shared
	 * region.  Mirror the readlink/getcwd shape: use a3 if it's set,
	 * otherwise fall back to a page.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);

#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
	/*
	 * Snapshot the three input args for the post oracle.  Without
	 * this the post handler reads rec->aN at post-time, when a
	 * sibling syscall may have scribbled the slots: a stomped cookie
	 * retargets the re-issue at a different dentry than the first
	 * call resolved, looks_like_corrupted_ptr() cannot tell a real-
	 * but-wrong heap address from the original buf user-buffer
	 * pointer (so the source memcpy would touch a foreign allocation
	 * the guard never inspected), and a stomped len slips past the
	 * empty-buffer gate.  post_state is private to the post handler.
	 * Gated on the syscall number macro to mirror the .post
	 * registration -- on systems without SYS_lookup_dcookie the post
	 * handler's re-issue would not work and a snapshot only the post
	 * handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->cookie    = (uint64_t) rec->a1;
	snap->buf       = rec->a2;
	snap->len       = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_lookup_dcookie) || defined(__NR_lookup_dcookie)
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
 * TOCTOU defeat: the three input args (cookie, buf, len) are
 * snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot retarget the re-issue at a different cookie, redirect
 * the source memcpy at a foreign user buffer, or flip the empty-buffer
 * gate.  The user-buffer payload at buf is then memcpy'd into a stack-
 * local before re-issue, with a private stack buffer for the recall
 * result so a sibling cannot mutate it mid-syscall and forge a clean
 * compare.  Drop the sample if the re-call returns a different length
 * (could be benign: the dentry got renamed, or the cookie cache got
 * pruned and we now see -ENOENT).  Compare exactly retval bytes with
 * memcmp.  Sample one in a hundred to stay in line with the rest of
 * the oracle family.
 */
static void post_lookup_dcookie(struct syscallrecord *rec)
{
	struct lookup_dcookie_post_state *snap =
		(struct lookup_dcookie_post_state *) rec->post_state;
	uint64_t snap_cookie;
	char first[256];
	char recheck[256];
	long rc;
	size_t snap_len;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_lookup_dcookie: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	if (snap->len == 0)
		goto out_free;

	{
		void *buf = (void *)(unsigned long) snap->buf;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf
		 * pointer field.  Reject pid-scribbled buf before deref.
		 */
		if (looks_like_corrupted_ptr(buf)) {
			outputerr("post_lookup_dcookie: rejected suspicious buf=%p (post_state-scribbled?)\n",
				  buf);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr,
					   1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first))
		snap_len = sizeof(first);

	snap_cookie = snap->cookie;
	memcpy(first, (void *)(unsigned long) snap->buf, snap_len);

	memset(recheck, 0, sizeof(recheck));
	rc = syscall(SYS_lookup_dcookie, snap_cookie, recheck, sizeof(recheck));

	if (rc != (long) rec->retval)
		goto out_free;

	if (memcmp(first, recheck, snap_len) == 0)
		goto out_free;

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

out_free:
	deferred_freeptr(&rec->post_state);
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
