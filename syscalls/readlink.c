/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
#include <stddef.h>
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

#if defined(SYS_readlink) || defined(__NR_readlink)
#ifndef SYS_readlink
#define SYS_readlink __NR_readlink
#endif

/*
 * Snapshot of the three readlink input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect the strncpy at a
 * foreign path string (steering the re-issue at a different symlink
 * inode would forge a clean-looking divergence between the two
 * payloads), redirect the source memcpy at a foreign user buffer, or
 * smear the bufsiz value the retval > bufsiz anomaly gate compares
 * against.
 */
struct readlink_post_state {
	unsigned long path;
	unsigned long buf;
	unsigned long bufsiz;
};
#endif

static void sanitise_readlink(struct syscallrecord *rec)
{
#if defined(SYS_readlink) || defined(__NR_readlink)
	struct readlink_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);

#if defined(SYS_readlink) || defined(__NR_readlink)
	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2/a3 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original buf
	 * user-buffer pointer (so the source memcpy would touch a foreign
	 * allocation the guard never inspected), a stomped path string
	 * pointer steers strncpy at a different name (the re-issue then
	 * resolves a different symlink inode and the byte compare fires as
	 * if the kernel had torn the original payload), and a stomped
	 * bufsiz can flip the retval > bufsiz anomaly gate either way --
	 * forging a violation when none occurred or hiding a real one.
	 * post_state is private to the post handler.  Gated on the syscall
	 * number macro to mirror the .post registration -- on systems
	 * without SYS_readlink the post handler's re-issue would not work
	 * and a snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->path      = rec->a1;
	snap->buf       = rec->a2;
	snap->bufsiz    = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_readlink) || defined(__NR_readlink)

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
	struct readlink_post_state *snap =
		(struct readlink_post_state *) rec->post_state;
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_readlink: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * STRONG-VAL count bound: readlink(2) on success returns the number
	 * of bytes the VFS copied into the user `buf`, capped at the `bufsiz`
	 * argument (rec->a3, snapped at sanitise time) by readlink_copy's
	 * truncation; failure returns -1.  A retval > bufsiz on a positive
	 * return is structurally impossible from the VFS path -- it points
	 * at a sign-extension tear in the syscall return path, a sibling-
	 * thread torn-write of rec->retval between syscall return and post
	 * entry, or -errno leaking through the success return slot.  Fire
	 * unconditionally, ahead of the ONE_IN(100) sample gate that
	 * throttles the equality oracle, so every offending retval is
	 * counted, not one-in-a-hundred.  Falls through to out_free so the
	 * snapshot heap is released via deferred_freeptr.
	 */
	if ((long) rec->retval > 0 &&
	    (unsigned long) rec->retval > snap->bufsiz) {
		outputerr("post_readlink: rejected retval=0x%lx > bufsiz=%lu\n",
			  rec->retval, snap->bufsiz);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->path == 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	{
		void *buf = (void *)(unsigned long) snap->buf;
		void *path = (void *)(unsigned long) snap->path;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf/
		 * path pointer fields.  Reject pid-scribbled values before
		 * deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf) || looks_like_corrupted_ptr(rec, path)) {
			outputerr("post_readlink: rejected suspicious buf=%p path=%p (post_state-scribbled?)\n",
				  buf, path);
			goto out_free;
		}
	}

	strncpy(snap_path, (const char *)(unsigned long) snap->path,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) snap->buf, snap_len);

	rc = syscall(SYS_readlink, snap_path, recheck_buf,
		     sizeof(recheck_buf));

	if (rc <= 0)
		goto out_free;

	if ((size_t) rc != snap_len)
		goto out_free;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		goto out_free;

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

out_free:
	deferred_freeptr(&rec->post_state);
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

#if defined(SYS_readlinkat) || defined(__NR_readlinkat)
#ifndef SYS_readlinkat
#define SYS_readlinkat __NR_readlinkat
#endif

/*
 * Snapshot of the four readlinkat input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the re-issue at a
 * different dfd, redirect the strncpy at a foreign pathname string
 * (steering the re-issue at a different symlink inode would forge a
 * clean-looking divergence between the two payloads), redirect the
 * source memcpy at a foreign user buffer, or smear the bufsiz value
 * the retval > bufsiz anomaly gate compares against.
 */
struct readlinkat_post_state {
	unsigned long dfd;
	unsigned long pathname;
	unsigned long buf;
	unsigned long bufsiz;
};
#endif

static void sanitise_readlinkat(struct syscallrecord *rec)
{
#if defined(SYS_readlinkat) || defined(__NR_readlinkat)
	struct readlinkat_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a3, rec->a4 ? rec->a4 : page_size);

#if defined(SYS_readlinkat) || defined(__NR_readlinkat)
	/*
	 * Snapshot the four input args for the post oracle.  Without
	 * this the post handler reads rec->aN at post-time, when a
	 * sibling syscall may have scribbled the slots: a stomped dfd
	 * retargets the re-issue at a different directory file
	 * descriptor than the first call resolved against,
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original buf user-buffer pointer (so the
	 * source memcpy would touch a foreign allocation the guard never
	 * inspected), a stomped pathname pointer steers strncpy at a
	 * different name (the re-issue then resolves a different symlink
	 * inode and the byte compare fires as if the kernel had torn the
	 * original payload), and a stomped bufsiz can flip the retval >
	 * bufsiz anomaly gate either way -- forging a violation when none
	 * occurred or hiding a real one.  post_state is private to the
	 * post handler.  Gated on the syscall number macro to mirror the
	 * .post registration -- on systems without SYS_readlinkat the
	 * post handler's re-issue would not work and a snapshot only the
	 * post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->dfd       = rec->a1;
	snap->pathname  = rec->a2;
	snap->buf       = rec->a3;
	snap->bufsiz    = rec->a4;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_readlinkat) || defined(__NR_readlinkat)

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
	struct readlinkat_post_state *snap =
		(struct readlinkat_post_state *) rec->post_state;
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	int dfd;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_readlinkat: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->pathname == 0)
		goto out_free;

	if (snap->buf == 0)
		goto out_free;

	if (snap->bufsiz == 0)
		goto out_free;

	if ((long) rec->retval > (long) snap->bufsiz) {
		output(0,
		       "[oracle:readlinkat] retval=%ld exceeds bufsiz=%ld\n",
		       (long) rec->retval, (long) snap->bufsiz);
		__atomic_add_fetch(&shm->stats.readlinkat_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
		goto out_free;
	}

	dfd = (int) snap->dfd;

	{
		void *buf = (void *)(unsigned long) snap->buf;
		void *path = (void *)(unsigned long) snap->pathname;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf/
		 * pathname pointer fields.  Reject pid-scribbled values
		 * before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf) || looks_like_corrupted_ptr(rec, path)) {
			outputerr("post_readlinkat: rejected suspicious buf=%p pathname=%p (post_state-scribbled?)\n",
				  buf, path);
			goto out_free;
		}
	}

	strncpy(snap_path, (const char *)(unsigned long) snap->pathname,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) snap->buf, snap_len);

	rc = syscall(SYS_readlinkat, dfd, snap_path, recheck_buf,
		     (int) sizeof(recheck_buf));

	if (rc <= 0)
		goto out_free;

	if ((size_t) rc != snap_len)
		goto out_free;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		goto out_free;

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

out_free:
	deferred_freeptr(&rec->post_state);
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
