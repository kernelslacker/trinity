/*
 * SYSCALL_DEFINE1(olduname, struct oldold_utsname __user *, name)
 *
 * The legacy "olduname" entry point is the predecessor of both uname /
 * newuname.  It writes a fixed five-field struct oldold_utsname (five
 * 9-byte char arrays: sysname, nodename, release, version, machine -- no
 * domainname).  The fields are NOT guaranteed null-terminated when the
 * underlying uts_ns->name string is exactly nine characters long.
 *
 * On x86_64 SYS_olduname / __NR_olduname are not defined -- the syscall
 * exists only on x86_32 and a handful of other legacy ABIs as a compat
 * shim.  The post-syscall oracle below is therefore #if-guarded to a
 * no-op on x86_64; only the sanitiser, argtypes and entry stub remain.
 */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_olduname) || defined(__NR_olduname)
#ifndef SYS_olduname
#define SYS_olduname __NR_olduname
#endif

/*
 * Snapshot of the one olduname input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.
 */
struct olduname_post_state {
	unsigned long name;
};
#endif

static void sanitise_olduname(struct syscallrecord *rec)
{
#if defined(SYS_olduname) || defined(__NR_olduname)
	struct olduname_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	/*
	 * struct old_utsname / oldold_utsname have no portable userspace
	 * declaration; one page is a generous overestimate of the kernel's
	 * writeback window for any of the legacy uname variants.
	 */
	avoid_shared_buffer(&rec->a1, page_size);

#if defined(SYS_olduname) || defined(__NR_olduname)
	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original name
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * the syscall number macro to mirror the .post registration -- on
	 * systems without SYS_olduname the post handler is not registered
	 * and a snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->name = rec->a1;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_olduname) || defined(__NR_olduname)

/*
 * Kernel layout from include/uapi/linux/utsname.h:
 *
 *   struct oldold_utsname {
 *       char sysname[9];
 *       char nodename[9];
 *       char release[9];
 *       char version[9];
 *       char machine[9];
 *   };
 *
 * Five 9-byte char arrays, total 45 bytes.  Fields are NOT guaranteed
 * null-terminated when the source string is exactly 9 characters long
 * (the kernel uname code path copies min(strlen, 9) bytes).  Compares
 * therefore use exact-size memcmp(..., 9), not strcmp.
 */
struct trinity_oldold_utsname {
	char sysname[9];
	char nodename[9];
	char release[9];
	char version[9];
	char machine[9];
};

/*
 * Oracle: SYS_olduname dispatches to the legacy uname code path which
 * copies five fields out of the calling task's uts_ns->name in a single
 * down_read(uts_sem) + copy_to_user.  Two back-to-back calls from the
 * same task into separate user buffers must produce byte-identical
 * five-field results -- the uts_ns->name slot only mutates under
 * sethostname / setdomainname, which take down_write(uts_sem) and
 * serialise against the read.  A divergence between the original
 * syscall payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write that left a torn struct in user memory
 *     (partial write, wrong-offset fill, residual stack data).
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - uts_sem ordering regression letting a concurrent sethostname
 *     race the read of a single field.
 *   - wrong uts_ns lookup on one of the two calls.
 *
 * This is a syscall<->syscall stable-equality oracle, mirroring uname.c
 * but for the truncated five-field oldold_utsname layout.
 *
 * TOCTOU defeat: the one input arg (name) is snapshotted at sanitise
 * time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->a1 between syscall return and post entry cannot
 * redirect the source memcpy at a foreign user buffer.  The user-buffer
 * payload at name is then snapshotted into a stack-local first, then
 * re-issued into a SEPARATE stack buffer (do NOT pass snap->name -- a
 * sibling could mutate it mid-syscall and forge a clean compare).
 * Compare each of the five fields with no early return so multi-field
 * corruption surfaces in a single sample, but bump the anomaly counter
 * only once.  Sample one in a hundred.
 */
static void post_olduname(struct syscallrecord *rec)
{
	struct olduname_post_state *snap =
		(struct olduname_post_state *) rec->post_state;
	struct trinity_oldold_utsname first;
	struct trinity_oldold_utsname recheck;
	bool diverged;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_olduname: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;

	if (snap->name == 0)
		goto out_free;

	{
		void *name = (void *)(unsigned long) snap->name;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner name
		 * field.  Reject pid-scribbled name before deref.
		 */
		if (looks_like_corrupted_ptr(rec, name)) {
			outputerr("post_olduname: rejected suspicious name=%p (post_state-scribbled?)\n",
				  name);
			goto out_free;
		}
	}

	memcpy(&first, (void *)(unsigned long) snap->name, sizeof(first));

	memset(&recheck, 0, sizeof(recheck));
	if (syscall(SYS_olduname, &recheck) != 0)
		goto out_free;

	diverged = (memcmp(first.sysname,  recheck.sysname,  9) != 0) ||
		   (memcmp(first.nodename, recheck.nodename, 9) != 0) ||
		   (memcmp(first.release,  recheck.release,  9) != 0) ||
		   (memcmp(first.version,  recheck.version,  9) != 0) ||
		   (memcmp(first.machine,  recheck.machine,  9) != 0);

	if (!diverged)
		goto out_free;

	{
		char first_hex[5][9 * 2 + 1];
		char recheck_hex[5][9 * 2 + 1];
		const char *first_fields[5] = {
			first.sysname, first.nodename, first.release,
			first.version, first.machine,
		};
		const char *recheck_fields[5] = {
			recheck.sysname, recheck.nodename, recheck.release,
			recheck.version, recheck.machine,
		};
		unsigned int i, j;

		for (i = 0; i < 5; i++) {
			for (j = 0; j < 9; j++) {
				snprintf(first_hex[i] + j * 2, 3, "%02x",
					 (unsigned char) first_fields[i][j]);
				snprintf(recheck_hex[i] + j * 2, 3, "%02x",
					 (unsigned char) recheck_fields[i][j]);
			}
		}

		output(0,
		       "[oracle:olduname] sysname %s vs %s nodename %s vs %s "
		       "release %s vs %s version %s vs %s machine %s vs %s\n",
		       first_hex[0], recheck_hex[0],
		       first_hex[1], recheck_hex[1],
		       first_hex[2], recheck_hex[2],
		       first_hex[3], recheck_hex[3],
		       first_hex[4], recheck_hex[4]);
		__atomic_add_fetch(&shm->stats.olduname_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif /* SYS_olduname || __NR_olduname */

struct syscallentry syscall_olduname = {
	.name = "olduname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_olduname,
#if defined(SYS_olduname) || defined(__NR_olduname)
	.post = post_olduname,
#endif
	.group = GROUP_PROCESS,
};
