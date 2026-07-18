/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 *
 * On x86_64 the uname syscall (SYS_uname / __NR_uname == 63) dispatches to
 * sys_newuname and writes a 6-field struct new_utsname (six 65-byte char
 * arrays: sysname, nodename, release, version, machine, domainname) -- the
 * legacy 5-field old_utsname comment above is x86-32 / compat-only history.
 * The oracle below targets the x86_64 ABI shape.
 */
#include <stdbool.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/utsname.h>
#include <asm/unistd.h>
#include <string.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef SYS_uname
#define SYS_uname __NR_uname
#endif

/*
 * Snapshot of the one uname input arg plus the poison seed read by the
 * post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot redirect the source
 * memcpy at a foreign user buffer or smear the poison seed against a
 * heap page that happens to still carry a residual pattern from an
 * earlier call.  A poison_seed of 0 means the sanitise-time writability
 * check refused to stamp poison for this call -- the field-diff oracle
 * still runs, the poison check does not.
 */
#define UNAME_POST_STATE_MAGIC	0x554E414DUL	/* "UNAM" */
struct uname_post_state {
	unsigned long magic;
	unsigned long name;
	uint64_t poison_seed;
};

static void sanitise_uname(struct syscallrecord *rec)
{
	struct uname_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, sizeof(struct utsname));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original name
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = UNAME_POST_STATE_MAGIC;
	snap->name = rec->a1;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the output buffer the kernel
	 * is about to fill.  The post handler feeds the seed back into
	 * check_output_struct(); a byte-identical poison after a success
	 * return means the kernel skipped copy_to_user() entirely or short-
	 * copied and left an uninitialised tail readable in user memory (a
	 * kernel->user infoleak).  Done after avoid_shared_buffer_out() so
	 * the poison lands on the final buffer the kernel will see.  Gate
	 * on range_readable_user() so a writable-pool draw that landed on
	 * an address no longer provably mapped -- e.g. a sibling munmap
	 * between allocation and now -- does not SIGSEGV the sanitiser
	 * inside poison_output_struct's byte-walk.  On skip, poison_seed
	 * stays 0 and the post handler no-ops the poison check while the
	 * field-recheck oracle still runs against snap->name.
	 */
	buf = (void *)(unsigned long) rec->a1;
	if (range_readable_user(buf, sizeof(struct new_utsname)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct new_utsname),
							 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: on x86_64, SYS_uname dispatches to sys_newuname and writes a
 * struct new_utsname out of the calling task's uts_ns->name in a single
 * down_read(uts_sem) + copy_to_user.  Two back-to-back calls from the same
 * task into separate user buffers must produce byte-identical 6-field
 * results -- the uts_ns->name slot only mutates under sethostname /
 * setdomainname, which take down_write(uts_sem) and serialise against the
 * read.  A divergence between the original syscall payload and an
 * immediate re-call of the same syscall points at one of:
 *
 *   - copy_to_user mis-write that left a torn struct in user memory
 *     (partial write, wrong-offset fill, residual stack data).
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - uts_sem ordering regression letting a concurrent sethostname /
 *     setdomainname race the read of a single field.
 *   - wrong uts_ns lookup on one of the two calls (namespace bookkeeping
 *     bug surfacing as a per-call discrepancy).
 *   - a neighbour-namespace string leaking into one of the two views.
 *
 * This is the syscall<->syscall stable-equality angle.  It is distinct
 * from the existing newuname.c oracle, which compares the syscall payload
 * against /proc/sys/kernel/{ostype,hostname,osrelease,version,domainname}
 * (syscall<->procfs).  The two oracles can fire independently: a
 * copy_to_user tear shows up here but not in the procfs oracle, while a
 * proc_dostring regression shows up in the procfs oracle but not here.
 *
 * TOCTOU defeat: the one input arg (name) is snapshotted at sanitise time
 * into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->a1 between syscall return and post entry cannot redirect the
 * source memcpy at a foreign user buffer.  The user-buffer payload at
 * name is then snapshotted into a stack-local first, then re-issued into
 * a SEPARATE stack buffer (do NOT pass snap->name -- a sibling could
 * mutate it mid-syscall and forge a clean compare).  Compare each of the
 * six fields with no early return so multi-field corruption surfaces in
 * a single sample, but bump the anomaly counter only once.  Sample one
 * in a hundred to stay in line with the rest of the oracle family.
 */
static void post_uname(struct syscallrecord *rec)
{
	struct uname_post_state *snap;
	struct new_utsname first;
	struct new_utsname recheck;
	bool diverged;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, UNAME_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->name == 0)
		goto out_release;

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->name,
				   sizeof(first)))
		goto out_release;

	/*
	 * Untouched-buffer poison check runs on every success sample the
	 * buffer snapshot succeeded on.  poison_seed of 0 means sanitise
	 * chose not to stamp poison (unwritable pointer) -- skip the check
	 * so "we couldn't poison" is not confused with "kernel didn't
	 * write".  Counts against the shared post_handler_untouched_out_buf
	 * slot.  The heavier field-recheck oracle below stays gated on
	 * ONE_IN(100) because it re-issues the syscall; this check is a
	 * cheap memcmp with no re-issue.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&first, sizeof(first), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if (syscall(SYS_uname, &recheck) != 0)
		goto out_release;

	diverged = (memcmp(first.sysname,    recheck.sysname,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.nodename,   recheck.nodename,   __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.release,    recheck.release,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.version,    recheck.version,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.machine,    recheck.machine,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.domainname, recheck.domainname, __NEW_UTS_LEN + 1) != 0);

	if (!diverged)
		goto out_release;

	{
		char first_hex[6][32 * 2 + 1];
		char recheck_hex[6][32 * 2 + 1];
		const char *first_fields[6] = {
			first.sysname, first.nodename, first.release,
			first.version, first.machine, first.domainname,
		};
		const char *recheck_fields[6] = {
			recheck.sysname, recheck.nodename, recheck.release,
			recheck.version, recheck.machine, recheck.domainname,
		};
		unsigned int i, j;

		for (i = 0; i < 6; i++) {
			for (j = 0; j < 32; j++) {
				snprintf(first_hex[i] + j * 2, 3, "%02x",
					 (unsigned char) first_fields[i][j]);
				snprintf(recheck_hex[i] + j * 2, 3, "%02x",
					 (unsigned char) recheck_fields[i][j]);
			}
		}

		output(0,
		       "[oracle:uname] sysname %s vs %s nodename %s vs %s "
		       "release %s vs %s version %s vs %s machine %s vs %s "
		       "domainname %s vs %s\n",
		       first_hex[0], recheck_hex[0],
		       first_hex[1], recheck_hex[1],
		       first_hex[2], recheck_hex[2],
		       first_hex[3], recheck_hex[3],
		       first_hex[4], recheck_hex[4],
		       first_hex[5], recheck_hex[5]);
		__atomic_add_fetch(&shm->stats.oracle.uname_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_uname = {
	.name = "uname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_uname,
	.post = post_uname,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
