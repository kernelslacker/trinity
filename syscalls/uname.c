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
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/utsname.h>
#include <asm/unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#ifndef SYS_uname
#define SYS_uname __NR_uname
#endif

static void sanitise_uname(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct utsname));
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
 * TOCTOU defeat: the user receive buffer at rec->a1 is alloc_shared
 * memory and a sibling can scribble it between the original return and
 * our re-issue.  Snapshot it into a stack-local first, then re-issue
 * into a SEPARATE stack buffer (do NOT pass rec->a1 -- a sibling could
 * mutate it mid-syscall and we want a clean compare).  Compare each of
 * the six fields with no early return so multi-field corruption surfaces
 * in a single sample, but bump the anomaly counter only once.  Sample
 * one in a hundred to stay in line with the rest of the oracle family.
 */
static void post_uname(struct syscallrecord *rec)
{
	struct new_utsname first;
	struct new_utsname recheck;
	bool diverged;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;

	if (rec->a1 == 0)
		return;

	memcpy(&first, (void *)(unsigned long) rec->a1, sizeof(first));

	if (syscall(SYS_uname, &recheck) != 0)
		return;

	diverged = (memcmp(first.sysname,    recheck.sysname,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.nodename,   recheck.nodename,   __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.release,    recheck.release,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.version,    recheck.version,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.machine,    recheck.machine,    __NEW_UTS_LEN + 1) != 0) ||
		   (memcmp(first.domainname, recheck.domainname, __NEW_UTS_LEN + 1) != 0);

	if (!diverged)
		return;

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
		__atomic_add_fetch(&shm->stats.uname_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_uname = {
	.name = "uname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_uname,
	.post = post_uname,
	.group = GROUP_PROCESS,
};
