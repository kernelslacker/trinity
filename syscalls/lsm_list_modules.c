/*
 * SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
 *		u32, flags)
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules __NR_lsm_list_modules
#endif

static void sanitise_lsm_list_modules(struct syscallrecord *rec)
{
	u32 *size;
	void *buf;

	/*
	 * The kernel reads *size to find how much space is available for the
	 * u64 LSM ID array. A zero causes immediate E2BIG. Provide a
	 * page-sized buffer and initialize the size accordingly.
	 */
	buf = get_writable_address(page_size);
	size = (u32 *) get_writable_address(sizeof(*size));
	if (!buf || !size)
		return;
	*size = page_size;
	rec->a1 = (unsigned long) buf;
	rec->a2 = (unsigned long) size;
	rec->a3 = 0;	/* flags must be zero */
}

/*
 * Oracle: lsm_list_modules(ids, size, flags) reports the IDs of the LSM
 * modules currently loaded into the kernel's LSM stack as a u64 array,
 * with the byte-count of the array written back through *size.  The LSM
 * stack is fixed at boot -- modules cannot be loaded or unloaded at
 * runtime -- so two back-to-back calls from the same task must produce
 * byte-identical results.  Any divergence between the first call's
 * payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right answer but
 *     it landed in the wrong slot in the user buffer or arrived torn.
 *   - sibling-thread scribble of the user receive buffer or size word
 *     between the syscall return and our post-hook re-read.
 *   - 32-bit-on-64-bit compat sign-extension on the size word.
 *   - LSM-stack accounting drift (a regression that lets the stack
 *     mutate at runtime, which it must never do).
 *
 * TOCTOU defeat: a sibling thread in the same trinity child can scribble
 * either the user IDs payload at rec->a1 or the size word at rec->a2 via
 * alloc_shared writes between the original syscall return and our
 * re-issue.  Snapshot both into stack-locals first, then re-issue with
 * fresh private buffers (do NOT pass rec->a1/rec->a2 -- a sibling could
 * mutate them mid-syscall and we want a clean compare).  The flags arg
 * is forced to zero by the sanitiser and is not part of the comparison.
 *
 * Comparison rules (no early return on first mismatch -- multi-field
 * corruption surfaces in a single sample):
 *   - size word must match byte-for-byte across the two calls.
 *   - the u64 IDs payload, of length first_size bytes, must match
 *     byte-for-byte across the two calls.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Wired only on syscall_lsm_list_modules -- the syscall stands
 * alone with no aliases.
 */
static void post_lsm_list_modules(struct syscallrecord *rec)
{
	u32 first_size;
	u64 first_ids[64];
	size_t first_count;
	u64 recheck_ids[64];
	u32 recheck_size = sizeof(recheck_ids);
	bool size_diverged;
	bool ids_diverged;
	int rc;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;

	if (rec->a1 == 0 || rec->a2 == 0)
		return;

	memcpy(&first_size, (void *)(unsigned long) rec->a2,
	       sizeof(first_size));
	if (first_size == 0 || first_size > page_size)
		return;

	first_count = first_size / sizeof(u64);
	if (first_count > 64)
		return;

	memcpy(first_ids, (void *)(unsigned long) rec->a1,
	       first_count * sizeof(u64));

	rc = syscall(SYS_lsm_list_modules, recheck_ids, &recheck_size, 0);
	if (rc != 0)
		return;

	size_diverged = (first_size != recheck_size);
	ids_diverged = (memcmp(first_ids, recheck_ids,
			       first_count * sizeof(u64)) != 0);

	if (size_diverged || ids_diverged) {
		size_t recheck_count = recheck_size / sizeof(u64);
		size_t i;
		char first_hex[64 * 17 + 1];
		char recheck_hex[64 * 17 + 1];
		size_t off;

		if (recheck_count > 64)
			recheck_count = 64;

		off = 0;
		for (i = 0; i < first_count; i++)
			off += snprintf(first_hex + off,
					sizeof(first_hex) - off,
					"%016lx ",
					(unsigned long) first_ids[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < recheck_count; i++)
			off += snprintf(recheck_hex + off,
					sizeof(recheck_hex) - off,
					"%016lx ",
					(unsigned long) recheck_ids[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:lsm_list_modules] size %u vs %u ids [%s] vs [%s]\n",
		       first_size, recheck_size, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.lsm_list_modules_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_lsm_list_modules = {
	.name = "lsm_list_modules",
	.num_args = 3,
	.argname = { [0] = "ids", [1] = "size", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_lsm_list_modules,
	.post = post_lsm_list_modules,
	.group = GROUP_PROCESS,
};
