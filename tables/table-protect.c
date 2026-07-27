/*
 * Per-arch syscallentry descriptor tables PROT_READ freeze.
 *
 * Carved out of tables/tables.c: this file owns the mprotect-extent
 * bookkeeping (desc_extents[]) that copy_syscall_table() populates via
 * out-params and select_syscall_tables() files, plus the freeze itself
 * that runs after munge_tables() completes and before fork_children().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include "tables.h"
#include "utils.h"

/*
 * Per-arch descriptor table extents captured at select_syscall_tables()
 * time so protect_syscall_tables() can mprotect(PROT_READ) exactly the
 * page span the descriptor array occupies.  Only the entries populated
 * by the active biarch/uniarch branch of select_syscall_tables() have
 * non-zero .len; protect_syscall_tables() skips zero-len slots so it
 * is safe to call under either build configuration.
 */
struct desc_extent desc_extents[3];

/*
 * Freeze the per-arch syscallentry descriptor tables PROT_READ after
 * munge_tables() has finished stamping the ACTIVE / TO_BE_DEACTIVATED /
 * EXPLICITLY_EXCLUDED flag bits and before fork_children() carves the
 * fleet.  A subsequent wild write from a fuzzed child into any field
 * of a descriptor (num_args, argtype[], argname[], flags, ...) faults
 * at the offending store instead of driving downstream code down a
 * corrupted path -- retire of the defensive clamps in for_each_arg,
 * gen_arg_struct_ptr and health/post-mortem rides on this contract.
 * The parallel syscall_runtime array stays RW on its own mapping so
 * per-child stats / scoreboard writes continue to succeed.
 */
void protect_syscall_tables(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(desc_extents); i++) {
		if (desc_extents[i].base == NULL || desc_extents[i].len == 0)
			continue;
		if (mprotect(desc_extents[i].base, desc_extents[i].len,
			     PROT_READ) != 0) {
			int saved_errno = errno;

			log_mprotect_failure(desc_extents[i].base,
					     desc_extents[i].len, PROT_READ,
					     __builtin_return_address(0),
					     saved_errno);
			outputerr("protect_syscall_tables: mprotect(desc[%u] base=%p len=%zu) failed: %s\n",
				  i, desc_extents[i].base, desc_extents[i].len,
				  strerror(saved_errno));
			exit(EXIT_FAILURE);
		}
	}
}
