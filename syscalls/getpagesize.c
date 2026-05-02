/*
 * sys_getpagesize (void)
 */
#include <unistd.h>
#include "shm.h"
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: sys_getpagesize, when present, must return the architectural
 * page size -- the same value the kernel reports via the ELF auxv
 * AT_PAGESZ entry that glibc caches and exposes through
 * sysconf(_SC_PAGESIZE).  On x86_64 the syscall is unimplemented and
 * returns -ENOSYS, but on the architectures that still wire it up
 * (alpha, arm, m68k, mips, sh, sparc, ...) any successful return must
 * agree with sysconf, otherwise userspace mmap math, malloc arenas
 * and stack guard placement all silently corrupt.
 *
 * Only sample successful returns; -ENOSYS is the expected outcome on
 * the most common host and isn't an anomaly.  ONE_IN(100) keeps the
 * sysconf cost in line with the rest of the oracle family.
 */
static void post_getpagesize(struct syscallrecord *rec)
{
	long expected;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	expected = sysconf(_SC_PAGESIZE);
	if (expected <= 0)
		return;

	if ((long) rec->retval != expected) {
		output(0, "getpagesize oracle: returned %ld but sysconf(_SC_PAGESIZE)=%ld\n",
		       (long) rec->retval, expected);
		__atomic_add_fetch(&shm->stats.getpagesize_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getpagesize = {
	.name = "getpagesize",
	.num_args = 0,
	.group = GROUP_PROCESS,
	.post = post_getpagesize,
};
