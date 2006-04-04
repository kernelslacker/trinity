#include <stdlib.h>
#include "files.h"


/*
 * asmlinkage long sys_splice(int fdin, int fdout, size_t len, unsigned int flags)
 * : len must be > 0
 * : fdin & fdout must be file handles
 *
 */
void sanitise_splice(
				unsigned long *a1,
				unsigned long *a2,
				__attribute((unused)) unsigned long *a3,
				__attribute((unused)) unsigned long *a4,
				__attribute((unused)) unsigned long *a5,
				__attribute((unused)) unsigned long *a6)
{
	/* first param is fdin */
	*a1 = get_random_fd();

	/* second param is fdout */
	*a2 = get_random_fd();

	/* Returns 0 if !len */
	if (*a3 == 0)
		*a1 = rand();

}
