#include "scrashme.h"
#include "sanitise.h"

/*
 * asmlinkage ssize_t sys_pwrite64(unsigned int fd, char __user *buf,
				                 size_t count, loff_t pos)
 */
void sanitise_pwrite64(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{

retry_pos:
	if ((int)*a4 < 0) {
		*a4 = rand64();
		goto retry_pos;
	}
}
