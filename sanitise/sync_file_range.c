#include <linux/fs.h>
#include "scrashme.h"
#include "sanitise.h"

/*
 * asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 * flags must be part of VALID_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE| SYNC_FILE_RANGE_WAIT_AFTER)
 */

#define VALID_SFR_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER)

void sanitise_sync_file_range(__unused__ unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, __unused__ unsigned long *a5, __unused__ unsigned long *a6)
{

retry_flags:
	if (*a4 & ~VALID_SFR_FLAGS) {
		*a4 = rand64() & VALID_SFR_FLAGS;
		printf("retrying flags\n");
		goto retry_flags;
	}

retry_offset:
	if ((signed long)*a2 < 0) {
		*a2 = rand64();
		printf("retrying offset\n");
		goto retry_offset;
	}

	if ((signed long)*a2+(signed long)*a3 < 0)
		goto retry_offset;

	if (*a2+*a3 < *a2)
		goto retry_offset;
}
