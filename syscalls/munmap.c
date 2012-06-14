/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include "trinity.h"
#include "sanitise.h"
#include "shm.h"

void sanitise_munmap(int childno)
{
retry:
	if (shm->a1[childno] == 0) {
		shm->a1[childno] = (unsigned long) get_address();
		goto retry;
	}
}

struct syscall syscall_munmap = {
	.name = "munmap",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.group = GROUP_VM,
	.sanitise = sanitise_munmap,
};
