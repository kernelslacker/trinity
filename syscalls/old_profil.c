/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_old_profil = {
	.name = "ni_syscall (old profil syscall)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
