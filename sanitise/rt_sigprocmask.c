#include <signal.h>
#include "scrashme.h"

/*
 * asmlinkage long
 sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
 */
void sanitise_rt_sigprocmask(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	*a4 = sizeof(sigset_t);
}
