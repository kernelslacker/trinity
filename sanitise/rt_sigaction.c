#include <signal.h>
#include "scrashme.h"

/*
 * asmlinkage long sys_rt_sigaction(int sig,
          const struct sigaction __user *act,
          struct sigaction __user *oact,
          size_t sigsetsize)
 */

void sanitise_rt_sigaction(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	*a4 = sizeof(sigset_t);
}
