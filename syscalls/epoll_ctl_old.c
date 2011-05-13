/*
   
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_epoll_ctl_old = {
	.name = "ni_syscall (epoll_ctl_old)",
	.num_args = 0,
	.flags = NI_SYSCALL,
};
