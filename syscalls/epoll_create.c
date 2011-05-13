/*
 * SYSCALL_DEFINE1(epoll_create, int, size)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_epoll_create = {
	.name = "epoll_create",
	.num_args = 1,
	.arg1name = "size",
	.arg1type = ARG_LEN,
};
