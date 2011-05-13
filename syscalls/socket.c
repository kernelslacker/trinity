/*
 * SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_socket = {
	.name = "socket",
	.num_args = 3,
	.arg1name = "family",
	.arg2name = "type",
	.arg3name = "protocol",
};
