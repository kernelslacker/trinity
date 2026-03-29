/*
 * SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/socket.h>
#include "sanitise.h"
#include "shm.h"

static void sanitise_bind(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

/*
static void dump(struct syscallrecord *rec)
{
	struct sockaddr_in *ipv4;

	ipv4 = (struct sockaddr_in *) rec->a2;
	output(1, "(sin_family=%d sin_addr.s_addr=%d.%d.%d.%d sin_port=%d)\n",
		ipv4->sin_family,
		(ipv4->sin_addr.s_addr & 0xff000000) >> 24,
		(ipv4->sin_addr.s_addr & 0xff0000) >> 16,
		(ipv4->sin_addr.s_addr & 0xff00) >> 8,
		(ipv4->sin_addr.s_addr & 0xff) ,
		ipv4->sin_port);
}
*/

struct syscallentry syscall_bind = {
	.name = "bind",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "umyaddr", [2] = "addrlen" },
	//.sanitise = dump,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_bind,
};
