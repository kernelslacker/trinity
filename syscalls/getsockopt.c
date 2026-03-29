/*
 * SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen)
 */
#include <stdlib.h>
#include "arch.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "utils.h"

static void sanitise_getsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	socklen_t *lenp;
	int fd;

	si = (struct socketinfo *) rec->a1;
	if (si == NULL) {
		rec->a1 = get_random_fd();
		return;
	}

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
		fd = si->fd;
		triplet = &si->triplet;
	}

	rec->a1 = fd;

	do_setsockopt(&so, triplet);

	rec->a2 = so.level;
	rec->a3 = so.optname;

	/* do_setsockopt allocates optval — we only needed level/optname. */
	free((void *) so.optval);

	/* Allocate an output buffer for the kernel to write into. */
	rec->a4 = (unsigned long) zmalloc(page_size);

	/* Provide a valid socklen_t pointer initialized to the buffer size. */
	lenp = zmalloc(sizeof(*lenp));
	*lenp = page_size;
	rec->a5 = (unsigned long) lenp;
}

static void post_getsockopt(struct syscallrecord *rec)
{
	deferred_freeptr(&rec->a4);
	deferred_freeptr(&rec->a5);
}

struct syscallentry syscall_getsockopt = {
	.name = "getsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_getsockopt,
	.post = post_getsockopt,
};
