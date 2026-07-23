/* signalfd FDs (signalfd4). */

#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "child.h"
#include "fd.h"
#include "syscall-gate.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#ifndef SFD_CLOEXEC
#define SFD_CLOEXEC 02000000
#endif
#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK 04000
#endif

static int do_signalfd4(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigaddset(&mask, SIGCHLD);

#ifdef __NR_signalfd4
	return trinity_raw_syscall(__NR_signalfd4, -1, &mask, sizeof(sigset_t),
		       SFD_CLOEXEC | SFD_NONBLOCK);
#else
	errno = ENOSYS;
	return -1;
#endif
}

#define SIGNALFD_INIT_POOL 4

static int init_signalfd_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SIGNALFD);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;

	for (i = 0; i < SIGNALFD_INIT_POOL; i++) {
		struct object *obj;
		int fd;

		fd = do_signalfd4();
		if (fd < 0)
			continue;

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			return false;
		}
		obj->signalfdobj.fd = fd;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_SIGNALFD);
	}

	return true;
}

static int get_rand_signalfd_fd(void)
{
	if (objects_empty(OBJ_FD_SIGNALFD) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->signalfdobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the signalfd routed into read/poll via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_SIGNALFD, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_SIGNALFD))
			continue;

		fd = obj->signalfdobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Periodic child-tick top-up.  See the block comment above
 * epoll_try_replenish() (fds/epoll.c) for the general contract.
 * init_signalfd_fds() seeds SIGNALFD_INIT_POOL entries once; without
 * this hook a child that drained its private copy via close / dup2 /
 * close_range hits stopped seeing signalfds at all.
 *
 * Same tradeoff the epoll hook documents: init_signalfd_fds() stores
 * fds inside objects (obj->signalfdobj.fd) that get_rand_signalfd_fd()
 * reads for ARG_FD_SIGNALFD, but a post-fork add_object(OBJ_GLOBAL) is
 * a no-op by the mainpid guard in objects/registry.c.  child_fd_ring_
 * push() therefore feeds the generic ARG_FD live-fd path in gen_arg_fd()
 * rather than the typed ARG_FD_SIGNALFD pool -- reachability from the
 * generic side is the win.
 */
static void signalfd_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	/*
	 * See the block comment above memfd_try_replenish() (fds/memfd.c) for
	 * the rationale.  child_fd_ring_push() is a shared, pure-overwrite
	 * hint cache -- it does not own the fds it evicts.  Every signalfd
	 * we mint past live_fds's 16-slot window would leak for the child's
	 * life, so keep a per-child 32-slot ring of the signalfds WE created
	 * and close the one that ages out before reusing its slot.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		int fd = do_signalfd4();

		if (fd < 0)
			return;

		if (created_head >= ARRAY_SIZE(created_fds))
			close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
		created_fds[created_head % ARRAY_SIZE(created_fds)] = fd;
		created_head++;

		child_fd_ring_push(&child->live_fds, fd);
	}
}

static const struct fd_provider signalfd_fd_provider = {
	.name = "signalfd",
	.objtype = OBJ_FD_SIGNALFD,
	.enabled = true,
	.init = &init_signalfd_fds,
	.get = &get_rand_signalfd_fd,
	.try_replenish = &signalfd_try_replenish,
};

REG_FD_PROV(signalfd_fd_provider);
