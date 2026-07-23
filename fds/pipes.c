/* Pipe FD related functions. */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "child.h"
#include "deferred-free.h"
#include "fd.h"
#include "objects.h"
#include "pipes.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "unblocker.h"
#include "utils.h"

#include "kernel/fcntl.h"
/*
 * Cross-process safe: only reads obj->pipeobj scalar fields and the
 * scope scalar.  These survive fork/COW and no process-local pointers
 * are dereferenced, so calling this from a different process than the
 * allocator is correct — relevant because head->dump runs from
 * dump_childdata() in the parent's crash diagnostics path even when a
 * child triggered the crash.
 */
static void pipefd_dump(struct object *obj, enum obj_scope scope)
{
	struct pipeobj *po = &obj->pipeobj;

	output(2, "pipe fd:%d flags:%x [%s] scope:%d\n",
		po->fd, po->flags,
		po->reader ? "reader" : "writer",
		scope);
}

static void open_pipe_pair(unsigned int flags)
{
	struct object *robj, *wobj;
	int pipes[2];

	if (pipe2(pipes, flags) < 0) {
		perror("pipe fail.\n");
		return;
	}

	/*
	 * Allocate both objs before publishing either to the pool.  If we
	 * add the read end first and the second alloc_object() then fails,
	 * pipe[0] is left in the pool with no paired writer — consumers
	 * that clear O_NONBLOCK will block forever on the orphaned reader.
	 */
	robj = alloc_object();
	if (robj == NULL) {
		close(pipes[0]);
		close(pipes[1]);
		return;
	}

	wobj = alloc_object();
	if (wobj == NULL) {
		memset(robj, 0, sizeof(*robj));
		deferred_free_enqueue(robj);
		close(pipes[0]);
		close(pipes[1]);
		return;
	}

	robj->pipeobj.fd = pipes[0];
	robj->pipeobj.flags = flags;
	robj->pipeobj.reader = true;
	add_object(robj, OBJ_GLOBAL, OBJ_FD_PIPE);

	wobj->pipeobj.fd = pipes[1];
	wobj->pipeobj.flags = flags;
	wobj->pipeobj.reader = false;
	add_object(wobj, OBJ_GLOBAL, OBJ_FD_PIPE);
}


static int open_pipe(void)
{
	int flags;

	flags = RAND_BOOL() ? O_NONBLOCK : 0;
	if (RAND_BOOL())
		flags |= O_CLOEXEC;

	open_pipe_pair(flags);
	return true;
}

static int init_pipes(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_PIPE);
	head->destroy = &close_fd_destructor;
	head->dump = &pipefd_dump;

	for (i = 0; i < 16; i++)
		open_pipe();

	return true;
}

int get_rand_pipe_fd(void)
{
	if (objects_empty(OBJ_FD_PIPE) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->pipeobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window:
	 * between the lockless slot pick and the consumer's read of
	 * the pipe fd routed into read/write/splice via the fd_provider .get callback,
	 * the parent can destroy the obj; release_obj() zeroes the chunk
	 * and routes it through deferred-free, so the stale slot pointer
	 * can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_PIPE, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_PIPE))
			continue;

		fd = obj->pipeobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

/*
 * Per-child periodic hook for the pipes provider.  Pokes one writer-
 * end fd with a single byte (non-blocking, flags restored after) so a
 * concurrent reader on an empty pipe doesn't sit indefinitely in
 * wait_event_interruptible_exclusive(pipe->rd_wait).  Kernel pipe-
 * reads are already killable in current Linux; this is belt-and-
 * suspenders for the orphaned-blocking-reader wedge open_pipe_pair()
 * warns about explicitly.
 *
 * Cheap: at most ~8 random object picks + one fcntl pair + one
 * write(1).  Bumps shm->stats.pipe_waker_* counters; no other side
 * effects.
 */
static void pipes_child_ops(void)
{
	pipe_waker_poke_one();
}

/*
 * Periodic child-tick top-up.  init_pipes() seeds 16 pairs into the
 * OBJ_GLOBAL pool once; a child that has closed most of them via
 * close/dup2/close_range stops seeing ARG_FD_PIPE picks.  Push fresh
 * pipe ends into the live-fd ring so gen_arg_fd()'s live-fd branch
 * keeps hitting.  add_object(OBJ_GLOBAL) from child context is a no-op,
 * so call pipe2() raw rather than open_pipe_pair().  Mirror init's
 * flag distribution (O_NONBLOCK ? / O_CLOEXEC ?) and push both ends;
 * reader/writer OBJ coupling is init-pool-only, and the live_fds ring
 * only tracks raw fds.
 */
static void pipe_try_replenish(unsigned int budget)
{
	struct childdata *child = this_child();
	unsigned int i;
	/*
	 * See the block comment above memfd_try_replenish() (fds/memfd.c) for
	 * the rationale.  child_fd_ring_push() is a shared, pure-overwrite
	 * hint cache -- it does not own the fds it evicts.  We push both
	 * pipe ends per tick, so every pair past live_fds's 16-slot window
	 * would leak (kernel pipe-buffer pages) for the child's life.  Keep
	 * a per-child 32-slot ring of the pipe fds WE created and close the
	 * one that ages out before reusing its slot.
	 */
	static int created_fds[32];
	static unsigned int created_head;

	if (child == NULL)
		return;

	for (i = 0; i < budget; i++) {
		int flags = RAND_BOOL() ? O_NONBLOCK : 0;
		int pipefd[2];
		unsigned int j;

		if (RAND_BOOL())
			flags |= O_CLOEXEC;

		if (pipe2(pipefd, flags) < 0)
			return;

		for (j = 0; j < 2; j++) {
			if (created_head >= ARRAY_SIZE(created_fds))
				close(created_fds[created_head % ARRAY_SIZE(created_fds)]);
			created_fds[created_head % ARRAY_SIZE(created_fds)] = pipefd[j];
			created_head++;
		}

		child_fd_ring_push(&child->live_fds, pipefd[0]);
		child_fd_ring_push(&child->live_fds, pipefd[1]);
	}
}

static const struct fd_provider pipes_fd_provider = {
	.name = "pipes",
	.objtype = OBJ_FD_PIPE,
	.enabled = true,
	.init = &init_pipes,
	.get = &get_rand_pipe_fd,
	.child_ops = &pipes_child_ops,
	.try_replenish = &pipe_try_replenish,
};

REG_FD_PROV(pipes_fd_provider);
