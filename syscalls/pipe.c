/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "objects.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void register_pipe_fd(int fd, bool reader)
{
	struct object *new;

	if (fd <= 2)
		return;
	if (find_local_object_by_fd(OBJ_FD_PIPE, fd) != NULL)
		return;

	new = alloc_object();
	new->pipeobj.fd = fd;
	new->pipeobj.reader = reader;
	add_object(new, OBJ_LOCAL, OBJ_FD_PIPE);
}

/*
 * Snapshot for the post handler.  Previously the raw int[2] result
 * buffer was parked in rec->post_state and post_pipe read fildes[0]/
 * fildes[1] off it directly if the pointer looked heap-shaped.  But the
 * heap-shape check on rec->post_state is value-based only -- a sibling
 * scribbling rec->post_state with any heap-shaped 8-byte aligned pointer
 * (a different syscall's post_state, a stale alloc_iovec(1) in the same
 * free-list bucket, ...) sails past looks_like_corrupted_ptr() and
 * post_pipe then reads fildes[0]/fildes[1] out of foreign bytes and
 * feeds them to register_pipe_fd() as putative fds.  Wrap the buffer
 * pointer in a magic-cookie struct so the raw int[2] is no longer
 * exposed via post_state -- post_pipe reads fildes through snap->fildes,
 * and a cookie mismatch rejects foreign-allocation forgeries before any
 * inner-field deref.  Mirrors RECVMSG_POST_STATE_MAGIC at recv.c:103.
 * Sized 24 bytes to stay clear of the 16-byte free-list bucket that
 * holds alloc_iovec(1) and other small allocations.
 *
 * Two pointers are stored.  ->fildes is the address the kernel actually
 * writes the returned int[2] into -- avoid_shared_buffer_out() relocates
 * rec->a1 off the libc heap into a parent-private writable region, so
 * post_pipe must read fds from the relocated buffer, not the zmalloc
 * result.  ->original_alloc is the zmalloc()'d pointer we hand back to
 * deferred_free_enqueue(): the relocated buffer is owned by the
 * writable-address allocator (mmap'd, alloc-track-unknown) and would be
 * rejected by deferred_free_enqueue()'s heap-bounds and alloc-track
 * gates.
 */
#define PIPE_POST_STATE_MAGIC	0x504950455F4D4147UL	/* "PIPE_MAG" */
struct pipe_post_state {
	unsigned long magic;
	int *fildes;
	int *original_alloc;
};

static void sanitise_pipe(struct syscallrecord *rec)
{
	int *fildes = zmalloc(sizeof(int) * 2);
	struct pipe_post_state *snap;

	rec->a1 = (unsigned long) fildes;

	avoid_shared_buffer_out(&rec->a1, 2 * sizeof(int));

	snap = zmalloc(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	snap->fildes = (int *) rec->a1;
	snap->original_alloc = fildes;
	rec->post_state = (unsigned long) snap;
}

static void post_pipe(struct syscallrecord *rec)
{
	struct pipe_post_state *snap =
		(struct pipe_post_state *) rec->post_state;
	int *fildes;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_pipe: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * pipe_post_state -- post_pipe would then read fildes[0]/fildes[1]
	 * out of a foreign buffer and feed them to register_pipe_fd as
	 * putative fds.  Mirrors recv.c:212.
	 */
	if (snap->magic != PIPE_POST_STATE_MAGIC) {
		outputerr("post_pipe: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	fildes = snap->fildes;

	if (fildes == NULL || looks_like_corrupted_ptr(rec, fildes)) {
		outputerr("post_pipe: rejected suspicious fildes=%p "
			  "(post_state-scribbled?)\n", fildes);
		rec->a1 = 0;
		goto out_free;
	}

	if ((long) rec->retval == 0) {
		register_pipe_fd(fildes[0], true);
		register_pipe_fd(fildes[1], false);
	}

	rec->a1 = 0;
	deferred_free_enqueue(snap->original_alloc);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_pipe = {
	.name = "pipe",
	.num_args = 1,
	.argname = { [0] = "fildes" },
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe,
	.post = post_pipe,
	.rettype = RET_ZERO_SUCCESS,
};

/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE	O_EXCL
#endif

static unsigned long pipe2_flags[] = {
	O_CLOEXEC, O_NONBLOCK, O_DIRECT, O_NOTIFICATION_PIPE,
};

static void sanitise_pipe2(struct syscallrecord *rec)
{
	int *fildes = zmalloc(sizeof(int) * 2);
	struct pipe_post_state *snap;

	rec->a1 = (unsigned long) fildes;

	avoid_shared_buffer_out(&rec->a1, 2 * sizeof(int));

	snap = zmalloc(sizeof(*snap));
	snap->magic = PIPE_POST_STATE_MAGIC;
	snap->fildes = (int *) rec->a1;
	snap->original_alloc = fildes;
	rec->post_state = (unsigned long) snap;
}

struct syscallentry syscall_pipe2 = {
	.name = "pipe2",
	.num_args = 2,
	.argtype = { [1] = ARG_LIST },
	.argname = { [0] = "fildes", [1] = "flags" },
	.arg_params[1].list = ARGLIST(pipe2_flags),
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe2,
	.post = post_pipe,
	.rettype = RET_ZERO_SUCCESS,
};
