/*
 * SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol, int __user *, usockvec)
 */
#include <stdlib.h>
#include <sys/socket.h>
#include "net.h"
#include "objects.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void register_socketpair_fd(int fd, struct syscallrecord *rec)
{
	struct object *new;

	if (fd <= 2)
		return;
	if (find_local_object_by_fd(OBJ_FD_SOCKET, fd) != NULL)
		return;

	new = alloc_object();
	new->sockinfo.fd = fd;
	new->sockinfo.triplet.family = rec->a1;
	new->sockinfo.triplet.type = rec->a2;
	new->sockinfo.triplet.protocol = rec->a3;
	add_object(new, OBJ_LOCAL, OBJ_FD_SOCKET);
}

/*
 * Snapshot for the post handler.  Mirrors the pipe.c fix shape: the raw
 * int[2] result buffer is no longer parked in rec->post_state directly --
 * a sibling scribbling rec->post_state with any heap-shaped 8-byte aligned
 * pointer (a different syscall's post_state, a stale alloc_iovec(1) in
 * the same free-list bucket, ...) would sail past looks_like_corrupted_ptr()
 * and post_socketpair would then read usockvec[0]/usockvec[1] out of foreign
 * bytes and feed them to register_socketpair_fd() as putative fds.  Wrap
 * the buffer pointer in a magic-cookie struct so the raw int[2] is no
 * longer exposed via post_state -- post_socketpair reads usockvec through
 * snap->usockvec, and a cookie mismatch rejects foreign-allocation
 * forgeries before any inner-field deref.
 *
 * Two pointers are stored.  ->usockvec is the address the kernel actually
 * writes the returned int[2] into -- avoid_shared_buffer_out() relocates
 * rec->a4 off the libc heap into a parent-private writable region, so
 * post_socketpair must read fds from the relocated buffer, not the zmalloc
 * result.  ->original_alloc is the zmalloc()'d pointer we hand back to
 * deferred_free_enqueue(): the relocated buffer is owned by the
 * writable-address allocator (mmap'd, alloc-track-unknown) and would be
 * rejected by deferred_free_enqueue()'s heap-bounds and alloc-track gates,
 * leaking the original zmalloc.
 */
#define SOCKETPAIR_POST_STATE_MAGIC	0x534F434B5F4D4147UL	/* "SOCK_MAG" */
struct socketpair_post_state {
	unsigned long magic;
	int *usockvec;
	int *original_alloc;
};

static void sanitise_socketpair(struct syscallrecord *rec)
{
	struct socket_triplet st = { .family = 0, .type = 0, .protocol = 0 };
	int *usockvec;
	struct socketpair_post_state *snap;

	gen_socket_args(&st);

	rec->a1 = st.family;
	rec->a2 = st.type;
	rec->a3 = st.protocol;

	usockvec = zmalloc(sizeof(int) * 2);
	rec->a4 = (unsigned long) usockvec;
	if (!rec->a4)
		return;

	avoid_shared_buffer_out(&rec->a4, 2 * sizeof(int));

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SOCKETPAIR_POST_STATE_MAGIC;
	snap->usockvec = (int *) rec->a4;
	snap->original_alloc = usockvec;
	rec->post_state = (unsigned long) snap;
}

static void post_socketpair(struct syscallrecord *rec)
{
	struct socketpair_post_state *snap =
		(struct socketpair_post_state *) rec->post_state;
	int *usockvec;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_socketpair: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * socketpair_post_state -- post_socketpair would then read
	 * usockvec[0]/usockvec[1] out of a foreign buffer and feed them
	 * to register_socketpair_fd as putative fds.
	 */
	if (snap->magic != SOCKETPAIR_POST_STATE_MAGIC) {
		outputerr("post_socketpair: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a4 = 0;
		rec->post_state = 0;
		return;
	}

	usockvec = snap->usockvec;

	if (usockvec == NULL || looks_like_corrupted_ptr(rec, usockvec)) {
		outputerr("post_socketpair: rejected suspicious usockvec=%p "
			  "(post_state-scribbled?)\n", usockvec);
		rec->a4 = 0;
		goto out_free;
	}

	if ((long) rec->retval == 0) {
		register_socketpair_fd(usockvec[0], rec);
		register_socketpair_fd(usockvec[1], rec);
	}

	rec->a4 = 0;
	deferred_free_enqueue(snap->original_alloc);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_socketpair = {
	.name = "socketpair",
	.num_args = 4,
	.argtype = { [3] = ARG_ADDRESS },
	.argname = { [0] = "family", [1] = "type", [2] = "protocol", [3] = "usockvec" },
	.group = GROUP_NET,
	.sanitise = sanitise_socketpair,
	.post = post_socketpair,
	.rettype = RET_ZERO_SUCCESS,
};
