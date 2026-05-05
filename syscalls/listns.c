/*
 * SYSCALL_DEFINE4(listns, const struct ns_id_req __user *, req,
 *		u64 __user *, ns_ids, size_t, nr_ns_ids,
 *		unsigned int, flags)
 */
#include <linux/types.h>
#include <sched.h>
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.
 * Define locally to build against older kernel headers.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 ns_type;
	__u64 ns_id;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	24
#endif

#ifndef LISTNS_CURRENT_USER
#define LISTNS_CURRENT_USER	(1 << 0)
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME		0x00000080
#endif

static unsigned long listns_flags[] = {
	LISTNS_CURRENT_USER,
};

static unsigned long ns_types[] = {
	CLONE_NEWNS,
	CLONE_NEWUTS,
	CLONE_NEWIPC,
	CLONE_NEWUSER,
	CLONE_NEWPID,
	CLONE_NEWNET,
	CLONE_NEWCGROUP,
	CLONE_NEWTIME,
};

/*
 * Snapshot of the listns input args read by the post oracle, captured at
 * sanitise time and consumed by the post handler.  Lives in rec->post_state,
 * a slot the syscall ABI does not expose, so a sibling syscall scribbling
 * rec->aN between the syscall returning and the post handler running cannot
 * smear the size bound used to validate the retval.
 */
struct listns_post_state {
	unsigned long req;
	unsigned long nr_ns_ids;
};

static void sanitise_listns(struct syscallrecord *rec)
{
	struct ns_id_req *req;
	struct listns_post_state *snap;

	req = zmalloc(sizeof(struct ns_id_req));
	req->size = NS_ID_REQ_SIZE_VER0;
	req->ns_type = ns_types[rand() % ARRAY_SIZE(ns_types)];

	rec->a1 = (unsigned long) req;
	rec->a3 = RAND_RANGE(1, 512);

	/*
	 * ns_ids (a2) is the kernel's writeback target: a u64 array of the
	 * matching namespace ids, up to a3 entries.  ARG_NON_NULL_ADDRESS
	 * draws from the random pool, so a fuzzed pointer can land inside
	 * an alloc_shared region.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3 * sizeof(__u64));

	/* Snapshot for the post handler -- a1 / a3 may be scribbled by a
	 * sibling syscall before post_listns() runs. */
	snap = zmalloc(sizeof(*snap));
	snap->req = rec->a1;
	snap->nr_ns_ids = rec->a3;
	rec->post_state = (unsigned long) snap;
}

static void post_listns(struct syscallrecord *rec)
{
	struct listns_post_state *snap = (struct listns_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_listns: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Kernel ABI: sys_listns writes at most nr_ns_ids u64 namespace IDs
	 * to the user buffer and returns the count written, capped at the
	 * snapshotted nr_ns_ids arg.  Failure returns -1UL.  Anything >
	 * snap->nr_ns_ids on a non-(-1UL) return is structural ABI
	 * corruption: a sign-extension tear in the syscall return path, a
	 * kernel-side write that spilled past the user-supplied bound, or a
	 * torn read of the namespace iterator counter.  Fall through to
	 * out_free so the deferred req / post_state buffers are still
	 * released.
	 */
	if ((long) rec->retval != -1L &&
	    (unsigned long) rec->retval > snap->nr_ns_ids) {
		outputerr("post_listns: retval %lu exceeds requested nr_ns_ids %lu\n",
			  (unsigned long) rec->retval, snap->nr_ns_ids);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

out_free:
	rec->a1 = 0;
	deferred_freeptr(&snap->req);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_listns = {
	.name = "listns",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "req", [1] = "ns_ids", [2] = "nr_ns_ids", [3] = "flags" },
	.arg_params[3].list = ARGLIST(listns_flags),
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_listns,
	.post = post_listns,
	.group = GROUP_PROCESS,
	.bound_arg = 3,
};
