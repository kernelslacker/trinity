/*
 * SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen)
 */
#include "arch.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "utils.h"
#include "valresult.h"

/*
 * Snapshot for the post handler: the valresult_buf whose buffers it gives
 * back to deferred_free_enqueue() through valresult_free().  They never
 * reach the kernel, which gets a buffer and a length word from the call's
 * pool instead.  The cookie hardens the post handler against a sibling
 * scribbling rec->post_state with a heap-shaped pointer to a foreign
 * allocation -- the cookie mismatch rejects the forgery before any
 * inner-field deref.
 */
#define GETSOCKOPT_POST_STATE_MAGIC	0x474554534F50545FUL	/* "GETSOPT_" */
struct getsockopt_post_state {
	unsigned long magic;
	struct valresult_buf vrb;
};

static void sanitise_getsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	struct getsockopt_post_state *snap;
	struct valresult_buf vrb;
	size_t buf_len;
	int *optlen;
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

	/* do_setsockopt allocates optval — we only needed level/optname.
	 * Dispatch via the helper so SO_ATTACH_FILTER's sock_fprog wrapper
	 * releases both the outer + inner filter buffer instead of leaking
	 * the inner (and double-freeing once the alloc-tracker evicts it). */
	release_sockopt_optval(&so);

	/*
	 * The (optval, *optlen) pair is shaped by the shared shape
	 * catalogue from page_size, the natural capacity (most options fit
	 * comfortably): EXACT / UNDER / +1 / HUGE / ZERO.  The kernel gets
	 * both from the call's pool, the low pool for a compat call, which
	 * reads each pointer slot as its low 32 bits: HUGE's 4 MiB is a heap
	 * buffer no pool can stand in for, which malloc() maps past 4 GiB.
	 * The buffer is a page at most, which nearly every option's value
	 * fits in, and a longer value runs on into pool scratch, or to the
	 * pool's guard page; the length word takes the shape's length.
	 *
	 * The snap doubles as a sibling-scribble shield: a foreign
	 * heap-shaped pointer parked in rec->post_state must fail the
	 * ownership-table gate before any inner-field deref.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_getsockopt() then gates the snap through
	 * post_state_claim_owned() before touching snap->vrb.
	 */
	vrb = valresult_alloc(page_size, valresult_pick_shape());
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETSOCKOPT_POST_STATE_MAGIC;
	snap->vrb = vrb;
	post_state_install(rec, snap);

	buf_len = min(vrb.cap, (size_t) page_size);
	rec->a4 = buf_len != 0 ?
		(unsigned long) get_writable_address(buf_len) : 0;
	optlen = (int *) get_writable_struct(sizeof(*optlen));
	if (optlen != NULL)
		*optlen = (int) *vrb.len_io;
	rec->a5 = (unsigned long) optlen;
}

static void post_getsockopt(struct syscallrecord *rec)
{
	struct getsockopt_post_state *snap;

	/*
	 * Clear the user pointers before any other work, so the record
	 * leaves the post handler naming none of this call's pool slots on
	 * every exit path, the claim_owned NULL early-return included.
	 */
	rec->a4 = 0;
	rec->a5 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETSOCKOPT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Free the inner valresult payload BEFORE post_state_release:
	 * release queues the outer snap chunk for deferred-free, after
	 * which snap->vrb is no longer safe to touch.
	 */
	valresult_free(&snap->vrb);
	post_state_release(rec, snap);
}

struct syscallentry syscall_getsockopt = {
	.name = "getsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.flags = NEED_ALARM | REEXEC_SANITISE_OK,
	.group = GROUP_NET,
	.sanitise = sanitise_getsockopt,
	.post = post_getsockopt,
	.rettype = RET_ZERO_SUCCESS,
};
