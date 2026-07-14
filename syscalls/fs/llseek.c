/*
 * SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
		unsigned long, offset_low, loff_t __user *, result,
		unsigned int, origin)
 */
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "sparse-files.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fs.h"
static unsigned long llseek_origins[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_llseek(struct syscallrecord *rec)
{
	unsigned int origin = (unsigned int) rec->a5;

	/* Belt-and-suspenders: keep the stderr capture memfd (and other
	 * protected fds) out of rec->a1 so a fuzz-induced llseek can't
	 * stash a huge offset for a follow-up write.  Sparse-pool branch
	 * below may overwrite rec->a1 with a tracked sparse-file fd;
	 * reroll first so the dense fall-through is covered. */
	reroll_protected_fd_arg(&rec->a1);

	rec->a2 = 0;	/* offset_high: keep offset < 4GB */

	/*
	 * Mirror the lseek wireup: SEEK_DATA / SEEK_HOLE need a sparse
	 * fd to reach the per-fs sparse-walk code, otherwise the
	 * kernel rejects on pos >= i_size before getting there.
	 */
	if (origin == SEEK_DATA || origin == SEEK_HOLE) {
		struct object *obj = get_rand_sparse_file_obj();

		if (obj != NULL) {
			off_t size = obj->sparsefileobj.size;

			rec->a1 = (unsigned long) obj->sparsefileobj.fd;
			if (ONE_IN(4))
				rec->a3 = rand64() & 0x7fffffff;
			else
				rec->a3 = (unsigned long) rnd_modulo_u64((uint64_t) size);
			/*
			 * Exercise the two-word→loff_t combine path that is
			 * the whole point of _llseek.  Only do this on the
			 * tracked sparse-file fd, and keep the high word
			 * small so ((a2 << 32) | a3) stays a positive loff_t.
			 */
			if (ONE_IN(5))
				rec->a2 = rand64() & 0xff;
			avoid_shared_buffer_out(&rec->a4, sizeof(loff_t));
			return;
		}
	}

	rec->a3 = rand64() & 0x7fffffff;	/* offset_low: non-negative */
	avoid_shared_buffer_out(&rec->a4, sizeof(loff_t));
}

static void post_llseek(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	/*
	 * The kernel reports the resulting offset (a non-negative loff_t)
	 * via *result and returns 0 on success. A negative-but-not-(-1)
	 * retval indicates a sign-extension or 32-on-64 compat tear.
	 */
	if (ret < 0)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_llseek = {
	.name = "llseek",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [3] = ARG_ADDRESS, [4] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset_high", [2] = "offset_low", [3] = "result", [4] = "origin" },
	.arg_params[4].list = ARGLIST(llseek_origins),
	.sanitise = sanitise_llseek,
	.post = post_llseek,
	.group = GROUP_VFS,
	.flags = REEXEC_SANITISE_OK,
};
