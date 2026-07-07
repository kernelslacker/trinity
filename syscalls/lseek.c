/*
 * SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
 */
#include <sys/types.h>
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "sparse-files.h"
#include "utils.h"

#include "kernel/fs.h"
static unsigned long lseek_whences[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_lseek(struct syscallrecord *rec)
{
	unsigned int whence = (unsigned int) rec->a3;

	/* Belt-and-suspenders: keep the stderr capture memfd (and other
	 * protected fds) out of rec->a1 so a fuzz-induced lseek can't
	 * stash a huge offset for a follow-up write that extends the memfd
	 * to multi-GB and turns the next SIGABRT-handler bug-log drain
	 * into a host-swamping write.  Sparse-pool branch below may
	 * overwrite rec->a1 with a tracked sparse-file fd; reroll first
	 * so the dense fall-through is covered. */
	reroll_protected_fd_arg(&rec->a1);

	/*
	 * SEEK_DATA / SEEK_HOLE return -ENXIO when the offset is past
	 * EOF and reach the per-fs sparse-walk code only when the
	 * underlying inode actually has holes.  generic_sanitise has
	 * already filled rec->a1 from the generic fd pool, which is
	 * dominated by dense / non-regular fds; redirect to the sparse
	 * file pool when the picked whence is one of the sparse-walk
	 * forms so the call has a real chance of reaching the
	 * iomap_seek_data / iomap_seek_hole and ext4 / btrfs / xfs /
	 * f2fs custom implementations.
	 */
	if (whence == SEEK_DATA || whence == SEEK_HOLE) {
		struct object *obj = get_rand_sparse_file_obj();

		if (obj != NULL) {
			off_t size = obj->sparsefileobj.size;

			rec->a1 = (unsigned long) obj->sparsefileobj.fd;
			/*
			 * Bias most picks into [0, size) so the kernel
			 * reaches the sparse-walk code, but keep an
			 * occasional out-of-range poke to exercise the
			 * -ENXIO / -EINVAL boundary paths.
			 */
			if (ONE_IN(4))
				rec->a2 = rand64() & 0x7fffffff;
			else
				rec->a2 = (unsigned long) rnd_modulo_u64((uint64_t) size);
			return;
		}
		/* Empty sparse pool — fall through to dense fuzz. */
	}

	/* Negative offsets produce EINVAL on most filesystems. */
	rec->a2 = rand64() & 0x7fffffff;
}

static void post_lseek(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	/*
	 * lseek returns a non-negative loff_t on success. A negative value
	 * that isn't -1 indicates a sign-extension or 32-on-64 compat tear
	 * in the return path.
	 */
	if (ret < 0)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_lseek = {
	.name = "lseek",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [2] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset", [2] = "whence" },
	.arg_params[2].list = ARGLIST(lseek_whences),
	.sanitise = sanitise_lseek,
	.post = post_lseek,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
