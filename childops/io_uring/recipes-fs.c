/*
 * iouring-recipes-fs -- filesystem / openat / xattr / splice / tee /
 * pipe / memfd recipe family for the iouring-recipes catalogue.
 *
 * See childops/io_uring/recipes.c for the dispatcher and the shared
 * pool-race fault handler; see iouring-recipes-internal.h for the
 * cross-TU symbol boundary.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"
#include "errno-classify.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "syscall-gate.h"
#include "trinity.h"

#include "childops/io_uring/recipes-internal.h"

/* ------------------------------------------------------------------ *
 * Recipe 5: OPENAT + CLOSE in linked SQEs (teardown race)
 *
 * Open /dev/null via IORING_OP_OPENAT then immediately chain a CLOSE.
 * The CLOSE uses fd=0 as a placeholder — it will produce EBADF or get
 * cancelled by the link chain.  The interesting path is the linked-
 * cancel sequence when the second request references a result not yet
 * available from the first.
 * ------------------------------------------------------------------ */
bool recipe_openat_close_linked(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	int r;
	static const char devnull[] = "/dev/null";

	sqe_clear(&sqes[0]);
	sqes[0].opcode     = IORING_OP_OPENAT;
	sqes[0].fd         = AT_FDCWD;
	sqes[0].addr       = (__u64)(uintptr_t)devnull;
	sqes[0].open_flags = O_RDONLY;
	sqes[0].flags      = IOSQE_IO_LINK;
	sqes[0].user_data  = 40;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_CLOSE;
	sqes[1].fd        = 0;
	sqes[1].user_data = 41;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * memfd helper used by the regular-file family below.
 * ------------------------------------------------------------------ */
static int iour_make_memfd(void)
{
	int fd = (int)trinity_raw_syscall(SYS_memfd_create, "trinity-iour", MFD_CLOEXEC);

	if (fd < 0)
		return -1;
	if (ftruncate(fd, 4096) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* ------------------------------------------------------------------ *
 * Recipe: FSYNC on a memfd
 * ------------------------------------------------------------------ */
bool recipe_fsync(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FSYNC;
	sqe.fd          = s->memfd;
	sqe.fsync_flags = 0;
	sqe.user_data   = 260;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SYNC_FILE_RANGE on a memfd
 * ------------------------------------------------------------------ */
bool recipe_sync_file_range(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode           = IORING_OP_SYNC_FILE_RANGE;
	sqe.fd               = s->memfd;
	sqe.off              = 0;
	sqe.len              = 4096;
	sqe.sync_range_flags = 0;
	sqe.user_data        = 270;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: READV from /dev/zero into a stack iovec
 * ------------------------------------------------------------------ */
bool recipe_readv(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iovec iov[2];
	char buf1[64], buf2[64];
	int r;

	s->open_fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		return false;

	iov[0].iov_base = buf1;
	iov[0].iov_len  = sizeof(buf1);
	iov[1].iov_base = buf2;
	iov[1].iov_len  = sizeof(buf2);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READV;
	sqe.fd        = s->open_fd;
	sqe.addr      = (__u64)(uintptr_t)iov;
	sqe.len       = 2;
	sqe.off       = 0;
	sqe.user_data = 280;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: WRITEV to a memfd via two iovecs
 * ------------------------------------------------------------------ */
bool recipe_writev(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iovec iov[2];
	char buf1[32], buf2[32];
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	memset(buf1, 'a', sizeof(buf1));
	memset(buf2, 'b', sizeof(buf2));
	iov[0].iov_base = buf1;
	iov[0].iov_len  = sizeof(buf1);
	iov[1].iov_base = buf2;
	iov[1].iov_len  = sizeof(buf2);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_WRITEV;
	sqe.fd        = s->memfd;
	sqe.addr      = (__u64)(uintptr_t)iov;
	sqe.len       = 2;
	sqe.off       = 0;
	sqe.user_data = 290;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FALLOCATE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=offset, sqe->addr=length, sqe->len=mode.
 * ------------------------------------------------------------------ */
bool recipe_fallocate(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_FALLOCATE;
	sqe.fd        = s->memfd;
	sqe.off       = 0;
	sqe.addr      = 8192;
	sqe.len       = 0;
	sqe.user_data = 300;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FTRUNCATE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=length.
 * ------------------------------------------------------------------ */
bool recipe_ftruncate(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_FTRUNCATE;
	sqe.fd        = s->memfd;
	sqe.off       = 2048;
	sqe.user_data = 310;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FADVISE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=offset, sqe->addr=len, sqe->fadvise_advice.
 * ------------------------------------------------------------------ */
bool recipe_fadvise(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode         = IORING_OP_FADVISE;
	sqe.fd             = s->memfd;
	sqe.off            = 0;
	sqe.addr           = 4096;
	sqe.fadvise_advice = POSIX_FADV_WILLNEED;
	sqe.user_data      = 320;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: READ_MULTISHOT on a pipe with provided buffers + cancel
 *
 * READ_MULTISHOT requires IOSQE_BUFFER_SELECT and a buf_group containing
 * at least one buffer — provide one, arm the multishot, then cancel it
 * synchronously to drain the in-flight request before teardown.
 * ------------------------------------------------------------------ */
bool recipe_read_multishot(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;
#define READMS_GROUP	7
#define READMS_COUNT	2
#define READMS_SIZE	256

	s->malloc_buf = malloc((size_t)READMS_COUNT * READMS_SIZE);
	if (!s->malloc_buf)
		return false;
	memset(s->malloc_buf, 0, (size_t)READMS_COUNT * READMS_SIZE);

	if (pipe(s->pipefd) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)s->malloc_buf;
	sqe.len       = READMS_SIZE;
	sqe.fd        = READMS_COUNT;
	sqe.off       = 0;
	sqe.buf_group = READMS_GROUP;
	sqe.user_data = 330;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 1) < 0)
		return false;
	iour_drain_cqes(ctx);
	s->provided_buf_active   = true;
	s->provided_buf_group_id = READMS_GROUP;
	s->provided_buf_count    = READMS_COUNT;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READ_MULTISHOT;
	sqe.fd        = s->pipefd[0];
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = READMS_GROUP;
	sqe.user_data = 331;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 0);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_ASYNC_CANCEL;
	sqe.addr      = 331;
	sqe.user_data = 332;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 1) < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;

#undef READMS_GROUP
#undef READMS_COUNT
#undef READMS_SIZE
}

/* ------------------------------------------------------------------ *
 * Recipe: OPENAT2 with a struct open_how (likely ENOENT)
 * ------------------------------------------------------------------ */
bool recipe_openat2(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iour_open_how how;
	static const char path[] = "/dev/null";
	int r;

	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_OPENAT2;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)path;
	sqe.addr2     = (__u64)(uintptr_t)&how;
	sqe.len       = sizeof(how);
	sqe.user_data = 340;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: OPENAT2 with flag combinations that fast-fail through
 * __io_openat_prep / build_open_flags / path_openat.
 *
 * recipe_openat2 above covers the success path with a plain
 * O_RDONLY|O_CLOEXEC open.  This sibling drives the *error* paths
 * that historically leaked the getname()'d struct filename or the
 * nameidata's path components.  Each invocation picks one combo at
 * random so a long fuzz run sees them all without bloating the
 * catalog.
 *
 *  0. O_TMPFILE|O_RDWR on AT_FDCWD with a regular-file path
 *     (-ENOTDIR through path_openat's terminate_walk).
 *  1. O_TMPFILE|O_RDONLY (rejected at build_open_flags — O_TMPFILE
 *     requires write access).
 *  2. O_PATH|O_TMPFILE (mutually exclusive, rejected at
 *     build_open_flags after the filename has been getname()'d).
 *  3. sqe->file_index != 0 with O_CLOEXEC (-EINVAL after the
 *     prep grabbed the filename; cleanup path must release it).
 *  4. RESOLVE_BENEATH|RESOLVE_IN_ROOT (mutually exclusive
 *     resolve bits, -EINVAL from build_open_flags).
 *  5. RESOLVE_CACHED against a fresh /tmp path (forces the
 *     rcu-walk fast path; misses → -EAGAIN, exercising the
 *     io_uring REQ_F_FORCE_ASYNC retry handoff).
 *  6. open_how.mode set without O_CREAT/O_TMPFILE (-EINVAL from
 *     build_open_how).
 *  7. how.resolve with an undefined high bit (-EINVAL from
 *     build_open_flags' RESOLVE_* mask check).
 * ------------------------------------------------------------------ */
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV		0x01
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#define RESOLVE_NO_MAGICLINKS	0x02
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS	0x04
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH		0x08
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT		0x10
#endif
#ifndef RESOLVE_CACHED
#define RESOLVE_CACHED		0x20
#endif

bool recipe_openat2_leak_combos(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iour_open_how how;
	static const char tmp_dir[]   = "/tmp";
	static const char dev_null[]  = "/dev/null";
	static const char etc_passwd[] = "/etc/passwd";
	const char *path;
	int r;

	memset(&how, 0, sizeof(how));
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_OPENAT2;
	sqe.fd        = AT_FDCWD;
	sqe.len       = sizeof(how);
	sqe.user_data = 0x4a4b;
	path          = dev_null;

	switch (rnd_modulo_u32(8)) {
	case 0:
		how.flags = O_TMPFILE | O_RDWR | O_CLOEXEC;
		path = tmp_dir;
		break;
	case 1:
		how.flags = O_TMPFILE | O_RDONLY;
		path = tmp_dir;
		break;
	case 2:
		how.flags = O_PATH | O_TMPFILE;
		path = tmp_dir;
		break;
	case 3:
		how.flags = O_RDONLY | O_CLOEXEC;
		sqe.file_index = 1;
		break;
	case 4:
		how.flags   = O_RDONLY;
		how.resolve = RESOLVE_BENEATH | RESOLVE_IN_ROOT;
		break;
	case 5:
		how.flags   = O_RDONLY | O_NONBLOCK;
		how.resolve = RESOLVE_CACHED | RESOLVE_NO_SYMLINKS;
		path = etc_passwd;
		break;
	case 6:
		how.flags = O_RDONLY;
		how.mode  = 0644;
		break;
	case 7:
	default:
		how.flags   = O_RDONLY;
		how.resolve = 0x80;
		break;
	}

	sqe.addr      = (__u64)(uintptr_t)path;
	sqe.addr2     = (__u64)(uintptr_t)&how;
	sqe.open_flags = 0;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SPLICE between two pipes (with primer write)
 * ------------------------------------------------------------------ */
bool recipe_splice(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	if (pipe(s->pipefd) < 0)
		return false;
	if (pipe(s->pipefd2) < 0)
		return false;

	{
		const char primer[64] = { 's', 'p', 'l', 'i', 'c', 'e' };
		ssize_t w __unused__ = write(s->pipefd[1], primer,
					     sizeof(primer));
	}

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_SPLICE;
	sqe.fd            = s->pipefd2[1];	/* out */
	sqe.splice_fd_in  = s->pipefd[0];	/* in */
	sqe.splice_off_in = (__u64)-1;
	sqe.off           = (__u64)-1;
	sqe.len           = 64;
	sqe.splice_flags  = 0;
	sqe.user_data     = 360;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: TEE between two pipes
 * ------------------------------------------------------------------ */
bool recipe_tee(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	if (pipe(s->pipefd) < 0)
		return false;
	if (pipe(s->pipefd2) < 0)
		return false;

	{
		const char primer[64] = { 't', 'e', 'e' };
		ssize_t w __unused__ = write(s->pipefd[1], primer,
					     sizeof(primer));
	}

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_TEE;
	sqe.fd           = s->pipefd2[1];	/* out */
	sqe.splice_fd_in = s->pipefd[0];	/* in */
	sqe.len          = 64;
	sqe.splice_flags = 0;
	sqe.user_data    = 370;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: RENAMEAT on missing source (ENOENT but full prep+issue)
 *
 * SQE layout: sqe->fd=old_dfd, sqe->addr=oldpath, sqe->len=new_dfd
 * (an int packed as u32), sqe->addr2=newpath, sqe->rename_flags.
 * ------------------------------------------------------------------ */
bool recipe_renameat(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char oldp[] = "/tmp/trinity-iour-rn-src";
	static const char newp[] = "/tmp/trinity-iour-rn-dst";
	int r;

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_RENAMEAT;
	sqe.fd           = AT_FDCWD;
	sqe.addr         = (__u64)(uintptr_t)oldp;
	sqe.len          = (__u32)AT_FDCWD;
	sqe.addr2        = (__u64)(uintptr_t)newp;
	sqe.rename_flags = 0;
	sqe.user_data    = 410;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: UNLINKAT on a path that doesn't exist
 * ------------------------------------------------------------------ */
bool recipe_unlinkat(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/tmp/trinity-iour-unlink-target";
	int r;

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_UNLINKAT;
	sqe.fd           = AT_FDCWD;
	sqe.addr         = (__u64)(uintptr_t)path;
	sqe.unlink_flags = 0;
	sqe.user_data    = 420;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: MKDIRAT — likely EEXIST or EACCES; prep + issue path runs
 * ------------------------------------------------------------------ */
bool recipe_mkdirat(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/tmp/trinity-iour-mkdir-target";
	int r;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_MKDIRAT;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)path;
	sqe.len       = 0700;
	sqe.user_data = 430;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SYMLINKAT — likely EEXIST/EACCES; prep + issue path runs
 *
 * SQE layout: sqe->fd=newdirfd, sqe->addr=target (symlink contents),
 *             sqe->addr2=linkpath.
 * ------------------------------------------------------------------ */
bool recipe_symlinkat(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char target[] = "/dev/null";
	static const char linkp[]  = "/tmp/trinity-iour-symlink";
	int r;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_SYMLINKAT;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)target;
	sqe.addr2     = (__u64)(uintptr_t)linkp;
	sqe.user_data = 440;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: LINKAT — same SQE shape as RENAMEAT plus hardlink_flags
 * ------------------------------------------------------------------ */
bool recipe_linkat(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char oldp[] = "/dev/null";
	static const char newp[] = "/tmp/trinity-iour-hardlink";
	int r;

	sqe_clear(&sqe);
	sqe.opcode         = IORING_OP_LINKAT;
	sqe.fd             = AT_FDCWD;
	sqe.addr           = (__u64)(uintptr_t)oldp;
	sqe.len            = (__u32)AT_FDCWD;
	sqe.addr2          = (__u64)(uintptr_t)newp;
	sqe.hardlink_flags = 0;
	sqe.user_data      = 450;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Xattr SQE layout: sqe->addr=name ptr, sqe->addr3=value ptr,
 *                   sqe->len=size, sqe->xattr_flags=flags;
 *                   path-based variants additionally use sqe->addr2=path.
 * ------------------------------------------------------------------ */
bool recipe_setxattr(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[]  = "/tmp/trinity-iour-xattr-tgt";
	static const char name[]  = "user.trinity";
	static const char value[] = "v";
	int r;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_SETXATTR;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr2       = (__u64)(uintptr_t)path;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 460;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

bool recipe_fsetxattr(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char name[]  = "user.trinity";
	static const char value[] = "v";
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FSETXATTR;
	sqe.fd          = s->memfd;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 470;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

bool recipe_getxattr(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/dev/null";
	static const char name[] = "user.trinity";
	char value[64];
	int r;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_GETXATTR;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr2       = (__u64)(uintptr_t)path;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 480;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

bool recipe_fgetxattr(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char name[] = "user.trinity";
	char value[64];
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FGETXATTR;
	sqe.fd          = s->memfd;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 490;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}
