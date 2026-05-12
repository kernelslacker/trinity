/*
 * SYSCALL_DEFINE3(execve,
 *                const char __user *, filename,
 *                const char __user *const __user *, argv,
 *                const char __user *const __user *, envp)
 *
 * On success, execve() does not return
 * on error -1 is returned, and errno is set appropriately.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "arch.h"	// page_size
#include "deferred-free.h"
#include "random.h"	// generate_rand_bytes
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"	// __unused__
#include "utils.h"
#include "compat.h"

/*
 * Snapshot of the argv/envp arrays and their lengths, captured at sanitise
 * time and consumed by the post handler.  Lives in rec->post_state, a slot
 * the syscall ABI does not expose, so the post-time array walk operates on
 * values immune to a sibling syscall scribbling rec->a2/a3/a4 between the
 * syscall returning and the post handler running.
 */
struct execve_post_state {
	void **argv;
	void **envp;
	unsigned long argvcount;
	unsigned long envpcount;
};

static unsigned long ** gen_ptrs_to_crap(unsigned int count)
{
	void **ptr;
	unsigned int i;

	/* Fabricate argv */
	ptr = zmalloc(count * sizeof(void *));

	for (i = 0; i < count; i++) {
		ptr[i] = zmalloc(page_size);
		generate_rand_bytes((unsigned char *) ptr[i], rand() % page_size);
	}

	return (unsigned long **) ptr;
}

/*
 * Redirect stdin/stdout/stderr before execve so the new process
 * can't block on reads or corrupt the fuzzer's output.
 *
 * stdin  <- /dev/null (prevents blocking reads)
 * stdout -> /dev/null (prevents output corruption)
 * stderr -> /dev/null (prevents output corruption)
 *
 * If the redirects fail we press on anyway — execve will almost
 * certainly fail with our random argv, and the child exits either way.
 */
static void redirect_stdio(void)
{
	int devnull;

	devnull = open("/dev/null", O_RDWR);
	if (devnull == -1)
		return;

	(void) dup2(devnull, STDIN_FILENO);
	(void) dup2(devnull, STDOUT_FILENO);
	(void) dup2(devnull, STDERR_FILENO);

	if (devnull > STDERR_FILENO)
		close(devnull);
}

/*
 * Refuse to let the syscall fire when the resolved target is the trinity
 * binary itself.  See the trinity_self_exe comment in include/shm.h for
 * the failure mode this defends against -- a fuzzed pathname (or an
 * inherited fd consumed by execveat AT_EMPTY_PATH) that resolves back to
 * our own binary spawns a nested trinity that inherits the parent's
 * cmdline, cgroup, and namespace state and starts its own child fleet.
 *
 * fstatat() handles every shape we care about:
 *   - execve absolute path:                    fstatat(AT_FDCWD, p, , 0)
 *   - execve relative path:                    fstatat(AT_FDCWD, p, , 0)
 *     (resolved against the child's cwd, which is where ./trinity lives
 *      in the typical operator launch)
 *   - execveat (dirfd, p, , flags):            fstatat(dirfd, p, , flags
 *      & (AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW))
 *   - execveat (fd, "", , AT_EMPTY_PATH):      fstatat above degenerates
 *     to the AT_EMPTY_PATH fd-only case and returns the fd's identity
 *
 * On match, overwrite the path buffer in place with a known-bad string
 * so the kernel returns a clean -ENOENT/-ENOTDIR -- the post handler's
 * argv/envp free walk is unaffected because the heap pointer itself
 * still points at the same allocation.  AT_SYMLINK_NOFOLLOW intentionally
 * propagates: a /proc/<pid>/exe symlink stat'd with NOFOLLOW returns the
 * symlink itself rather than the binary, so a fuzz call that sets
 * NOFOLLOW slips past -- accepted, that combination is harmless because
 * the same flag also blocks the kernel's lookup from following into the
 * binary on the syscall side.
 *
 * Stat failures (EACCES, EFAULT from a scribbled pointer, ENOENT on a
 * fuzzed bogus path) skip the guard and let the syscall fail naturally,
 * preserving the existing failure-path coverage.
 */
static void block_self_exec(struct syscallrecord *rec)
{
	static const char poison[] = "/dev/null/no-such-thing";
	bool is_execve;
	char *pathptr;
	int dirfd;
	int flags;
	struct stat st;

	if (!shm->trinity_self_exe.valid)
		return;

	is_execve = current_entry_is_execve();
	if (is_execve) {
		dirfd = AT_FDCWD;
		pathptr = (char *) rec->a1;
		flags = 0;
	} else {
		dirfd = (int) rec->a1;
		pathptr = (char *) rec->a2;
		flags = (int)(rec->a5 & (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW));
	}

	if (pathptr == NULL) {
		if ((flags & AT_EMPTY_PATH) == 0)
			return;
		pathptr = (char *) "";
	}

	if (fstatat(dirfd, pathptr, &st, flags) != 0)
		return;

	if (st.st_dev != shm->trinity_self_exe.dev ||
	    st.st_ino != shm->trinity_self_exe.ino)
		return;

	/*
	 * The pathname buffer is a fresh MAX_PATH_LEN zmalloc allocation
	 * from generate_pathname() -- writing 24 bytes into it is safe
	 * and the post handler's deferred_free still gets a valid heap
	 * pointer.  The execveat AT_EMPTY_PATH+NULL-path shape has no
	 * real buffer to overwrite (we substituted the static "" literal
	 * for fstatat above); strip AT_EMPTY_PATH instead so the kernel
	 * reads the NULL pointer and returns -EFAULT before touching the
	 * binary.
	 */
	if (is_execve)
		memcpy((char *) rec->a1, poison, sizeof(poison));
	else if (rec->a2 != 0)
		memcpy((char *) rec->a2, poison, sizeof(poison));
	else
		rec->a5 &= ~(unsigned long) AT_EMPTY_PATH;

	__atomic_add_fetch(&shm->stats.execve_self_exec_blocked, 1,
			   __ATOMIC_RELAXED);
}

static void sanitise_execve(struct syscallrecord *rec)
{
	struct execve_post_state *snap;
	unsigned long **argv, **envp;
	unsigned int argvcount, envpcount;

	redirect_stdio();

	/* Fabricate argv */
	argvcount = rand() % 32;
	argv = gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rand() % 32;
	envp = gen_ptrs_to_crap(envpcount);

	if (current_entry_is_execve()) {
		rec->a2 = (unsigned long) argv;
		rec->a3 = (unsigned long) envp;
	} else {
		rec->a3 = (unsigned long) argv;
		rec->a4 = (unsigned long) envp;
	}

	block_self_exec(rec);

	/*
	 * Snapshot the array pointers and counts for the post handler.  The
	 * snapshot lives in rec->post_state, which the syscall ABI does not
	 * expose, so a sibling syscall scribbling rec->a2/a3/a4 between the
	 * syscall returning and the post handler running cannot misdirect
	 * the array walk into an unrelated heap allocation.
	 *
	 * Register the snap pointer in the post_state ownership table so
	 * the post handler can verify the value it reads back out of
	 * rec->post_state really came from this allocation -- a sibling
	 * scribble that redirects rec->post_state to a foreign chunk is
	 * caught by the post_state_is_owned() lookup before we copy bytes
	 * out of an allocation that may be smaller than struct
	 * execve_post_state.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->argv = (void **) argv;
	snap->envp = (void **) envp;
	snap->argvcount = argvcount;
	snap->envpcount = envpcount;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/* if execve succeeds, we'll never get back here, so this only
 * has to worry about the case where execve returned a failure.
 *
 * Route the snapshot's argv/envp arrays (and their inner element
 * pointers) through deferred_free_enqueue() so the lifetime overlaps
 * the same TTL window every other syscall's allocations live in.  The
 * earlier free()-direct path bypassed deferred-free's bookkeeping --
 * the alloc_track entry for each pointer survived the direct free(),
 * leaving a stale tracked allocation that a later eviction in the
 * deferred-free ring could free a second time.  Letting the queue own
 * the release closes that double-free window and keeps the alloc_track
 * side-set consistent with reality.
 *
 * deferred_free_enqueue() carries its own NULL / shape / heap-bounds
 * guards, so the inner-pointer corruption checks the old direct-free
 * helper performed via inner_ptr_ok_to_free() are subsumed; a scribbled
 * inner slot is rejected at the queue boundary and counted by the same
 * telemetry path every other syscall's enqueues use.
 */
static void enqueue_execve_ptrs(void **argv, void **envp,
				unsigned int argvcount, unsigned int envpcount)
{
	unsigned int i;

	for (i = 0; i < argvcount; i++)
		deferred_free_enqueue(argv[i], NULL);
	deferred_free_enqueue(argv, NULL);

	for (i = 0; i < envpcount; i++)
		deferred_free_enqueue(envp[i], NULL);
	deferred_free_enqueue(envp, NULL);
}

static void post_execve(struct syscallrecord *rec)
{
	struct execve_post_state *snap = (struct execve_post_state *) rec->post_state;
	struct execve_post_state local_snap;

	rec->a2 = 0;
	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_execve: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Shape passed, but a sibling-stomp can still redirect post_state
	 * to a different heap allocation that happens to be canonical and
	 * aligned -- typically a smaller struct from another syscall's own
	 * post_state slot.  Copying *snap into local_snap then reads
	 * sizeof(struct execve_post_state) bytes past the end of the foreign
	 * allocation (heap-buffer-overflow).
	 *
	 * The earlier guard probed glibc's chunk-header allocation size via
	 * malloc_usable_size().  That works under glibc but is undefined
	 * behaviour on any pointer the runtime did not hand out; libsanitizer
	 * treats the call as a hard runtime error and aborts the child --
	 * the guard meant to catch sibling-stomp becomes the new crash site
	 * under -fsanitize=address.
	 *
	 * Replace the chunk probe with an explicit ownership check.
	 * sanitise_execve() registers each snap in the post_state ownership
	 * table at allocation time; a value that fails the lookup cannot be
	 * one we produced, so we bail without freeing.  The lookup is pure
	 * pointer comparison and well-defined under both glibc and ASAN.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_execve: rejected post_state=%p not in ownership table "
			  "(post_state-redirected?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Copy the snapshot struct contents into a local so the field
	 * validations below run against the same bytes the array walk
	 * will consume.  A sibling syscall scribbling snap->argv /
	 * snap->envp / snap->{argv,envp}count between the looks_like_corrupted_ptr
	 * check and the subsequent field reads would otherwise let
	 * post-validated garbage reach enqueue_execve_ptrs() and SIGSEGV
	 * the post handler on the first inner deref.
	 */
	local_snap = *snap;

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner array pointers may no longer reference our heap
	 * allocations.  enqueue_execve_ptrs() walks argv[]/envp[] before
	 * handing the outer arrays to deferred-free, and a bad pointer
	 * crashes on the first deref.  Leak rather than walk garbage.
	 */
	if (looks_like_corrupted_ptr(rec, local_snap.argv) ||
	    looks_like_corrupted_ptr(rec, local_snap.envp)) {
		outputerr("post_execve: rejected suspicious argv=%p envp=%p "
			  "(post_state-scribbled?)\n", local_snap.argv, local_snap.envp);
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}
	/*
	 * sanitise_execve() bounds both counts by rand() % 32; anything
	 * over 32 means the snapshot was scribbled.  Walking the array
	 * with a bogus count reads far past the end of the allocation,
	 * so leak instead — the child process is dying anyway.
	 */
	if (local_snap.argvcount > 32 || local_snap.envpcount > 32) {
		outputerr("post_execve: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n",
			  local_snap.argvcount, local_snap.envpcount);
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}
	enqueue_execve_ptrs(local_snap.argv, local_snap.envp,
			    local_snap.argvcount, local_snap.envpcount);
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

static void post_execveat(struct syscallrecord *rec)
{
	struct execve_post_state *snap = (struct execve_post_state *) rec->post_state;
	struct execve_post_state local_snap;

	rec->a3 = 0;
	rec->a4 = 0;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_execveat: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/* See post_execve() — ownership-table guard against post_state
	 * redirected to a foreign allocation by sibling stomp.  Replaces
	 * the prior malloc_usable_size() probe, which was UB on a
	 * non-malloc-owned pointer and aborted the child under ASAN.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_execveat: rejected post_state=%p not in ownership table "
			  "(post_state-redirected?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * See post_execve() above — copy the snapshot struct out before
	 * validating individual fields so a sibling scribble between the
	 * snap pointer check and the field reads can't slip past the
	 * looks_like_corrupted_ptr / count guards.
	 */
	local_snap = *snap;

	if (looks_like_corrupted_ptr(rec, local_snap.argv) ||
	    looks_like_corrupted_ptr(rec, local_snap.envp)) {
		outputerr("post_execveat: rejected suspicious argv=%p envp=%p "
			  "(post_state-scribbled?)\n", local_snap.argv, local_snap.envp);
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}
	if (local_snap.argvcount > 32 || local_snap.envpcount > 32) {
		outputerr("post_execveat: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n",
			  local_snap.argvcount, local_snap.envpcount);
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}
	enqueue_execve_ptrs(local_snap.argv, local_snap.envp,
			    local_snap.argvcount, local_snap.envpcount);
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_execve = {
	.name = "execve",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "name", [1] = "argv", [2] = "envp" },
	.sanitise = sanitise_execve,
	.post = post_execve,
	.group = GROUP_VFS,
	.flags = EXTRA_FORK,
};

static unsigned long execveat_flags[] = {
	AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
};

struct syscallentry syscall_execveat = {
	.name = "execveat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "argv", [3] = "envp", [4] = "flags" },
	.arg_params[4].list = ARGLIST(execveat_flags),
	.sanitise = sanitise_execve,
	.post = post_execveat,
	.group = GROUP_VFS,
	.flags = EXTRA_FORK,
};
