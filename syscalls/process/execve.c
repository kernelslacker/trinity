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
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "arch.h"	// page_size
#include "deferred-free.h"
#include "random.h"	// generate_rand_bytes
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "tables.h"
#include "trinity.h"	// __unused__
#include "utils.h"

#include "kernel/fcntl.h"
/*
 * Snapshot of the argv/envp arrays and their lengths, captured at sanitise
 * time and consumed by the post handler.  Lives in rec->post_state, a slot
 * the syscall ABI does not expose, so the post-time array walk operates on
 * values immune to a sibling syscall scribbling rec->a2/a3/a4 between the
 * syscall returning and the post handler running.
 */
#define EXECVE_POST_STATE_MAGIC	0x455845435F4D4147UL	/* "EXEC_MAG" */
struct execve_post_state {
	unsigned long magic;
	void **argv;
	void **envp;
	unsigned long argvcount;
	unsigned long envpcount;
};

static unsigned long ** gen_ptrs_to_crap(unsigned int count)
{
	void **ptr;
	unsigned int i;

	/* Fabricate argv -- this outer array and the per-entry page buffers
	 * are released via enqueue_execve_ptrs() in the post handler, which
	 * routes them through deferred_free_enqueue().  Opt in to the
	 * alloc-tracker so the matching consume-on-free pairs up. */
	ptr = zmalloc_tracked(count * sizeof(void *));

	for (i = 0; i < count; i++) {
		ptr[i] = zmalloc_tracked(page_size);
		generate_rand_bytes((unsigned char *) ptr[i], rnd_modulo_u32(page_size));
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
	 * Allocate a fresh buffer for the poison string rather than
	 * scribbling in place: ARG_PATHNAME's backing buffer is not
	 * guaranteed to be >= sizeof(poison), and a small (8-byte) chunk
	 * was already shown to clobber heap metadata via the same
	 * debunked invariant fixed in pathnames.c:get_testfile_path.
	 * cleanup_deferred_free reads the live arg slot after dispatch,
	 * so reassigning rec->aN releases the new buffer; the original
	 * ARG_PATHNAME allocation is left in alloc_track[] and freed
	 * when the ring evicts it.
	 *
	 * The execveat AT_EMPTY_PATH+NULL-path shape has no real buffer
	 * to overwrite (we substituted the static "" literal for fstatat
	 * above); strip AT_EMPTY_PATH instead so the kernel reads the
	 * NULL pointer and returns -EFAULT before touching the binary.
	 */
	if (is_execve || rec->a2 != 0) {
		char *buf = zmalloc_tracked(sizeof(poison));

		memcpy(buf, poison, sizeof(poison));
		if (is_execve)
			rec->a1 = (unsigned long) buf;
		else
			rec->a2 = (unsigned long) buf;
	} else {
		rec->a5 &= ~(unsigned long) AT_EMPTY_PATH;
	}

	__atomic_add_fetch(&shm->stats.diag.execve_self_exec_blocked, 1,
			   __ATOMIC_RELAXED);
}

static void sanitise_execve(struct syscallrecord *rec)
{
	struct execve_post_state *snap;
	unsigned long **argv, **envp;
	unsigned int argvcount, envpcount;

	redirect_stdio();

	/* Fabricate argv */
	argvcount = rnd_modulo_u32(32);
	argv = gen_ptrs_to_crap(argvcount);

	/* Fabricate envp */
	envpcount = rnd_modulo_u32(32);
	envp = gen_ptrs_to_crap(envpcount);

	if (current_entry_is_execve()) {
		rec->a2 = (unsigned long) argv;
		rec->a3 = (unsigned long) envp;
	} else {
		rec->a3 = (unsigned long) argv;
		rec->a4 = (unsigned long) envp;
	}

	block_self_exec(rec);

	/* magic-cookie / private post_state: see post_state_register(). */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = EXECVE_POST_STATE_MAGIC;
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
		deferred_free_enqueue(argv[i]);
	deferred_free_enqueue(argv);

	for (i = 0; i < envpcount; i++)
		deferred_free_enqueue(envp[i]);
	deferred_free_enqueue(envp);
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
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * execve_post_state.  A cookie mismatch means snap does not point
	 * at our struct -- bail without freeing, the pointer is suspect.
	 */
	if (snap->magic != EXECVE_POST_STATE_MAGIC) {
		outputerr("post_execve: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
		post_state_release(rec, snap);
		return;
	}
	/*
	 * sanitise_execve() bounds both counts by rnd_modulo_u32(32); anything
	 * over 32 means the snapshot was scribbled.  Walking the array
	 * with a bogus count reads far past the end of the allocation,
	 * so leak instead — the child process is dying anyway.
	 */
	if (local_snap.argvcount > 32 || local_snap.envpcount > 32) {
		outputerr("post_execve: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n",
			  local_snap.argvcount, local_snap.envpcount);
		post_state_release(rec, snap);
		return;
	}
	enqueue_execve_ptrs(local_snap.argv, local_snap.envp,
			    local_snap.argvcount, local_snap.envpcount);
	post_state_release(rec, snap);
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

	/* See post_execve() — magic-cookie gate against a sibling
	 * scribble redirecting rec->post_state to a foreign heap-shaped
	 * allocation that would otherwise pose as our struct.  Bail
	 * without freeing on mismatch; the pointer is suspect.
	 */
	if (snap->magic != EXECVE_POST_STATE_MAGIC) {
		outputerr("post_execveat: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
		post_state_release(rec, snap);
		return;
	}
	if (local_snap.argvcount > 32 || local_snap.envpcount > 32) {
		outputerr("post_execveat: rejected suspicious argvcount=%lu envpcount=%lu "
			  "(post_state-scribbled?)\n",
			  local_snap.argvcount, local_snap.envpcount);
		post_state_release(rec, snap);
		return;
	}
	enqueue_execve_ptrs(local_snap.argv, local_snap.envp,
			    local_snap.argvcount, local_snap.envpcount);
	post_state_release(rec, snap);
}

struct syscallentry syscall_execve = {
	.name = "execve",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "name", [1] = "argv", [2] = "envp" },
	.sanitise = sanitise_execve,
	.post = post_execve,
	.group = GROUP_VFS,
	.flags = AVOID_SYSCALL | EXTRA_FORK,
};

#ifndef AT_EXECVE_CHECK
#define AT_EXECVE_CHECK 0x10000
#endif

static unsigned long execveat_flags[] = {
	AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, AT_EXECVE_CHECK,
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
	.flags = AVOID_SYSCALL | EXTRA_FORK,
};
