/*
 * SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg)
 */
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/sem.h"
static unsigned long semctl_cmds[] = {
	IPC_RMID, IPC_SET, IPC_STAT, IPC_INFO,
	GETPID, GETVAL, GETALL, GETNCNT, GETZCNT,
	SETVAL, SETALL,
	SEM_STAT, SEM_INFO, SEM_STAT_ANY,
};

/*
 * Fallback nsems cap used for semnum picks when the producer-side pool
 * entry doesn't carry the set's real nsems.  Today the OBJ_SYSV_SEM
 * pool stashes only the semid (see syscalls/semget.c sysvsemobj), so
 * every lookup goes through the fallback.  Matches the bound the
 * pre-existing semnum ARG_RANGE was using (0..250), tightened down so
 * 70%+ of picks land inside the set's valid index range.
 */
#define SEMCTL_FALLBACK_NSEMS	32

/*
 * Upper bound on the unsigned-short array we hand the kernel for
 * SETALL / GETALL.  Has to cover the worst-case nsems we let semget()
 * create (its ARG_RANGE hi is 250); 256 entries == 512 bytes leaves
 * headroom over that without inflating the per-call alloc.  Avoids
 * the OOB-read footgun where the kernel walks N entries from the
 * caller buffer using the set's real nsems, not whatever bound the
 * fuzzer-side allocator thought it was using.
 */
#define SEMCTL_ARRAY_SLOTS	256

/*
 * union semun is glibc-private and not declared in any header; callers
 * must provide their own per the semctl(2) man page.  Mirrors the
 * shape childops/recipe/runner.c uses.
 */
union trinity_semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
	struct seminfo *__buf;
};

/*
 * Look up the chosen semid's nsems in the producer-side pool so the
 * semnum pick lands inside the set's valid index range.  The pool
 * entry doesn't carry nsems today (sysvsemobj stashes only semid), so
 * every caller falls back to SEMCTL_FALLBACK_NSEMS.  Wiring is kept
 * separate from the call site so a future pool-entry nsems extension
 * is a one-spot change.
 */
static int lookup_sysv_sem_nsems(int semid __unused__)
{
	return SEMCTL_FALLBACK_NSEMS;
}

/*
 * Split semnum across:
 *   70% in-range  [0, nsems-1]   (success path)
 *   30% out-of-range nsems..nsems+63 (EFBIG path)
 * Negative semnum is uninteresting (always -EINVAL very early in the
 * kernel handler), so the out-of-range bucket stays non-negative.
 */
static int pick_semnum(int semid)
{
	int nsems = lookup_sysv_sem_nsems(semid);

	if (rnd_modulo_u32(100) < 70)
		return (int) rnd_modulo_u32((uint32_t) nsems);
	return nsems + (int) rnd_modulo_u32(64);
}

/*
 * Build the union semun shape per cmd.  SETVAL puts a value in
 * [0, SEMVMX] in rec->a4 directly.  SETALL fills a fresh
 * unsigned-short array with values in that same range, IPC_SET
 * populates sem_perm.uid/.gid/.mode in a fresh semid_ds, and the
 * pure-output cmds (GETALL, IPC_STAT, SEM_STAT, SEM_STAT_ANY,
 * IPC_INFO, SEM_INFO) hand the kernel a zeroed destination buffer.
 *
 * On x86-64 the union semun is passed by value in a single register,
 * so storing the per-cmd value through rec->a4 is sufficient -- no
 * separate type slot to track.  The pointer-typed buffers are
 * zmalloc_tracked so the per-call lifetime matches the syscall's.
 * For the kernel-READ cmds (SETALL, IPC_SET) we then run
 * avoid_shared_buffer_inout() so the relocation away from any
 * shared-mem overlap preserves the curated payload; for the
 * kernel-WRITTEN cmds and the ignored-arg default we use
 * avoid_shared_buffer_out(), which relocates without copying (the
 * kernel is about to overwrite the buffer anyway).
 */
static void build_semun_arg(struct syscallrecord *rec)
{
	int cmd = (int) rec->a3;
	union trinity_semun u;
	struct semid_ds *ds;
	unsigned short *array;
	struct seminfo *info;
	unsigned int i;

	switch (cmd) {
	case SETVAL:
		u.val = (int) rnd_modulo_u32(SEMVMX + 1);
		rec->a4 = (unsigned long) u.val;
		return;

	case SETALL:
		array = zmalloc_tracked(SEMCTL_ARRAY_SLOTS * sizeof(*array));
		for (i = 0; i < SEMCTL_ARRAY_SLOTS; i++)
			array[i] = (unsigned short) rnd_modulo_u32(SEMVMX + 1);
		u.array = array;
		rec->a4 = (unsigned long) u.array;
		avoid_shared_buffer_inout(&rec->a4,
					  SEMCTL_ARRAY_SLOTS * sizeof(*array));
		return;

	case GETALL:
		array = zmalloc_tracked(SEMCTL_ARRAY_SLOTS * sizeof(*array));
		u.array = array;
		rec->a4 = (unsigned long) u.array;
		avoid_shared_buffer_out(&rec->a4,
					SEMCTL_ARRAY_SLOTS * sizeof(*array));
		return;

	case IPC_STAT:
	case SEM_STAT:
	case SEM_STAT_ANY:
		ds = zmalloc_tracked(sizeof(*ds));
		u.buf = ds;
		rec->a4 = (unsigned long) u.buf;
		avoid_shared_buffer_out(&rec->a4, sizeof(*ds));
		return;

	case IPC_SET:
		ds = zmalloc_tracked(sizeof(*ds));
		/*
		 * IPC_SET copies sem_perm.uid / .gid / .mode out of the
		 * caller-supplied semid_ds and applies them to the sem
		 * set's perm record.  Same shape and rationale as the
		 * msgctl IPC_SET branch -- without populating these the
		 * call either fires EPERM (can't reassign ownership to
		 * uid=0 as non-root) or installs mode=0 and locks the
		 * set out of every subsequent fuzzed operation.  The
		 * 0400 OR keeps read access alive for later consumers.
		 */
		{
			static const unsigned short mode_dict[] = {
				0600, 0644, 0666,
			};
			ds->sem_perm.uid = getuid();
			ds->sem_perm.gid = getgid();
			ds->sem_perm.mode =
				mode_dict[rnd_modulo_u32(ARRAY_SIZE(mode_dict))]
				| 0400;
		}
		u.buf = ds;
		rec->a4 = (unsigned long) u.buf;
		avoid_shared_buffer_inout(&rec->a4, sizeof(*ds));
		return;

	case IPC_INFO:
	case SEM_INFO:
		info = zmalloc_tracked(sizeof(*info));
		u.__buf = info;
		rec->a4 = (unsigned long) u.__buf;
		avoid_shared_buffer_out(&rec->a4, sizeof(*info));
		return;

	case GETPID:
	case GETVAL:
	case GETNCNT:
	case GETZCNT:
	case IPC_RMID:
	default:
		/*
		 * arg is ignored for these cmds.  Leave rec->a4 alone --
		 * the random-pool address the generator already deposited
		 * is fine, and the avoid_shared_buffer_out() call from
		 * the caller keeps it out of shared memory.
		 */
		avoid_shared_buffer_out(&rec->a4, page_size);
		return;
	}
}

static void sanitise_semctl(struct syscallrecord *rec)
{
	/*
	 * Override the ARG_RANGE-generated semnum with a pool-aware pick.
	 * The default 0..250 range was wider than any set's real nsems
	 * (semget caps at 250, but most fuzz-created sets are smaller),
	 * leaving semnum out-of-range for ~all picks and starving the
	 * sem_array lookup success path.
	 */
	rec->a2 = (unsigned long) pick_semnum((int) rec->a1);

	build_semun_arg(rec);
}

struct syscallentry syscall_semctl = {
	.name = "semctl",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_SEM_ID, [1] = ARG_RANGE, [2] = ARG_OP, [3] = ARG_ADDRESS },
	.argname = { [0] = "semid", [1] = "semnum", [2] = "cmd", [3] = "arg" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 250,
	.arg_params[2].list = ARGLIST(semctl_cmds),
	.sanitise = sanitise_semctl,
};
