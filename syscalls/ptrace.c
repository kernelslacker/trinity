/*
 * SYSCALL_DEFINE4(ptrace, long, request, long, pid, long, addr, long, data)
 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ptrace.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

/*
 * Snapshot of the heap allocation sanitise hands to the kernel via
 * rec->a4, captured at sanitise time and consumed by the post handler.
 * Lives in rec->post_state, a slot the syscall ABI does not expose, so
 * the post path is immune to a sibling syscall scribbling rec->a1 or
 * rec->a4 between the syscall returning and the post handler running.
 *
 * Per-op allocation matrix.  Of the 25 PTRACE_* requests this generator
 * knows about, only four allocate a heap buffer that the post handler
 * has to free:
 *
 *   PTRACE_SETSIGINFO  -> siginfo_t *
 *   PTRACE_GETSIGINFO  -> siginfo_t *
 *   PTRACE_SETSIGMASK  -> sigset_t *
 *   PTRACE_GETSIGMASK  -> sigset_t *
 *
 * The other 21 requests feed rec->a4 with non-heap values -- signals,
 * immediate bitmasks, addresses from get_address() / get_writable_-
 * address(), or zero -- and leave snap->data NULL.  The post handler
 * dispatches off the snapshot, not rec->a1, so a sibling scribble of
 * the request opcode also cannot redirect the free into a non-heap
 * rec->a4 slot.
 */
struct ptrace_post_state {
	void *data;
};

static unsigned long ptrace_o_flags[] = {
	PTRACE_O_TRACESYSGOOD,
	PTRACE_O_TRACEFORK,
	PTRACE_O_TRACEVFORK,
	PTRACE_O_TRACECLONE,
	PTRACE_O_TRACEEXEC,
	PTRACE_O_TRACEVFORKDONE,
	PTRACE_O_TRACEEXIT,
	PTRACE_O_TRACESECCOMP,
	PTRACE_O_EXITKILL,
	PTRACE_O_SUSPEND_SECCOMP,
};

static void sanitise_ptrace(struct syscallrecord *rec)
{
	struct ptrace_post_state *snap;
	void *data = NULL;

	/* Use child pids only — tracing parent/screen/tmux hangs forever */
	rec->a2 = get_pid();

	/*
	 * arg4 (data) semantics depend on the request.  Generate appropriate
	 * values instead of leaving it ARG_UNDEFINED (random garbage that
	 * rarely exercises real code paths).
	 */
	switch (rec->a1) {
	case PTRACE_SETOPTIONS:
		/* Bitmask of PTRACE_O_* flags */
		rec->a4 = set_rand_bitmask(ARRAY_SIZE(ptrace_o_flags),
					   ptrace_o_flags);
		break;

	case PTRACE_POKEDATA:
	case PTRACE_POKETEXT:
	case PTRACE_POKEUSR:
		/* Data is the value to write at the address in arg3 */
		switch (rand() % 4) {
		case 0: rec->a4 = 0; break;
		case 1: rec->a4 = rand32(); break;
		case 2: rec->a4 = rand64(); break;
		case 3: rec->a4 = (unsigned long) get_address(); break;
		}
		break;

	case PTRACE_SETSIGINFO: {
		/* data must point to a siginfo_t */
		siginfo_t *si = zmalloc(sizeof(siginfo_t));

		si->si_signo = (rand() % 31) + 1;
		si->si_code = rand32();
		si->si_errno = rand() % 133;
		rec->a4 = (unsigned long) si;
		data = si;
		break;
	}

	case PTRACE_GETSIGINFO: {
		/* data must point to writable siginfo_t buffer */
		siginfo_t *si = zmalloc(sizeof(siginfo_t));

		rec->a4 = (unsigned long) si;
		data = si;
		break;
	}

	case PTRACE_SETSIGMASK: {
		/*
		 * data points to a sigset_t; addr (arg3) is sizeof(sigset_t).
		 * Set a random signal mask.
		 */
		sigset_t *set = zmalloc(sizeof(sigset_t));

		generate_rand_bytes((unsigned char *) set, sizeof(sigset_t));
		rec->a3 = sizeof(sigset_t);
		rec->a4 = (unsigned long) set;
		data = set;
		break;
	}

	case PTRACE_GETSIGMASK: {
		/* data points to writable sigset_t; addr is sizeof(sigset_t) */
		sigset_t *set = zmalloc(sizeof(sigset_t));

		rec->a3 = sizeof(sigset_t);
		rec->a4 = (unsigned long) set;
		data = set;
		break;
	}

	case PTRACE_CONT:
	case PTRACE_SYSCALL:
	case PTRACE_SINGLESTEP:
	case PTRACE_SYSEMU:
	case PTRACE_SYSEMU_SINGLESTEP:
	case PTRACE_DETACH:
		/* data is the signal to deliver (0 = none) */
		if (RAND_BOOL())
			rec->a4 = 0;
		else
			rec->a4 = (rand() % 31) + 1;
		break;

	case PTRACE_PEEKDATA:
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKUSR:
	case PTRACE_GETREGS:
	case PTRACE_GETFPREGS:
	case PTRACE_GETEVENTMSG:
		/* data is an output pointer — give it a writable address */
		rec->a4 = (unsigned long) get_writable_address(page_size);
		break;

	case PTRACE_SETREGS:
	case PTRACE_SETFPREGS:
		/* data points to a register set — give it a readable address */
		rec->a4 = (unsigned long) get_address();
		break;

	case PTRACE_TRACEME:
	case PTRACE_KILL:
	case PTRACE_ATTACH:
		/* These ignore data */
		rec->a4 = 0;
		break;

	default:
		/* Unknown requests — leave data as random */
		break;
	}

	/*
	 * Snapshot the heap pointer (or NULL for the 21 ops that did not
	 * allocate) for the post handler.  A sibling syscall can scribble
	 * rec->a4 between the syscall returning and the post handler
	 * running, leaving a real-but-wrong heap pointer that
	 * looks_like_corrupted_ptr() cannot distinguish from the original;
	 * the post handler then hands the wrong allocation to free, leaking
	 * ours and corrupting another sanitise routine's live buffer.  A
	 * scribble of rec->a1 is just as dangerous -- it would redirect the
	 * old request-gated dispatch into a non-heap rec->a4 slot.
	 * rec->post_state is private to the post handler, so the scribblers
	 * have nothing to scribble there.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->data = data;
	rec->post_state = (unsigned long) snap;
}

static void post_ptrace(struct syscallrecord *rec)
{
	struct ptrace_post_state *snap = (struct ptrace_post_state *) rec->post_state;

	rec->a4 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_ptrace: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner pointer may no longer reference our heap allocation.
	 * NULL is a legitimate value here (most ops do not allocate), so
	 * only flag a non-NULL value that fails the heuristic.  Leak
	 * rather than hand garbage to free().
	 */
	if (snap->data != NULL && looks_like_corrupted_ptr(snap->data)) {
		outputerr("post_ptrace: rejected suspicious snap data=%p "
			  "(post_state-scribbled?)\n", snap->data);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		deferred_freeptr(&rec->post_state);
		return;
	}

	/*
	 * deferred_free_enqueue() is a no-op on NULL, so the call falls
	 * through harmlessly for ops that did not allocate.  We use
	 * enqueue (not deferred_freeptr) so concurrent observers that
	 * grabbed the address from rec->a4 before a scribble do not UAF.
	 */
	deferred_free_enqueue(snap->data, NULL);
	deferred_freeptr(&rec->post_state);
}

static unsigned long ptrace_reqs[] = {
	PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSR,
	PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSR, PTRACE_GETREGS,
	PTRACE_GETFPREGS, PTRACE_GETSIGINFO, PTRACE_SETREGS, PTRACE_SETFPREGS,
	PTRACE_SETSIGINFO, PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG, PTRACE_CONT,
	PTRACE_SYSCALL, PTRACE_SINGLESTEP, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP,
	PTRACE_KILL, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_GETSIGMASK,
	PTRACE_SETSIGMASK,
};

struct syscallentry syscall_ptrace = {
	.name = "ptrace",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID, [2] = ARG_ADDRESS },
	.argname = { [0] = "request", [1] = "pid", [2] = "addr", [3] = "data" },
	.arg_params[0].list = ARGLIST(ptrace_reqs),
	.sanitise = sanitise_ptrace,
	.post = post_ptrace,

	.flags = AVOID_SYSCALL,
};
