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
#include "shm.h"
#include "trinity.h"
#include "compat.h"

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
		break;
	}

	case PTRACE_GETSIGINFO: {
		/* data must point to writable siginfo_t buffer */
		siginfo_t *si = zmalloc(sizeof(siginfo_t));

		rec->a4 = (unsigned long) si;
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
		break;
	}

	case PTRACE_GETSIGMASK: {
		/* data points to writable sigset_t; addr is sizeof(sigset_t) */
		sigset_t *set = zmalloc(sizeof(sigset_t));

		rec->a3 = sizeof(sigset_t);
		rec->a4 = (unsigned long) set;
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
}

static void post_ptrace(struct syscallrecord *rec)
{
	switch (rec->a1) {
	case PTRACE_SETSIGINFO:
	case PTRACE_GETSIGINFO:
	case PTRACE_SETSIGMASK:
	case PTRACE_GETSIGMASK:
		freeptr(&rec->a4);
		break;
	default:
		break;
	}
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
