/*
 * SYSCALL_DEFINE4(ptrace, long, request, long, pid, long, addr, long, data)
 */
#include "trinity.h"
#include "sanitise.h"
#include <linux/ptrace.h>

struct syscall syscall_ptrace = {
	.name = "ptrace",
	.num_args = 4,
	.arg1name = "request",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 23,
		.values = { PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_PEEKDATA, PTRACE_PEEKUSR,
				PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSR, PTRACE_GETREGS,
				PTRACE_GETFPREGS, PTRACE_GETSIGINFO, PTRACE_SETREGS, PTRACE_SETFPREGS,
				PTRACE_SETSIGINFO, PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG, PTRACE_CONT,
				PTRACE_SYSCALL, PTRACE_SINGLESTEP, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP,
				PTRACE_KILL, PTRACE_ATTACH, PTRACE_DETACH },
	},
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "addr",
	.arg3type = ARG_ADDRESS,
	.arg4name = "data",
};
