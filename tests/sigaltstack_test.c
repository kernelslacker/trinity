/*
 * Self-check for sigaltstack's sanitiser and post oracle
 * (syscalls/signal/sigaltstack.c): a compat call's uss is the 12-byte
 * struct compat_stack its kernel reads, and a compat call's answer, in
 * the same layout, is not compared with the native re-call's stack_t.
 */

#include <signal.h>
#include <stdint.h>
#include <string.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* get_writable_address */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_sigaltstack */

extern struct childdata *fake_this_child;	/* fake_shm.c */

/* sigaltstack on i386. */
#define NR_SIGALTSTACK_32	186

/* The smallest stack a compat call may set: x86's MINSIGSTKSZ, which
 * the kernel's COMPAT_MINSIGSTKSZ falls back to. */
#define KERNEL_MINSIGSTKSZ	2048

/* include/linux/compat.h's compat_stack_t. */
struct compat_stack_view {
	uint32_t ss_sp;
	int32_t ss_flags;
	uint32_t ss_size;
};

/* Calls: one in fourteen only reads the stack back, and the re-call is
 * sampled one in a hundred of those. */
#define CALLS	30000

void sigaltstack_self_check(void);
void sigaltstack_self_check(void)
{
	static struct childdata compat;
	struct syscallrecord *crec = &compat.syscall;
	unsigned long before = shm->stats.oracle.sigaltstack_oracle_anomalies;
	unsigned int i, disabled = 0, enabled = 0;

	/* A sanitiser builds the call in this_child()'s record, whose
	 * being compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0; i < CALLS; i++) {
		memset(crec, 0, sizeof(*crec));
		crec->do32bit = true;
		crec->nr = NR_SIGALTSTACK_32;
		crec->a2 = (unsigned long) get_writable_address(sizeof(stack_t));
		syscall_sigaltstack.sanitise(crec);

		/* The dispatcher's post pass, on a failed call for each one
		 * that sets a stack, which releases the snapshot. */
		crec->retval = (unsigned long) -1L;
		if (crec->a1 != 0) {
			const struct compat_stack_view *css =
				(const struct compat_stack_view *) crec->a1;

			if (crec->a1 > UINT32_MAX - sizeof(*css))
				BUG("sigaltstack: a compat call's uss lies past 4 GiB");
			if (css->ss_flags == SS_DISABLE && css->ss_sp == 0 &&
			    css->ss_size == 0)
				disabled++;
			else if (css->ss_flags == 0 && css->ss_sp != 0 &&
				 css->ss_size >= KERNEL_MINSIGSTKSZ)
				enabled++;
		} else if (crec->a2 != 0) {
			/* What a compat kernel writes back for a task with
			 * no stack, the rest of the buffer as it was. */
			const struct compat_stack_view none = {
				.ss_flags = SS_DISABLE,
			};

			memcpy((void *) crec->a2, &none, sizeof(none));
			crec->retval = 0;
		}
		syscall_sigaltstack.post(crec);
	}
	fake_this_child = NULL;

	if (disabled == 0 || enabled == 0)
		BUG("sigaltstack: a compat call's uss read as no stack the sanitiser drew");
	if (shm->stats.oracle.sigaltstack_oracle_anomalies != before)
		BUG("sigaltstack: a compat call's answer was compared with the native stack_t");
}
