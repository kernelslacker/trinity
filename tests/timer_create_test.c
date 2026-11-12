/*
 * Self-check for the signal timer_create's sanitiser gives a timer: once
 * armed, the timer signals the child that made it, maybe over and over, so
 * the signal is one of the set a child takes without dying
 * (signals-safelist.c), but for the two its watchdogs count, or a realtime
 * one, which the child ignores.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "signals-safelist.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_timer_create */

#define TIMER_CREATE_ROUNDS	4000

void timer_create_self_check(void);
void timer_create_self_check(void)
{
	bool safe = false, realtime = false;
	unsigned int i, k;

	for (i = 0; i < TIMER_CREATE_ROUNDS; i++) {
		struct syscallrecord rec;
		const struct sigevent *sev;

		memset(&rec, 0, sizeof(rec));
		syscall_timer_create.sanitise(&rec);
		free((void *) rec.post_state);
		sev = (const struct sigevent *) rec.a2;
		if (sev == NULL)
			continue;

		if (sev->sigev_signo >= SIGRTMIN && sev->sigev_signo <= SIGRTMAX) {
			realtime = true;
			continue;
		}
		if (sev->sigev_signo == SIGALRM || sev->sigev_signo == SIGXCPU)
			BUG("timer_create: a timer's signal sets off the child's watchdogs");
		for (k = 0; k < child_safe_signals_count; k++) {
			if ((unsigned long) sev->sigev_signo == child_safe_signals[k])
				break;
		}
		if (k == child_safe_signals_count)
			BUG("timer_create: a timer's signal ends the child it signals");
		safe = true;
	}
	if (!safe || !realtime)
		BUG("timer_create: a timer's signal is never a safe one, or never realtime");
}
