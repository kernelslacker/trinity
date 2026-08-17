#ifndef _TRINITY_STATS_SUBSYS_POSIX_TIMER_H
#define _TRINITY_STATS_SUBSYS_POSIX_TIMER_H

struct posix_timer_stats {
	/* recipe_posix_timer arm 2 (SIGEV_THREAD_ID) signal delivery counters.
	 * sigev_delivered: sigtimedwait returned > 0 with si_code == SI_TIMER
	 *   and the 0x5e cookie intact -- confirms the kernel send_sigqueue()
	 *   path reached the fuzz child's task.
	 * sigev_missed: sigtimedwait timed out or failed -- timer armed but
	 *   signal never arrived within the 50 ms window.
	 * sigev_cookie_bad: sigtimedwait returned > 0 but si_value.sival_int
	 *   or si_code did not match expectations -- unexpected signal source. */
	unsigned long sigev_delivered;
	unsigned long sigev_missed;
	unsigned long sigev_cookie_bad;
};

#endif /* _TRINITY_STATS_SUBSYS_POSIX_TIMER_H */
