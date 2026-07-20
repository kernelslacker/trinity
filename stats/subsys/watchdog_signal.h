#ifndef _TRINITY_STATS_SUBSYS_WATCHDOG_SIGNAL_H
#define _TRINITY_STATS_SUBSYS_WATCHDOG_SIGNAL_H

/*
 * watchdog signal-handler clobber + reinstall accounting.  Sampled
 * from the arm-site probe (sigaction NULL read + reinstall) in
 * health/signals.c around every alarm(1) arm on the alt-op dispatch
 * and NEED_ALARM syscall paths.
 *
 * Bespoke (non-category) RAW group.  All bumps RELAXED on shm->stats.
 * The surrounding struct stats_s composes an instance of struct
 * watchdog_signal_stats as its "watchdog_signal" member.
 */
struct watchdog_signal_stats {
	/* Bumped immediately before each alarm(1) arm (alt-op dispatch
	 * and NEED_ALARM syscall paths) when a sigaction(SIGALRM, NULL,
	 * &cur) probe reads back sa_handler != sigalrm_handler -- i.e. a
	 * fuzzed rt_sigaction call in this child has overwritten the
	 * internal-watchdog disposition before the watchdog gets armed.
	 * SIGALRM appears in settable_signals[], so a child can disarm
	 * its own 1-second inner watchdog by installing SIG_IGN /
	 * SIG_DFL / an arbitrary dummy; subsequent blocking ops then
	 * ride only the ~30-second outer watchdog, which is the dominant
	 * late-run wedge mechanism.  The arm-site probe now restores the
	 * handler in place before arming (see sigalrm_reinstalled below),
	 * so this row measures the incidence and the reinstalled row
	 * measures the repair rate; both bump on every repair.  RELAXED
	 * add-fetch: coarse anomaly counter, not an event log. */
	unsigned long sigalrm_clobbered;

	/* Mirror of sigalrm_clobbered for SIGXCPU.  SIGXCPU also lives
	 * in settable_signals[] and shares the same disarm-by-fuzzed-
	 * rt_sigaction class; the inner-watchdog SIGXCPU disposition
	 * (sigxcpu_handler) is installed once per child in
	 * mask_signals_child() and is now restored by the same arm-site
	 * probe that reinstalls SIGALRM.  Sampled from the same arm
	 * sites as the SIGALRM probe -- the probe is effectively free
	 * (one extra rt_sigaction read) and surfacing SIGXCPU separately
	 * keeps the SIGALRM signal clean.  RELAXED add-fetch; same
	 * caveat as the SIGALRM row above. */
	unsigned long sigxcpu_clobbered;

	/* Companion counters to the two _clobbered rows above: bumped
	 * alongside a clobber when the arm-site probe restores the
	 * expected inner-watchdog handler via sigaction() before arming
	 * alarm(1).  Every reinstall bumps both rows; keeping the repair
	 * counter separate leaves the raw clobber incidence intact for
	 * comparison with earlier read-only-probe runs.  Same probe
	 * sites, same RELAXED semantics as the paired _clobbered row. */
	unsigned long sigalrm_reinstalled;
	unsigned long sigxcpu_reinstalled;
};

#endif	/* _TRINITY_STATS_SUBSYS_WATCHDOG_SIGNAL_H */
