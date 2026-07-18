/*
 * Time / timer struct-catalog registrations.
 *
 * Rows in this file map the timekeeping-primary syscalls (adjtimex,
 * clock_*, timer_*, timerfd_*, nanosleep, settimeofday, setitimer,
 * timer_create) onto the timex / timespec / itimerspec / itimerval /
 * timeval / timezone / sigevent descriptors.  Timeout-taking syscalls
 * whose primary domain is elsewhere (ppoll, pselect6, mq_timed*,
 * io_*getevents, futex*, semtimedop, ...) keep their timespec rows
 * with the owning domain file.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>
#include <signal.h>

#include "config.h"

#include "struct_catalog.h"
#include "trinity.h"

const struct syscall_struct_arg struct_catalog_registry_time[] = {
	/* adjtimex(struct timex *) */
	{ "adjtimex",		1, &struct_catalog[SC_TIMEX] },
	/* clock_adjtime(clockid_t, struct timex *) */
	{ "clock_adjtime",	2, &struct_catalog[SC_TIMEX] },
	/* timer_settime(timer_t, int, struct itimerspec *, struct itimerspec *) */
	{ "timer_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* timerfd_settime(int, int, struct itimerspec *, struct itimerspec *) */
	{ "timerfd_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* clock_nanosleep(clockid_t, int, struct timespec *, struct timespec *) */
	{ "clock_nanosleep",	3, &struct_catalog[SC_TIMESPEC] },
	/* nanosleep(struct timespec *, struct timespec *) */
	{ "nanosleep",		1, &struct_catalog[SC_TIMESPEC] },
	/*
	 * clock_settime(clockid_t which_clock, const struct timespec *tp)
	 * a2 is the INPUT timespec.  Attribution-only: the bespoke
	 * sanitise_clock_settime (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "clock_settime",	2, &struct_catalog[SC_TIMESPEC] },
	/*
	 * timer_create(clockid_t, struct sigevent *, timer_t *)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * timer_create_sanitise() keeps owning the live (sigev_value,
	 * sigev_signo, sigev_notify, _sigev_un._tid) layout and the
	 * SIGEV_* notify-mode distribution.  Attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at sigev_notify / sigev_signo rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "timer_create",	2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * setitimer(int which, const struct itimerval __user *value,
	 *           struct itimerval __user *ovalue)
	 * a2 is the INPUT struct itimerval pointer; the bespoke
	 * sanitise_setitimer() keeps owning the live fill (writable
	 * allocation, per-timeval bucket distribution via fill_timeval(),
	 * half-the-time disarm of it_value, a3 routed through
	 * avoid_shared_buffer_out()).  a3 (ovalue) is a kernel-written
	 * output and is intentionally not mapped; getitimer's a2 is
	 * likewise an output and is not mapped either.  Attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named tv_sec / tv_usec slots rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "setitimer",		2, &struct_catalog[SC_ITIMERVAL] },
	/*
	 * settimeofday a1: INPUT struct timeval.  Attribution-only;
	 * bespoke sanitiser owns the live fill.  gettimeofday's a1 not
	 * mapped: kernel-written OUTPUT with no input to attribute.
	 * See Documentation/struct_catalog.md.
	 */
	{ "settimeofday",	1, &struct_catalog[SC_TIMEVAL] },
	/*
	 * settimeofday a2: INPUT struct timezone.  Attribution-only;
	 * bespoke sanitise_settimeofday() owns the live fill.
	 * gettimeofday's a2 not mapped: kernel-written OUTPUT.
	 * See Documentation/struct_catalog.md.
	 */
	{ "settimeofday",	2, &struct_catalog[SC_TIMEZONE] },
	/* sentinel */
	{ NULL, 0, NULL },
};
