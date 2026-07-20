#ifndef _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H
#define _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H

/* epoll_volatility childop counters + epoll-family wait/arm accounting */
struct epoll_volatility_stats {
	unsigned long runs;		/* total epoll_volatility invocations */
	unsigned long ctl_calls;	/* total epoll_ctl ADD/MOD/DEL calls (success + fail) */
	unsigned long failed;		/* epoll_ctl returned -1 (EEXIST/ENOENT/EINVAL/...) */

	/* Number of times a child won the CAS in arm_epoll_if_needed() and
	 * actually performed the EPOLL_CTL_ADD population for an unarmed
	 * epfd.  Should rise once per epfd seeded by init_epoll_fds().
	 * A flat counter means children aren't picking unarmed epfds --
	 * either the consumer wireup regressed or no one is calling
	 * get_typed_fd(ARG_FD_EPOLL) / get_rand_epoll_fd. */
	unsigned long lazy_armed;

	/* Number of fd-pickup attempts the watch-set sanitisers (arm_epoll,
	 * sanitise_epoll_ctl, sanitise_poll/ppoll, sanitise_select) refused
	 * because the candidate fd belonged to an fd_provider whose
	 * poll_can_block tag was set (FUSE / userfaultfd / KVM vCPU /
	 * io_uring / pidfd).  Drop the kernel into the four ep_item_poll
	 * blocking-poll callsites (do_epoll_ctl + ep_send_events +
	 * __ep_eventpoll_poll + ep_loop_check_proc) without this filter and
	 * a single FUSE daemon dying takes 100+ child slots into
	 * TASK_UNINTERRUPTIBLE on the per-fd waitqueue, which the watchdog
	 * cannot break and defer-slot-reuse cannot recycle.  A non-zero
	 * counter alongside steady lazy_armed growth means the filter is
	 * doing work; a flat counter while D-state child counts climb means
	 * a new blocking-poll fd_provider escaped the tagging. */
	unsigned long blocking_poll_skipped;

	/* Cause-attribution for the epoll wait-family (epoll_wait,
	 * epoll_pwait, epoll_pwait2) rejects landing in
	 * validate_arg_coupling() with maxevents > 0 && events == NULL.
	 * The bare validator_rejected headline conflates every coupled-
	 * pair rule; these split the epoll subset by why a2 was zero:
	 *
	 *   wait_null_events_alloc_fail
	 *       The initial address the arg generator produced for a2
	 *       (ARG_NON_NULL_ADDRESS) was already 0 at sanitise entry.
	 *       Real cause today: get_writable_address() returning NULL
	 *       when mapping_sizes[] drew the GB(1) bucket that exceeds
	 *       the 1 MiB writable_pool, so get_non_null_address()
	 *       returned NULL.
	 *   wait_null_events_shared_reject
	 *       a2 was non-zero at sanitise entry but zero at sanitise
	 *       exit.  No live code path zeroes *addr inside
	 *       avoid_shared_buffer_out today; retained as a bucket so a
	 *       future ASB reject that DOES zero the slot is attributed
	 *       on first sight instead of silently collapsing back into
	 *       the headline.
	 *
	 * A "late mutation" residual (a2 was non-zero at sanitise exit
	 * but zero at validate_arg_coupling() time -- a sibling stomp
	 * between the two) is not accounted here; it is derivable as
	 * (epoll validator-rejects - alloc_fail - shared_reject) once a
	 * per-family split of validator_rejected is added.  Bumped with
	 * RELAXED atomics on shm->stats -- multi-producer, low rate,
	 * dump-side reader only. */
	unsigned long wait_null_events_alloc_fail;
	unsigned long wait_null_events_shared_reject;
};

#endif /* _TRINITY_STATS_SUBSYS_EPOLL_VOLATILITY_H */
