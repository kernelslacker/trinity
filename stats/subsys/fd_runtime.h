#ifndef _TRINITY_STATS_SUBSYS_FD_RUNTIME_H
#define _TRINITY_STATS_SUBSYS_FD_RUNTIME_H

struct fd_runtime_stats {
	/*
	 * register_returned_fd() runtime-registration bookkeeping.
	 *
	 * registered:  count of fds the generic ret_objtype post-hook
	 *   auto-registered into a per-type OBJ_LOCAL pool because no
	 *   syscall-specific .post had already done so.  Rendered in JSON
	 *   under fd_lifecycle.runtime_registered so a spike alongside
	 *   flat ret_objtype activity has a non-guess explanation.
	 *
	 * stdio / already_registered:  register_returned_fd() reject
	 *   attribution -- bumped on every skipped registration.  Rendered
	 *   in JSON under the fd_runtime_skipped category so schema
	 *   consumers see the same top-level keys.
	 *
	 * stdio:  fd <= 2.  Either a kernel/test bug surfaced a stdio fd
	 *   as a fresh syscall return (genuinely noteworthy) or stderr was
	 *   closed and the next open(2) got re-allocated into slot 2; both
	 *   warrant a look.
	 *
	 * already_registered:  find_local_object_by_fd() matched.  Dominant
	 *   reason is a per-syscall .post that already registered the fd
	 *   with richer metadata (socket triplet, eventfd count,
	 *   perf_event_attr, ...); the generic post-hook correctly defers
	 *   to it.  A spike with no .post-side counter movement means a
	 *   syscall is dup'ing an fd we already own and the dup path isn't
	 *   routing through set_object_fd() with a fresh slot, i.e. a
	 *   coverage-equivalent obj is being silently dropped.
	 */
	unsigned long registered;
	unsigned long stdio;
	unsigned long already_registered;
};

#endif /* _TRINITY_STATS_SUBSYS_FD_RUNTIME_H */
