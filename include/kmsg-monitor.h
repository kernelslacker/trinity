#pragma once

/*
 * Structured tag for a /dev/kmsg report that kmsg-monitor noticed.
 * Emitted alongside the raw banner string so downstream log parsers
 * can switch on a stable integer instead of grepping banner text.
 *
 * KMSG_EVENT_UNKNOWN is deliberately zero so zero-initialised storage
 * means "no classification".  New kinds get appended; the integer
 * values are part of the on-the-wire format.
 */
enum kmsg_event_kind {
	KMSG_EVENT_UNKNOWN = 0,
	KMSG_WARN,		/* generic WARN_ON / WARNING: splat */
	KMSG_WARN_RECLOCK,	/* lockdep "possible recursive locking" */
	KMSG_WARN_CIRCULAR,	/* lockdep "possible circular locking" */
	KMSG_RCU,		/* RCU self-detected stall */
	KMSG_BUG,		/* BUG()/BUG_ON, KASAN/KMSAN/KCSAN/UBSAN, refcount_t */
	KMSG_OOPS,		/* Oops, #GP, unhandled paging fault */
};

void kmsg_monitor_start(void);
void kmsg_monitor_stop(void);
