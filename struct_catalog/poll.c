/*
 * struct_catalog/poll.c -- poll / epoll struct field tables.
 *
 * Field/variant tables are `const` (not `static const`) so the spine's
 * .fields=/.variants= references resolve via struct_catalog-internal.h.
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty when USE_<X> is off.
 */

#include <stddef.h>
#include <sys/epoll.h>

#include "config.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#include "kernel/epoll.h"
/* ------------------------------------------------------------------ */
/* struct epoll_event (epoll_ctl)                                      */
/* ------------------------------------------------------------------ */

/*
 * EPOLL* event-bit vocabulary for epoll_event.events.  EPOLLEXCLUSIVE
 * and EPOLLWAKEUP postdate older glibc vintages; include/kernel/epoll.h declares
 * EPOLLWAKEUP unconditionally and the local #ifdef arm covers
 * EPOLLEXCLUSIVE.  Bits outside the mask either fail the kernel's
 * EP_PRIVATE_BITS check or get silently masked, so a uniform-byte
 * splat almost never produces a useful (op, events) combination.
 */
#ifndef EPOLLEXCLUSIVE
# define EPOLLEXCLUSIVE_COMPAT	(1u << 28)
#else
# define EPOLLEXCLUSIVE_COMPAT	EPOLLEXCLUSIVE
#endif

#define EPOLL_EVENTS_MASK \
	(EPOLLIN     | EPOLLOUT    | EPOLLRDHUP   | EPOLLPRI    | \
	 EPOLLERR    | EPOLLHUP    | EPOLLET      | EPOLLONESHOT | \
	 EPOLLWAKEUP | EPOLLEXCLUSIVE_COMPAT       | \
	 EPOLLRDNORM | EPOLLRDBAND | EPOLLWRNORM  | EPOLLWRBAND | \
	 EPOLLMSG)

const struct struct_field epoll_event_fields[EPOLL_EVENT_FIELDS_N] = {
	FIELDX(struct epoll_event, events, FT_FLAGS,
	       .u.flags.mask = EPOLL_EVENTS_MASK,
	       .mutate_weight = 80),
};
