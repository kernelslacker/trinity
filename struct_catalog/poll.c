/*
 * struct_catalog/poll.c -- poll / epoll struct field tables.
 *
 * Field/variant tables are `const` (not `static const`) so the spine's
 * .fields=/.variants= references resolve via struct_catalog-internal.h.
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty when USE_<X> is off.
 */

#include <stddef.h>
#include <poll.h>
#include <sys/epoll.h>

#include "config.h"
#include "struct_catalog.h"
#include "compat.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#include "kernel/epoll.h"
/* ------------------------------------------------------------------ */
/* struct pollfd (poll, ppoll)                                         */
/* ------------------------------------------------------------------ */

/*
 * poll and ppoll pass an ARRAY of pollfd at a1 (nfds in a2), not a
 * single struct, and the arg slot is ARG_ADDRESS rather than
 * ARG_STRUCT_PTR_*.  The bespoke alloc_pollfds() helper in
 * syscalls/poll.c allocates the buffer, picks each entry's
 * (fd, events) tuple from the pollable-fd pool plus a curated event
 * vocabulary, and overwrites rec->a1 -- the schema-aware fill path
 * never runs for this slot.
 *
 * Registration is attribution-only, mirroring sembuf above:
 * struct_field_for_cmp() uses the FT_FD / FT_FLAGS tags to steer
 * KCOV-CMP learned constants at the fd or events slot rather than at
 * a coincidentally-same-width slot.  revents is the kernel-written
 * output half of this value-result buffer and stays FT_RAW: no
 * userspace-side vocab applies, and FT_FLAGS attribution against the
 * kernel-chosen revents bitmask would mislead the heuristic.
 */
#define POLLFD_EVENTS_MASK \
	(POLLIN | POLLOUT | POLLPRI | POLLERR | \
	 POLLHUP | POLLNVAL | POLLRDHUP)

const struct struct_field pollfd_fields[POLLFD_FIELDS_N] = {
	FIELDX(struct pollfd, fd, FT_FD,
	       .mutate_weight = 80),
	FIELDX(struct pollfd, events, FT_FLAGS,
	       .u.flags.mask = POLLFD_EVENTS_MASK,
	       .mutate_weight = 80),
	FIELD(struct pollfd, revents),
};

/* ------------------------------------------------------------------ */
/* struct epoll_event (epoll_ctl)                                      */
/* ------------------------------------------------------------------ */

/*
 * EPOLL* event-bit vocabulary for epoll_event.events.  EPOLLEXCLUSIVE
 * and EPOLLWAKEUP postdate older glibc vintages; compat.h declares
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
