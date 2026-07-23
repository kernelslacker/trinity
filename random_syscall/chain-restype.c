/*
 * Resource-type dependency table for --chain-resource-typing.
 *
 * Small on purpose: one row per fd-family with a clean producer /
 * consumer split we already ship coverage for.  The whole point of
 * the row is to measure per-kind productivity via
 * chain_restype_replay_win[] BEFORE deciding which families deserve
 * a more elaborate schema.  A universal resource model is out of
 * scope here.
 *
 * Entries are syscall NAMES, not compile-time NRs; the numeric slot
 * is resolved at chain_restype_init() time via search_syscall_table
 * against the active table set (biarch-aware).  Names that fail to
 * resolve on the current arch drop out silently -- a compat gap that
 * removes a producer just leaves that row's producer slot at the
 * -1 sentinel, and classify_producer skips it.
 *
 * PIDFD: clone3 is included as a producer even though it only
 * produces a pidfd when its user-side struct clone_args carries the
 * CLONE_PIDFD flag.  Verifying that would require dereferencing
 * args[0] which may point at a fuzzed / unmapped user buffer.
 * Classifying by NR alone means clone3 without CLONE_PIDFD is a
 * false-positive producer -- but the whole point of the row is to
 * MEASURE per-kind productivity, and the resulting near-zero
 * chain_restype_replay_win[PIDFD] would surface exactly that
 * mismatch.  Same rationale for socket-tcp keying on (a1, a2 & 0xff)
 * -- we can inspect scalar arg values cheaply, but not deref a
 * pointer.
 */

#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sequence.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

#include "chain-internal.h"

#define CHAIN_RESTYPE_MAX_PRODUCERS 4
#define CHAIN_RESTYPE_MAX_CONSUMERS 6

struct chain_restype_row {
	const char *producers[CHAIN_RESTYPE_MAX_PRODUCERS];
	const char *consumers[CHAIN_RESTYPE_MAX_CONSUMERS];
};

static const struct chain_restype_row chain_restype_table[CHAIN_RESTYPE_NR] = {
	[CHAIN_RESTYPE_EPOLL_FD] = {
		.producers = { "epoll_create1", NULL, NULL, NULL },
		.consumers = { "epoll_ctl", "epoll_wait", "epoll_pwait",
			       "epoll_pwait2", NULL, NULL },
	},
	[CHAIN_RESTYPE_TIMERFD] = {
		.producers = { "timerfd_create", NULL, NULL, NULL },
		.consumers = { "timerfd_settime", "timerfd_gettime", "read",
			       NULL, NULL, NULL },
	},
	[CHAIN_RESTYPE_EVENTFD] = {
		.producers = { "eventfd2", NULL, NULL, NULL },
		.consumers = { "poll", "read", "write",
			       NULL, NULL, NULL },
	},
	[CHAIN_RESTYPE_IO_URING_FD] = {
		.producers = { "io_uring_setup", NULL, NULL, NULL },
		.consumers = { "io_uring_register", "io_uring_enter",
			       NULL, NULL, NULL, NULL },
	},
	[CHAIN_RESTYPE_PIDFD] = {
		.producers = { "pidfd_open", "clone3", NULL, NULL },
		.consumers = { "pidfd_send_signal", "pidfd_getfd", "waitid",
			       "process_mrelease", NULL, NULL },
	},
	[CHAIN_RESTYPE_SOCKET_TCP] = {
		.producers = { "socket", NULL, NULL, NULL },
		.consumers = { "bind", "connect", "setsockopt", "sendmsg",
			       NULL, NULL },
	},
	[CHAIN_RESTYPE_BPF_MAP_FD] = {
		.producers = { "bpf", NULL, NULL, NULL },
		.consumers = { "bpf", NULL, NULL, NULL, NULL, NULL },
	},
};

/*
 * Resolved NR tables.  [biarch_slot] indexes are (0 = uniarch or
 * 64-bit, 1 = 32-bit under biarch).  Slot value -1 means "no NR
 * resolved" -- either the name is not in the compiled table for
 * this arch or biarch is off and we never populate slot 1.
 */
static int chain_restype_producer_nr[CHAIN_RESTYPE_NR][2]
					[CHAIN_RESTYPE_MAX_PRODUCERS];
static int chain_restype_consumer_nr[CHAIN_RESTYPE_NR][2]
					[CHAIN_RESTYPE_MAX_CONSUMERS];

static void chain_restype_resolve_slot(const char *name, int slot,
				       int *dst64, int *dst32)
{
	int nr;

	if (name == NULL) {
		*dst64 = -1;
		if (dst32 != NULL)
			*dst32 = -1;
		return;
	}

	if (biarch == true) {
		nr = search_syscall_table(syscalls_64bit,
					  max_nr_64bit_syscalls, name);
		*dst64 = (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) ?
			 nr : -1;

		nr = search_syscall_table(syscalls_32bit,
					  max_nr_32bit_syscalls, name);
		if (dst32 != NULL)
			*dst32 = (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) ?
				 nr : -1;
	} else {
		nr = search_syscall_table(syscalls, max_nr_syscalls, name);
		*dst64 = (nr >= 0 && (unsigned int)nr < MAX_NR_SYSCALL) ?
			 nr : -1;
		if (dst32 != NULL)
			*dst32 = -1;
	}
	(void)slot;
}

void chain_restype_init(void)
{
	unsigned int k, i;

	for (k = 0; k < CHAIN_RESTYPE_NR; k++) {
		const struct chain_restype_row *row = &chain_restype_table[k];

		for (i = 0; i < CHAIN_RESTYPE_MAX_PRODUCERS; i++)
			chain_restype_resolve_slot(row->producers[i], (int)i,
				&chain_restype_producer_nr[k][0][i],
				&chain_restype_producer_nr[k][1][i]);
		for (i = 0; i < CHAIN_RESTYPE_MAX_CONSUMERS; i++)
			chain_restype_resolve_slot(row->consumers[i], (int)i,
				&chain_restype_consumer_nr[k][0][i],
				&chain_restype_consumer_nr[k][1][i]);
	}
}

/*
 * NR match against the producer slot for @kind.  Biarch-aware: 32-bit
 * dispatches match against the biarch [1] slot, everything else
 * matches [0].
 */
static bool chain_restype_nr_matches_producer(enum chain_resource_kind kind,
					      unsigned int nr, bool do32bit)
{
	unsigned int slot = do32bit ? 1u : 0u;
	unsigned int i;

	for (i = 0; i < CHAIN_RESTYPE_MAX_PRODUCERS; i++) {
		int cand = chain_restype_producer_nr[kind][slot][i];

		if (cand < 0)
			continue;
		if ((unsigned int)cand == nr)
			return true;
	}
	return false;
}

static bool chain_restype_nr_matches_consumer(enum chain_resource_kind kind,
					      unsigned int nr, bool do32bit)
{
	unsigned int slot = do32bit ? 1u : 0u;
	unsigned int i;

	for (i = 0; i < CHAIN_RESTYPE_MAX_CONSUMERS; i++) {
		int cand = chain_restype_consumer_nr[kind][slot][i];

		if (cand < 0)
			continue;
		if ((unsigned int)cand == nr)
			return true;
	}
	return false;
}

int chain_restype_classify_producer(unsigned int nr, bool do32bit,
				    const unsigned long args[6],
				    unsigned long retval)
{
	/* Filter errno-style returns.  A producer that failed did not
	 * produce a resource; feeding a -EBADF into a consumer next
	 * step wastes the bias budget on a downstream -EBADF -- exactly
	 * the same rationale execute_chain_steps uses to gate retval
	 * substitution on (long)rv >= 0. */
	if ((long)retval < 0)
		return -1;

	/* Simple-NR kinds: any producer NR in the row matches. */
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_EPOLL_FD,
					      nr, do32bit))
		return CHAIN_RESTYPE_EPOLL_FD;
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_TIMERFD,
					      nr, do32bit))
		return CHAIN_RESTYPE_TIMERFD;
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_EVENTFD,
					      nr, do32bit))
		return CHAIN_RESTYPE_EVENTFD;
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_IO_URING_FD,
					      nr, do32bit))
		return CHAIN_RESTYPE_IO_URING_FD;
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_PIDFD,
					      nr, do32bit))
		return CHAIN_RESTYPE_PIDFD;

	/* socket-tcp keys on (family, type & 0xff).  socket()'s a1 is
	 * the address family, a2 is (type | flags) so mask out
	 * SOCK_NONBLOCK / SOCK_CLOEXEC before comparing to SOCK_STREAM. */
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_SOCKET_TCP,
					      nr, do32bit)) {
		unsigned long fam = args[0];
		unsigned long type = args[1] & 0xffUL;

		if ((fam == AF_INET || fam == AF_INET6) &&
		    type == (unsigned long)SOCK_STREAM)
			return CHAIN_RESTYPE_SOCKET_TCP;
	}

	/* bpf-map-fd keys on cmd == BPF_MAP_CREATE (a1). */
	if (chain_restype_nr_matches_producer(CHAIN_RESTYPE_BPF_MAP_FD,
					      nr, do32bit)) {
		if (args[0] == (unsigned long)BPF_MAP_CREATE)
			return CHAIN_RESTYPE_BPF_MAP_FD;
	}

	return -1;
}

/*
 * Classify a step as a consumer.  Used by record_chain_outcome() to
 * detect producer->consumer PAIRS inside a saved / replayed chain, so
 * chain_restype_save / chain_restype_replay_win only bump for chains
 * that actually carried the pair (a producer-only chain isn't the
 * signal we're trying to reward).
 *
 * bpf is both the producer and the consumer for BPF_MAP_FD; the
 * consumer arm is BPF_MAP_UPDATE_ELEM / BPF_MAP_LOOKUP_ELEM.  The NR
 * table alone is not enough there -- BPF_MAP_FD is the one row whose
 * consumer syscall NR is the same as the producer NR, so an "any
 * later bpf()" match would count every unrelated cmd (PROG_LOAD,
 * OBJ_PIN, LINK_CREATE ...) as a map-fd consumer and inflate the
 * pair signal above what the fd coupling actually earned.  Gate the
 * BPF row on a1 == BPF_MAP_{UPDATE,LOOKUP}_ELEM so the pair credit
 * lines up with real map-fd use.  a1 is a scalar cmd enum, not the
 * bpf_attr pointer, so this stays within the "inspect scalars, do
 * not deref user memory" rule the producer classifier already sets.
 */
int chain_restype_classify_consumer(enum chain_resource_kind kind,
				    unsigned int nr, bool do32bit,
				    const unsigned long args[6])
{
	if (kind >= CHAIN_RESTYPE_NR)
		return -1;
	if (!chain_restype_nr_matches_consumer(kind, nr, do32bit))
		return -1;

	if (kind == CHAIN_RESTYPE_BPF_MAP_FD) {
		unsigned long cmd = args[0];

		if (cmd != (unsigned long)BPF_MAP_UPDATE_ELEM &&
		    cmd != (unsigned long)BPF_MAP_LOOKUP_ELEM)
			return -1;
	}

	return (int)kind;
}

/*
 * True iff kind has at least one resolved consumer NR in the table
 * for @do32bit_hint.  Cheap short-circuit for the SHADOW/LIVE hook:
 * a kind whose consumer table came up empty on this arch cannot bias.
 */
bool chain_restype_has_consumer(enum chain_resource_kind kind,
				bool do32bit_hint)
{
	unsigned int slot = do32bit_hint ? 1u : 0u;
	unsigned int i;

	if (kind >= CHAIN_RESTYPE_NR)
		return false;
	for (i = 0; i < CHAIN_RESTYPE_MAX_CONSUMERS; i++) {
		if (chain_restype_consumer_nr[kind][slot][i] >= 0)
			return true;
	}
	return false;
}

int chain_restype_pick_consumer(enum chain_resource_kind kind,
				bool do32bit_hint)
{
	unsigned int slot = do32bit_hint ? 1u : 0u;
	int live[CHAIN_RESTYPE_MAX_CONSUMERS];
	unsigned int nlive = 0;
	unsigned int i;

	if (kind >= CHAIN_RESTYPE_NR)
		return -1;

	for (i = 0; i < CHAIN_RESTYPE_MAX_CONSUMERS; i++) {
		int cand = chain_restype_consumer_nr[kind][slot][i];
		struct syscallentry *entry;

		if (cand < 0)
			continue;

		/* The resolved NR set is frozen at init time, but a NR
		 * can go inert mid-run via the self-deactivation path
		 * (ENOSYS strike-out, capability loss, TO_BE_DEACTIVATED
		 * sweep).  entry->active_number == 0 marks that state.
		 * validate_specific_syscall_silent() only rejects the
		 * static flags (AVOID/NI/NEEDS_ROOT) and will happily
		 * pass a deactivated entry, so check active_number
		 * directly here — biasing to a deactivated NR wastes the
		 * bias budget on a step the dispatch path is going to
		 * refuse anyway. */
		entry = get_syscall_entry((unsigned int)cand, do32bit_hint);
		if (entry == NULL)
			continue;
		if (entry->active_number == 0)
			continue;

		live[nlive++] = cand;
	}
	if (nlive == 0)
		return -1;
	return live[rnd_modulo_u32(nlive)];
}
