/*
 * Struct-catalog registration + (nr, arg) lookup.
 *
 * Carved out of struct_catalog/catalog.c: this TU owns the mapping
 * from a fuzzed syscall dispatch to the struct_desc that describes
 * the argument's payload, plus the fast nr-indexed lookup built at
 * init time.
 *
 * The slot_binding pool + desc_by_nr_64/32[] sizing bounds
 * (SLOT_POOL_MAX, DISCRIM_VARIANTS_PER_SLOT_MAX) BUG on overflow
 * rather than silently drop mappings.
 *
 * Three public resolvers:
 *   - struct_arg_lookup: rec-driven (nr, arg) with discriminator match.
 *   - struct_arg_lookup_two_key: explicit (name, arg, k1, k2).
 *   - struct_arg_lookup_by_name: discriminator-blind default.
 */

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sched.h>
#include <utime.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
#include <linux/capability.h>
#include <linux/netfilter.h>
#include <linux/futex.h>
#include <linux/rseq.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>
#include <linux/kexec.h>
#include <linux/landlock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * include/kernel headers define those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede the kernel fallback header;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_CAN
#include <linux/can.h>
#endif
#ifdef USE_RXRPC
#include <linux/rxrpc.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_ATALK
#include <linux/atalk.h>
#endif
#ifdef USE_ATM
#include <linux/atm.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
#endif
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>
#endif

#include "argtype-ops.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#ifdef X86
#include <asm/ldt.h>		/* struct user_desc -- modify_ldt arg2 */
#endif
#include "debug.h"
#include "perf.h"		/* random_tracepoint_config -- FT_PICKER for TRACEPOINT.config */
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"


#include "kernel/fcntl.h"
#include "kernel/l2tp.h"
#include "kernel/seccomp.h"
#include "kernel/in.h"
#include "kernel/sctp.h"
/* ------------------------------------------------------------------ */
/* Syscall -> struct arg mapping -- composition root                    */
/* ------------------------------------------------------------------ */

/*
 * Every syscall_struct_arg row now lives in a per-domain array under
 * struct_catalog/registry/.  This table names them; consumers iterate
 * via FOR_EACH_SYSCALL_STRUCT_ARG(g, sa).  A row's identity is
 * (syscall_name, arg_idx) plus any discriminator keys, so re-ordering
 * groups here is safe: no two rows across groups share the same key.
 */
extern const struct syscall_struct_arg struct_catalog_registry_time[];
extern const struct syscall_struct_arg struct_catalog_registry_io_uring[];
extern const struct syscall_struct_arg struct_catalog_registry_sched[];
extern const struct syscall_struct_arg struct_catalog_registry_bpf[];
extern const struct syscall_struct_arg struct_catalog_registry_net[];
extern const struct syscall_struct_arg struct_catalog_registry_fs[];
extern const struct syscall_struct_arg struct_catalog_registry_process[];
extern const struct syscall_struct_arg struct_catalog_registry_misc[];

const struct syscall_struct_arg_group syscall_struct_arg_groups[] = {
	{ struct_catalog_registry_time },
	{ struct_catalog_registry_io_uring },
	{ struct_catalog_registry_sched },
	{ struct_catalog_registry_bpf },
	{ struct_catalog_registry_net },
	{ struct_catalog_registry_fs },
	{ struct_catalog_registry_process },
	{ struct_catalog_registry_misc },
	{ NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr_64[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * desc_by_nr_32[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * Populated at init time by scanning the active syscall table.
 * Split to avoid collisions when biarch builds have different syscall
 * numbers for 32-bit and 64-bit that happen to overlap.
 *
 * Each non-NULL cell points into slot_pool[] and groups every
 * registration for that (nr, arg_idx): one optional default entry plus
 * any discriminator variants.  struct_arg_lookup() walks the variants
 * (rec required) first and falls back to the default; a slot with
 * neither a default nor a matching variant returns NULL.
 */
/*
 * Per-slot discriminated variant cap.  Bumped 8 -> 32 ahead of the
 * setsockopt (level, optname) two-key rows: arg4 will accrete one
 * binding per cataloged optval shape, and even the proof batch
 * (linger / timeval / ip_mreqn / ipv6_mreq / packet_mreq) consumes
 * five slots before any of the higher-leverage shapes (sctp / mptcp /
 * tcp_repair) land.  Init BUG()s on overflow, so the cap MUST be raised
 * before any setsockopt rows -- a deferred bump turns the first
 * registration past 8 into a hard boot failure.
 */
#define DISCRIM_VARIANTS_PER_SLOT_MAX	32

struct slot_binding {
	const struct struct_desc	*default_desc;
	const struct syscall_struct_arg	*discrim[DISCRIM_VARIANTS_PER_SLOT_MAX];
	unsigned int			 num_discrim;
};

/*
 * Slot-binding pool.  Sized for every registered (nr, arg) cell across
 * both arch tables -- syscall_struct_args[] is ~60 entries today, so 256
 * leaves growth headroom and stays comfortably under any reasonable
 * static budget.  struct_catalog_init() BUG()s if a registration
 * overflows either the pool or the per-slot variant cap rather than
 * silently dropping mappings.
 */
#define SLOT_POOL_MAX			256

static struct slot_binding slot_pool[SLOT_POOL_MAX];
static unsigned int slot_pool_used;

static const struct slot_binding *desc_by_nr_64[MAX_NR_SYSCALL][6];
static const struct slot_binding *desc_by_nr_32[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec)
{
	const struct slot_binding *b;
	unsigned int i;

	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	b = do32bit ? desc_by_nr_32[nr][arg_idx - 1]
		    : desc_by_nr_64[nr][arg_idx - 1];
	if (b == NULL)
		return NULL;

	/*
	 * Discriminated variants are consulted only when the caller has a
	 * live syscall record to read sibling args off.  No rec, or no
	 * discriminated entries registered, falls straight through to the
	 * default desc -- the byte-identical pre-discriminator path.
	 */
	if (rec != NULL && b->num_discrim != 0) {
		for (i = 0; i < b->num_discrim; i++) {
			const struct syscall_struct_arg *sa = b->discrim[i];
			unsigned long raw;

			if (!read_rec_arg(rec, sa->discrim_arg_idx, &raw))
				continue;
			if (!discrim_key_matches(raw, sa->discrim_shift,
						 sa->discrim_mask,
						 sa->discrim_value,
						 sa->discrim_values,
						 sa->num_discrim_values))
				continue;
			/*
			 * Key2 only participates when the entry declares one
			 * (discrim2_arg_idx != 0); single-key rows leave
			 * key2 a no-op and stay byte-identical to the
			 * pre-extension path.  Both keys must match.
			 */
			if (!discrim_key2_matches(sa, rec))
				continue;
			return sa->desc;
		}
	}
	return b->default_desc;
}

const struct struct_desc *struct_arg_lookup_two_key(const char *name,
						    unsigned int arg_idx,
						    unsigned long k1,
						    unsigned long k2)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;

	/*
	 * Linear scan keeps the cost identical to struct_arg_lookup_by_name
	 * and avoids a second nr-indexed table just for explicit-key
	 * callers.  The registration table is small (~70 entries today); the
	 * scan runs once per apply_sockopt_entry call which already does
	 * O(table) work picking a random row.
	 *
	 * Skip rows with no second key registered: this entry point is for
	 * genuine two-key resolution -- a single-key row would resolve to
	 * different semantics on its own and a caller wanting that should
	 * use struct_arg_lookup() (rec-path) or struct_arg_lookup_by_name
	 * (discriminator-blind) instead.
	 */
	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (sa->discrim_arg_idx == 0 || sa->discrim2_arg_idx == 0)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (!discrim_key_matches(k1, sa->discrim_shift, sa->discrim_mask,
					 sa->discrim_value, sa->discrim_values,
					 sa->num_discrim_values))
			continue;
		if (!discrim_key_matches(k2, sa->discrim2_shift,
					 sa->discrim2_mask,
					 sa->discrim2_value,
					 sa->discrim2_values,
					 sa->num_discrim2_values))
			continue;
		return sa->desc;
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;
	const struct struct_desc *first = NULL;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	/*
	 * Prefer the slot's default (non-discriminated) entry; fall back to
	 * the first discriminated variant when no default is registered.
	 * Callers that need OR-across-all-variants semantics (e.g. the
	 * nested-address-scrub mask) use struct_arg_any_has_address_field()
	 * below -- single-desc returns can't represent that question.
	 */
	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (sa->discrim_arg_idx == 0)
			return sa->desc;
		if (first == NULL)
			first = sa->desc;
	}
	return first;
}

/*
 * Allocate (or fetch) the slot_binding cell at table[nr][arg_idx-1].
 * Pool growth is bounded by SLOT_POOL_MAX; running out is a hard
 * configuration error (caller forgot to bump the cap when extending
 * the registration table), not a runtime degradation, so BUG() rather
 * than silently dropping mappings.
 */
static struct slot_binding *
slot_binding_get(const struct slot_binding *table[MAX_NR_SYSCALL][6],
		 unsigned int nr, unsigned int arg_idx)
{
	struct slot_binding *b;

	if (table[nr][arg_idx - 1] != NULL)
		return (struct slot_binding *) table[nr][arg_idx - 1];

	if (slot_pool_used >= SLOT_POOL_MAX) {
		output(0, "struct_catalog: SLOT_POOL_MAX (%u) exhausted at "
		       "(nr=%u, arg=%u) -- raise SLOT_POOL_MAX or trim "
		       "syscall_struct_args[]\n",
		       (unsigned int) SLOT_POOL_MAX, nr, arg_idx);
		BUG("struct_catalog: SLOT_POOL_MAX exhausted");
	}
	b = &slot_pool[slot_pool_used++];
	b->default_desc = NULL;
	b->num_discrim = 0;
	table[nr][arg_idx - 1] = b;
	return b;
}

/*
 * Attach one syscall_struct_args[] entry to its (nr, arg_idx) binding.
 * Default entries write through to slot_binding::default_desc;
 * discriminated entries push into the variant list in registration
 * order so the lookup walk's first-match semantic matches the source
 * declaration order.  Multiple defaults for the same slot are a
 * registration bug; BUG() so the conflict surfaces at init rather than
 * silently leaking the later-registered desc into the lookup.
 */
static void slot_binding_attach(const struct slot_binding *table[MAX_NR_SYSCALL][6],
				unsigned int nr,
				const struct syscall_struct_arg *sa)
{
	struct slot_binding *b = slot_binding_get(table, nr, sa->arg_idx);

	if (sa->discrim_arg_idx == 0) {
		if (b->default_desc != NULL) {
			output(0, "struct_catalog: duplicate default "
			       "registration for (%s, arg %u)\n",
			       sa->syscall_name, sa->arg_idx);
			BUG("struct_catalog: duplicate default registration");
		}
		b->default_desc = sa->desc;
		return;
	}
	if (b->num_discrim >= DISCRIM_VARIANTS_PER_SLOT_MAX) {
		output(0, "struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX (%u) "
		       "exhausted for (%s, arg %u) -- raise the cap or "
		       "collapse variants\n",
		       (unsigned int) DISCRIM_VARIANTS_PER_SLOT_MAX,
		       sa->syscall_name, sa->arg_idx);
		BUG("struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX exhausted");
	}
	b->discrim[b->num_discrim++] = sa;
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	/*
	 * Holes are zero-init struct_desc slots with .name == NULL --
	 * a sign of a typo'd [SC_X] designator above the slot, or of an
	 * SC_X enum constant added without a matching catalog entry.
	 * Catch it on first init rather than letting the dispatch path
	 * deref a half-zeroed struct_desc.
	 */
	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (struct_catalog[i].name == NULL) {
			outputerr("struct_catalog: hole at slot %u "
				  "(missing [SC_X] designator)\n", i);
			BUG("struct_catalog: hole in catalog array");
		}
	}

	validate_syscall_struct_args();

	memset(desc_by_nr_64, 0, sizeof(desc_by_nr_64));
	memset(desc_by_nr_32, 0, sizeof(desc_by_nr_32));
	slot_pool_used = 0;

	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL) {
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
			}
		}
	}

	for (i = 0; i < SC_NR_ENTRIES; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
