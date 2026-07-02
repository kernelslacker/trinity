#include <stdbool.h>
#include <stdint.h>

#include "args-internal.h"
#include "argtype-ops.h"
#include "debug.h"		// BUG
#include "deferred-free.h"	// deferred_free_enqueue
#include "random.h"
#include "results.h"		// pick_successful_fd
#include "sanitise.h"
#include "shm.h"
#include "struct_catalog.h"
#include "syscall.h"

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum)
{
	return entry->argtype[argnum - 1];
}



/*
 * Shared cleanup helper for any argtype whose generator hands back a
 * heap allocation that must be released after the syscall returns
 * (ARG_PATHNAME, ARG_SOCKADDR).
 *
 * Read via get_arg_snapshot() so that if the slot opted into the
 * arg_shadow mask, we free the pointer the parent's sanitiser actually
 * handed the kernel rather than whatever a sibling may have stomped
 * into rec->aN after the syscall returned -- the latter is the
 * highest-value site for a wild-free hazard, since deferred_free_enqueue
 * would otherwise feed a non-malloc pointer to the side-set gate.
 * Unopted slots fall through to the live rec->aN, matching the
 * pre-change behaviour.
 */
static void cleanup_deferred_free(struct syscallrecord *rec, unsigned int argnum)
{
	deferred_free_enqueue((void *) get_arg_snapshot(rec, argnum));
}

/*
 * Per-argtype policy descriptor table.
 *
 * Indexed by enum argtype.  Each entry concentrates everything fill_arg,
 * generic_free_arg, and blanket_address_scrub need to know about that
 * argtype: how to produce a value, how to release it afterwards, whether
 * the slot participates in the fd biases, the blanket address scrub, the
 * numeric-substitute fuzzer technique, and whether it has a paired
 * length slot that follows it in the argument list.
 */
const struct argtype_ops argtype_table[] = {
	[ARG_UNDEFINED] = {
		.name = "ARG_UNDEFINED",
		.generate = gen_undefined_arg,
	},
	[ARG_FD] = {
		.name = "ARG_FD",
		.generate = gen_arg_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_LEN] = {
		.name = "ARG_LEN",
		.generate = gen_arg_len,
	},
	[ARG_ADDRESS] = {
		.name = "ARG_ADDRESS",
		.generate = handle_arg_address,
		.default_address_scrub = true,
	},
	[ARG_MODE_T] = {
		.name = "ARG_MODE_T",
		.generate = handle_arg_mode_t,
	},
	[ARG_NON_NULL_ADDRESS] = {
		.name = "ARG_NON_NULL_ADDRESS",
		.generate = gen_arg_non_null_address,
		.default_address_scrub = true,
	},
	[ARG_PID] = {
		.name = "ARG_PID",
		.generate = gen_arg_pid,
		.accepts_numeric_substitute = true,
	},
	[ARG_KEY_SERIAL] = {
		.name = "ARG_KEY_SERIAL",
		.generate = gen_arg_key_serial,
		.accepts_numeric_substitute = true,
	},
	[ARG_TIMERID] = {
		.name = "ARG_TIMERID",
		.generate = gen_arg_timerid,
		.accepts_numeric_substitute = true,
	},
	[ARG_AIO_CTX] = {
		.name = "ARG_AIO_CTX",
		.generate = gen_arg_aio_ctx,
		.accepts_numeric_substitute = true,
	},
	[ARG_SEM_ID] = {
		.name = "ARG_SEM_ID",
		.generate = gen_arg_sem_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_MSG_ID] = {
		.name = "ARG_MSG_ID",
		.generate = gen_arg_msg_id,
		.accepts_numeric_substitute = true,
	},
	[ARG_SYSV_SHM] = {
		.name = "ARG_SYSV_SHM",
		.generate = gen_arg_sysv_shm,
		.accepts_numeric_substitute = true,
	},
	[ARG_RANGE] = {
		.name = "ARG_RANGE",
		.generate = handle_arg_range,
		.default_address_scrub = true,
	},
	[ARG_OP] = {
		.name = "ARG_OP",
		.generate = handle_arg_op,
	},
	[ARG_LIST] = {
		.name = "ARG_LIST",
		.generate = handle_arg_list,
	},
	[ARG_CPU] = {
		.name = "ARG_CPU",
		.generate = gen_arg_cpu,
	},
	[ARG_NUMA_NODE] = {
		.name = "ARG_NUMA_NODE",
		.generate = gen_arg_numa_node,
		.accepts_numeric_substitute = true,
	},
	[ARG_PATHNAME] = {
		.name = "ARG_PATHNAME",
		.generate = gen_arg_pathname,
		.cleanup = cleanup_deferred_free,
	},
	[ARG_XATTR_NAME] = {
		.name = "ARG_XATTR_NAME",
		.generate = gen_arg_xattr_name,
	},
	[ARG_FSTYPE_NAME] = {
		.name = "ARG_FSTYPE_NAME",
		.generate = gen_arg_fstype_name,
	},
	[ARG_TIMESPEC] = {
		.name = "ARG_TIMESPEC",
		.generate = gen_arg_timespec,
	},
	[ARG_ITIMERVAL] = {
		.name = "ARG_ITIMERVAL",
		.generate = gen_arg_itimerval,
	},
	[ARG_ITIMERSPEC] = {
		.name = "ARG_ITIMERSPEC",
		.generate = gen_arg_itimerspec,
	},
	[ARG_TIMEVAL] = {
		.name = "ARG_TIMEVAL",
		.generate = gen_arg_timeval,
	},
	[ARG_NODEMASK] = {
		.name = "ARG_NODEMASK",
		.generate = gen_arg_nodemask,
	},
	[ARG_CPUMASK] = {
		.name = "ARG_CPUMASK",
		.generate = gen_arg_cpumask,
	},
	[ARG_BUF_SIZED] = {
		.name = "ARG_BUF_SIZED",
		.generate = gen_arg_buf_sized,
		.paired_length = ARG_BUF_LEN,
	},
	[ARG_BUF_LEN] = {
		.name = "ARG_BUF_LEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_IOVEC] = {
		.name = "ARG_IOVEC",
		.generate = handle_arg_iovec,
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVEC_IN] = {
		.name = "ARG_IOVEC_IN",
		.generate = handle_arg_iovec_in,
		.paired_length = ARG_IOVECLEN,
	},
	[ARG_IOVECLEN] = {
		.name = "ARG_IOVECLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_SOCKADDR] = {
		.name = "ARG_SOCKADDR",
		.generate = handle_arg_sockaddr,
		.cleanup = cleanup_deferred_free,
		.paired_length = ARG_SOCKADDRLEN,
	},
	[ARG_SOCKADDRLEN] = {
		.name = "ARG_SOCKADDRLEN",
		.generate = gen_arg_paired_length,
	},
	[ARG_MMAP] = {
		.name = "ARG_MMAP",
		.generate = gen_arg_mmap,
	},
	[ARG_SOCKETINFO] = {
		.name = "ARG_SOCKETINFO",
		.generate = gen_arg_socketinfo,
	},
	[ARG_STRUCT_PTR_IN] = {
		.name = "ARG_STRUCT_PTR_IN",
		.generate = gen_arg_struct_ptr_in,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_PTR_OUT] = {
		.name = "ARG_STRUCT_PTR_OUT",
		.generate = gen_arg_struct_ptr_out,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_PTR_INOUT] = {
		.name = "ARG_STRUCT_PTR_INOUT",
		.generate = gen_arg_struct_ptr_inout,
		.paired_length = ARG_STRUCT_SIZE,
	},
	[ARG_STRUCT_SIZE] = {
		.name = "ARG_STRUCT_SIZE",
		.generate = gen_arg_struct_size,
	},
	[ARG_FD_BPF_BTF] = {
		.name = "ARG_FD_BPF_BTF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_LINK] = {
		.name = "ARG_FD_BPF_LINK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_MAP] = {
		.name = "ARG_FD_BPF_MAP",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_BPF_PROG] = {
		.name = "ARG_FD_BPF_PROG",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EPOLL] = {
		.name = "ARG_FD_EPOLL",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_EVENTFD] = {
		.name = "ARG_FD_EVENTFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FANOTIFY] = {
		.name = "ARG_FD_FANOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_FS_CTX] = {
		.name = "ARG_FD_FS_CTX",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_INOTIFY] = {
		.name = "ARG_FD_INOTIFY",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_IO_URING] = {
		.name = "ARG_FD_IO_URING",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_LANDLOCK] = {
		.name = "ARG_FD_LANDLOCK",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MEMFD] = {
		.name = "ARG_FD_MEMFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MOUNT] = {
		.name = "ARG_FD_MOUNT",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_MQ] = {
		.name = "ARG_FD_MQ",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PERF] = {
		.name = "ARG_FD_PERF",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIDFD] = {
		.name = "ARG_FD_PIDFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_PIPE] = {
		.name = "ARG_FD_PIPE",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SIGNALFD] = {
		.name = "ARG_FD_SIGNALFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_SOCKET] = {
		.name = "ARG_FD_SOCKET",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
	[ARG_FD_TIMERFD] = {
		.name = "ARG_FD_TIMERFD",
		.generate = gen_arg_typed_fd,
		.can_use_success_fd_bias = true,
		.can_use_failed_fd_filter = true,
	},
};

const unsigned int argtype_table_size =
	sizeof(argtype_table) / sizeof(argtype_table[0]);

const struct argtype_ops *argtype_get_ops(enum argtype t)
{
	if ((unsigned int) t >= argtype_table_size)
		BUG("argtype_get_ops: argtype out of range\n");
	if (argtype_table[t].generate == NULL)
		BUG("argtype_get_ops: argtype has no generator\n");
	return &argtype_table[t];
}

/*
 * Build the address-scrub slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from copy_syscall_table()
 * in tables.c; the cached mask in entry->address_scrub_mask drives
 * blanket_address_scrub() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype carries the default_address_scrub descriptor flag.
 */
uint8_t compute_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->default_address_scrub)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Bit k set means slot (k+1)'s argtype is ARG_STRUCT_PTR_IN/OUT/INOUT
 * AND the cataloged struct for that (syscall, arg) reaches an
 * FT_ADDRESS field via the pointer chain.  Resolved once at table-init
 * time so the per-dispatch nested_address_scrub() walk short-circuits
 * with a single masked load on the bulk of syscalls (no cataloged
 * struct, or no address-shaped field inside it).
 */
uint8_t compute_nested_address_scrub_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL || entry->name == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		enum argtype t = entry->argtype[i];

		if (t != ARG_STRUCT_PTR_IN &&
		    t != ARG_STRUCT_PTR_OUT &&
		    t != ARG_STRUCT_PTR_INOUT)
			continue;

		/*
		 * Discriminator-aware: any cataloged variant for this slot
		 * carrying an FT_ADDRESS field forces the bit on, because the
		 * live variant resolves per-dispatch and the mask is a
		 * conservative include.  struct_arg_lookup_by_name() returns
		 * only one descriptor and can't represent that OR-across.
		 */
		if (struct_arg_any_has_address_field(entry->name, i + 1))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the cleanup-hook slot bitmap for entry's argtype[] table.  Called
 * once per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->cleanup_arg_mask drives
 * generic_free_arg() below without re-walking argtype[] or re-running
 * argtype_get_ops() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype has a non-NULL .cleanup hook in the descriptor table.
 */
uint8_t compute_cleanup_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		const struct argtype_ops *ops = argtype_get_ops(entry->argtype[i]);

		if (ops->cleanup != NULL)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the fd-arg slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->fd_arg_mask drives the fd-scoreboard
 * update loops in handle_success() / handle_failure() (results.c) without
 * re-running is_fdarg() per slot.  Bit k (k=0..5) set means slot (k+1)'s
 * argtype is ARG_FD or any typed-fd argtype.
 */
uint8_t compute_fd_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (is_fdarg(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Build the ARG_LEN slot bitmap for entry's argtype[] table.  Called once
 * per syscallentry at table-init time from copy_syscall_table() in
 * tables.c; the cached mask in entry->len_arg_mask drives the
 * successful-length scoreboard update in handle_success() (results.c)
 * without re-running get_argtype() per slot.  Bit k (k=0..5) set means
 * slot (k+1)'s argtype is ARG_LEN.
 */
uint8_t compute_len_arg_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (entry->argtype[i] == ARG_LEN)
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Precompute arg_params[i].list.all_bits (the OR of every value in the
 * arglist) for each ARG_OP/ARG_LIST slot.  Called once per syscallentry
 * at table-init time from copy_syscall_table() in tables.c so callers
 * that need "all valid bits" (e.g. set_rand_bitmask-style boundary or
 * structured-mutation paths) can read the precomputed mask instead of
 * re-walking values[] on every invocation.  Slots whose argtype is not
 * ARG_OP/ARG_LIST own the .range union member and are left untouched.
 */
void populate_arglist_all_bits(struct syscallentry *entry)
{
	unsigned int i;

	if (entry == NULL)
		return;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		enum argtype t = entry->argtype[i];
		struct arglist *al;
		unsigned long bits = 0;
		unsigned int k;

		if (t != ARG_OP && t != ARG_LIST)
			continue;

		al = &entry->arg_params[i].list;
		if (al->values == NULL || al->num == 0) {
			al->all_bits = 0;
			continue;
		}

		for (k = 0; k < al->num; k++)
			bits |= al->values[k];

		al->all_bits = bits;
	}
}

unsigned long fill_arg(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	const struct argtype_ops *ops;
	enum argtype t;
	unsigned long val;

	if (argnum > entry->num_args)
		return 0;

	t = get_argtype(entry, argnum);
	ops = argtype_get_ops(t);

	/* Pre-generate bias: for fd-typed args, occasionally re-pick a low
	 * fd that previously succeeded for this exact (syscall, argnum)
	 * slot.  Targets the sweet spot where the kernel accepted the fd
	 * last time, so we keep exercising the post-validation path instead
	 * of bouncing off EBADF/EINVAL on a fresh random pick. */
	if (ops->can_use_success_fd_bias && RAND_BOOL()) {
		int fd = pick_successful_fd(&entry->results[argnum - 1]);

		if (fd >= 0)
			return (unsigned long) fd;
	}

	val = ops->generate(entry, rec, argnum);

	/* Central-generator coverage for the address-family argtypes.
	 *
	 * ARG_NON_NULL_ADDRESS routes through get_non_null_address() ->
	 * get_writable_address() and always returns a trinity-owned RW
	 * scratch page.  ARG_ADDRESS routes through get_address(): the
	 * ~1%-rate NULL arm, the writable-page arm (also via
	 * get_writable_address), and a previous-slot-reuse path whose
	 * +1 / +sizeof() offsets stay within the same RW page after a
	 * non-zero find_previous_arg_address result.  Any non-zero return
	 * therefore points into RW scratch, so stamp dir/owner to promote
	 * the slot out of arg_meta_addr_without_meta.
	 *
	 * Other argtypes stay at the seed defaults: NULL get_address()
	 * results carry no buffer to describe; ARG_RANGE is numeric in
	 * [low, high], not an address; ARG_UNDEFINED mints a writable
	 * address on only one of nine arms and the disambiguation is not
	 * visible from here.
	 *
	 * Publish generation == rec->arg_meta_gen + 1 so arg_meta_init's
	 * preservation gate can distinguish a fresh stamp from stale
	 * residue left by a prior dispatch whose argtype happened to
	 * write the same dir/owner bits.
	 */
	if (val != 0 && (t == ARG_ADDRESS || t == ARG_NON_NULL_ADDRESS)) {
		struct arg_slot_meta *m = &rec->arg_meta[argnum - 1];

		m->dir = ARG_DIR_INOUT;
		m->owner = ARG_OWNER_GENERIC;
		m->generation = rec->arg_meta_gen + 1;
	}

	return val;
}
