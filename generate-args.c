#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "arch.h"
#include "argtype-ops.h"
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "maps.h"
#include "minicorpus.h"
#include "net.h"
#include "numa.h"
#include "pathnames.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "strategy.h"	// plateau_rescue_bias_active_for, RRC_CMP_DERIVED
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// num_online_cpus

/*
 * CMP-hint injection rate.  Baseline is 1-in-16 (the historical rate the
 * ARG_OP / ARG_LIST paths shipped with); boosted to 1-in-4 inside a
 * SR_PLATEAU_FORCE intervention whose dominant rescue class is
 * RRC_CMP_DERIVED, so the learned constants the classifier credited
 * for the recent rescues fire more aggressively during the targeted
 * intervention.  Wrapped in a helper so any future tuning lands in one
 * place rather than scattered across the three call sites.
 */
#define CMP_HINT_INJECT_DENOM_BASELINE  16U
#define CMP_HINT_INJECT_DENOM_AMPLIFIED 4U

static unsigned int cmp_hint_inject_denom(void)
{
	return plateau_rescue_bias_active_for(RRC_CMP_DERIVED) ?
		CMP_HINT_INJECT_DENOM_AMPLIFIED :
		CMP_HINT_INJECT_DENOM_BASELINE;
}

/* ONE_IN denominator for substituting a wrong-subtype fd (or a generic
 * pool fd) into a typed-fd argument slot.  Trades a small fraction of
 * the precision win that typed-fd dispatch buys for coverage of the
 * wrong-fd-type bug class -- without this, a kernel type-check guard
 * sitting on the path that only fires for a mismatched fd subtype is
 * never exercised, because the consumer always hands the syscall the
 * correct subtype out of the matching obj pool. */
#define WRONG_FD_TYPE_FREQ	16

static int get_cpu(void)
{
	int i;
	i = rand() % 100;

	switch (i) {
	case 0: return -1;
	case 1: return rand() % 4096;
	case 2: return INT_MAX;
	case 3 ... 99:
		return rand() % num_online_cpus;
	}
	return 0;
}

static unsigned long handle_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long addr = 0;

	if (argnum == 1)
		return (unsigned long) get_address();

	if (RAND_BOOL())
		return (unsigned long) get_address();

	/* Half the time, we look to see if earlier args were also ARG_ADDRESS,
	 * and munge that instead of returning a new one from get_address() */

	addr = find_previous_arg_address(entry, rec, argnum);
	if (addr == 0)
		return (unsigned long) get_address();

	switch (rand() % 4) {
	case 0:	break;	/* return unmodified */
	case 1:	addr++;
		break;
	case 2:	addr+= sizeof(int);
		break;
	case 3:	addr+= sizeof(long);
		break;
	}

	return addr;
}

static unsigned long handle_arg_range(struct syscallentry *entry,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum)
{
	unsigned long i;
	unsigned long low = entry->arg_params[argnum - 1].range.low;
	unsigned long high = entry->arg_params[argnum - 1].range.hi;

	if (high == 0) {
		outputerr("%s forgets to set hirange!\n", entry->name);
		BUG("Fix syscall definition!\n");
	}

	if (low >= high) {
		outputerr("%s has invalid range: low(%lu) >= high(%lu)!\n",
			entry->name, low, high);
		BUG("Fix syscall definition!\n");
	}

	/* ~1 in 8: bias toward the range boundaries where off-by-one bugs hide */
	if (ONE_IN(8)) {
		switch (rand() % 4) {
		case 0: return low;
		case 1: return high;
		case 2: return (low < high) ? low + 1 : low;
		case 3: return (high > low) ? high - 1 : high;
		}
	}

	/* Guard against overflow: if high == ULONG_MAX, high - low + 1 wraps to 0 */
	if (high - low == ULONG_MAX)
		i = low + (unsigned long) rand64();
	else
		i = low + (unsigned long) rand64() % (high - low + 1);
	return i;
}

static void get_num_and_values(struct syscallentry *entry, unsigned int argnum,
		unsigned int *num, const unsigned long **values)
{
	*num = entry->arg_params[argnum - 1].list.num;
	*values = entry->arg_params[argnum - 1].list.values;

	if (*num == 0)
		BUG("ARG_OP/LIST with 0 args. What?\n");

	if (*values == NULL)
		BUG("ARG_OP/LIST with no values.\n");
}

/*
 * Get a single entry from the list of values.
 */
static unsigned long handle_arg_op(struct syscallentry *entry,
				   struct syscallrecord *rec,
				   unsigned int argnum)
{
	const unsigned long *values = NULL;
	unsigned int num = 0;
	unsigned int call = rec->nr;
	unsigned long hint;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 16: try a CMP hint as an undocumented command code.
	 * Bumped to ~1 in 4 inside a SR_PLATEAU_FORCE intervention whose
	 * dominant rescue class is RRC_CMP_DERIVED. */
	if (ONE_IN(cmp_hint_inject_denom()) &&
	    cmp_hints_try_get(call, &hint))
		return hint;

	return values[rand() % num];
}

/*
 * OR a random number of bits from the list of values into a bitmask, and return it.
 */
static unsigned long handle_arg_list(struct syscallentry *entry,
				     struct syscallrecord *rec,
				     unsigned int argnum)
{
	unsigned long mask = 0;
	unsigned int num = 0;
	const unsigned long *values = NULL;
	unsigned int call = rec->nr;
	unsigned long hint;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 8: OR in a shifted flag to probe for undocumented adjacent bits */
	if (ONE_IN(8)) {
		mask = set_rand_bitmask(num, values);
		mask |= shift_flag_bit(values[rand() % num]);
		return mask;
	}

	/* ~1 in 16: OR in a CMP hint as an undocumented flag bit.
	 * Bumped to ~1 in 4 inside a SR_PLATEAU_FORCE intervention whose
	 * dominant rescue class is RRC_CMP_DERIVED. */
	if (ONE_IN(cmp_hint_inject_denom()) &&
	    cmp_hints_try_get(call, &hint)) {
		mask = set_rand_bitmask(num, values);
		mask |= hint;
		return mask;
	}

	if (RAND_BOOL())
		num = min(num, 3U);

	mask = set_rand_bitmask(num, values);
	return mask;
}

static unsigned long handle_arg_iovec(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long num_entries;

	/* Each iovec entry pulls a map under a global lock, so bias toward
	 * small counts: 90% of the time pick 1-8, only occasionally exercise
	 * the larger 1-256 range. */
	if (ONE_IN(10))
		num_entries = RAND_RANGE(1, 256);
	else
		num_entries = RAND_RANGE(1, 8);

	if (argnum < 6 && entry->argtype[argnum] == ARG_IOVECLEN) {
		switch (argnum) {
		case 1:	rec->a2 = num_entries; break;
		case 2:	rec->a3 = num_entries; break;
		case 3:	rec->a4 = num_entries; break;
		case 4:	rec->a5 = num_entries; break;
		case 5:	rec->a6 = num_entries; break;
		}
	}
	return (unsigned long) alloc_iovec(num_entries);
}

static unsigned long handle_arg_sockaddr(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	struct sockaddr *sockaddr = NULL;
	socklen_t sockaddrlen = 0;

	generate_sockaddr((struct sockaddr **)&sockaddr, &sockaddrlen, PF_NOHINT);

	if (argnum < 6 && entry->argtype[argnum] == ARG_SOCKADDRLEN) {
		switch (argnum) {
		case 1:	rec->a2 = sockaddrlen; break;
		case 2:	rec->a3 = sockaddrlen; break;
		case 3:	rec->a4 = sockaddrlen; break;
		case 4:	rec->a5 = sockaddrlen; break;
		case 5:	rec->a6 = sockaddrlen; break;
		}
	}
	return (unsigned long) sockaddr;
}

static unsigned long handle_arg_mode_t(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	unsigned int i, count;
	mode_t mode = 0, op = 0;

	count = rand() % 9;

	for (i = 0; i < count; i++) {
		unsigned int j;

		j = rand() % 15;
		switch (j) {
		case  0: op = S_IRWXU; break;
		case  1: op = S_IRUSR; break;
		case  2: op = S_IWUSR; break;
		case  3: op = S_IXUSR; break;

		case  4: op = S_IRWXG; break;
		case  5: op = S_IRGRP; break;
		case  6: op = S_IWGRP; break;
		case  7: op = S_IXGRP; break;

		case  8: op = S_IRWXO; break;
		case  9: op = S_IROTH; break;
		case 10: op = S_IWOTH; break;
		case 11: op = S_IXOTH; break;

		case 12: op = S_ISUID; break;
		case 13: op = S_ISGID; break;
		case 14: op = S_ISVTX; break;
		}
		if (RAND_BOOL())
			mode |= op;
		else
			mode &= ~op;
	}
	return mode;
}

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum)
{
	return entry->argtype[argnum - 1];
}

static unsigned long gen_undefined_arg(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec,
				       unsigned int argnum __unused__)
{
	unsigned int call = rec->nr;
	unsigned long hint;

	switch (rand() % 9) {
	case 0:
		if (cmp_hints_try_get(call, &hint))
			return hint;
		return mutate_value(get_boundary_value());
	case 1: return mutate_value(get_boundary_value());
	case 2: return mutate_value(rand64());
	case 3: return get_interesting_value();
	case 4: return rand64();
	case 5: return (unsigned long) get_writable_address(page_size);
	case 6: return rand64() & rand64();	/* sparse bits (~25% set) */
	case 7: return rand64() | rand64();	/* dense bits (~75% set) */
	case 8: return get_sizeof_boundary_value();
	}
	return rand64();
}

/*
 * Thin generator wrappers used by argtype_table[].  Each one encodes the
 * body of the matching case in fill_arg's switch so the table can dispatch
 * directly off the argtype.  Where the inline case is a single expression
 * (ARG_LEN, ARG_MMAP, ARG_CPU, ...) the wrapper is one return statement.
 * Where the inline case used a pool-vs-garbage substitution (ARG_PID and
 * friends), the wrapper preserves the ~1-in-8 bias.
 */

static unsigned long gen_arg_fd(struct syscallentry *entry,
				struct syscallrecord *rec __unused__,
				unsigned int argnum)
{
	struct results *results = &entry->results[argnum - 1];
	bool filter;
	int fd = 0;
	int tries;

	/* Prefer live fds returned by recent syscalls (70% of the time). */
	if (rand() % 10 < 7) {
		struct childdata *child = this_child();

		if (child != NULL) {
			int live_fd = get_child_live_fd(child);

			if (live_fd >= 0)
				return live_fd;
		}
	}
	if (RAND_BOOL()) {
		unsigned int i;
		/* If this is the 2nd or more ARG_FD, make it unique */
		for (i = 1; i < argnum; i++) {
			enum argtype arg;
			arg = get_argtype(entry, i);
			if (arg == ARG_FD)
				return get_new_random_fd();
		}
	}

	/* Same failed_fds re-roll bias as the typed-fd path. */
	filter = (rand() % 10) < 7;
	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = get_random_fd();
		if (!filter || !fd_recently_failed(results, fd))
			break;
	}
	return (unsigned long) fd;
}

static unsigned long gen_arg_typed_fd(struct syscallentry *entry,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum)
{
	enum argtype argtype = get_argtype(entry, argnum);
	struct results *results = &entry->results[argnum - 1];
	bool filter = (rand() % 10) < 7;
	enum argtype effective_argtype = argtype;
	bool use_generic = false;
	int fd = 0;
	int tries;

	/* With ~1/WRONG_FD_TYPE_FREQ probability, swap the requested typed-fd
	 * subtype for a different one (or, less often, a generic fd from the
	 * global pool) before entering the reroll loop.  The swap is sticky
	 * across rerolls so the failed-fd filter still has a chance to drop
	 * known-bad (slot, fd) pairs for whatever fd source we ended up with. */
	if (ONE_IN(WRONG_FD_TYPE_FREQ)) {
		__atomic_fetch_add(&shm->stats.wrong_fd_type_substitutions,
				   1UL, __ATOMIC_RELAXED);
		if (ONE_IN(4)) {
			use_generic = true;
			__atomic_fetch_add(&shm->stats.wrong_fd_type_subst_generic,
					   1UL, __ATOMIC_RELAXED);
		} else {
			unsigned int range = ARG_FD_TIMERFD - ARG_FD_BPF_BTF;
			unsigned int pick = rand() % range;

			effective_argtype = ARG_FD_BPF_BTF + pick;
			if (effective_argtype >= argtype)
				effective_argtype++;
		}
	}

	for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
		fd = use_generic ? get_random_fd()
				 : get_typed_fd(effective_argtype);
		if (!filter || !fd_recently_failed(results, fd))
			break;
	}
	return (unsigned long) fd;
}

static unsigned long gen_arg_len(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	return (unsigned long) get_len();
}

static unsigned long gen_arg_non_null_address(struct syscallentry *entry __unused__,
					      struct syscallrecord *rec __unused__,
					      unsigned int argnum __unused__)
{
	return (unsigned long) get_non_null_address();
}

static unsigned long gen_arg_mmap(struct syscallentry *entry __unused__,
				  struct syscallrecord *rec __unused__,
				  unsigned int argnum __unused__)
{
	return (unsigned long) get_map();
}

static unsigned long gen_arg_pid(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_pid_from_pool();
}

static unsigned long gen_arg_key_serial(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_key_serial();
}

static unsigned long gen_arg_timerid(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int32_t) rand32();
	return (unsigned long) get_random_timerid();
}

static unsigned long gen_arg_aio_ctx(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) rand64();
	return get_random_aio_ctx();
}

static unsigned long gen_arg_sem_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec __unused__,
				    unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_sem();
}

static unsigned long gen_arg_msg_id(struct syscallentry *entry __unused__,
				    struct syscallrecord *rec __unused__,
				    unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_msg();
}

static unsigned long gen_arg_sysv_shm(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (int) rand32();
	return (unsigned long) get_random_sysv_shm();
}

static unsigned long gen_arg_cpu(struct syscallentry *entry __unused__,
				 struct syscallrecord *rec __unused__,
				 unsigned int argnum __unused__)
{
	return (unsigned long) get_cpu();
}

static unsigned long gen_arg_numa_node(struct syscallentry *entry __unused__,
				       struct syscallrecord *rec __unused__,
				       unsigned int argnum __unused__)
{
	if (ONE_IN(8))
		return (unsigned long) (rand32() & 0xFFFF);
	return (unsigned long) random_numa_node();
}

static unsigned long gen_arg_pathname(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	return (unsigned long) generate_pathname();
}

/* ARG_IOVECLEN / ARG_SOCKADDRLEN: the value was published into the slot
 * by the paired ARG_IOVEC / ARG_SOCKADDR generator that ran earlier in
 * this dispatch.  Just hand it back. */
static unsigned long gen_arg_paired_length(struct syscallentry *entry __unused__,
					   struct syscallrecord *rec,
					   unsigned int argnum)
{
	return get_argval(rec, argnum);
}

static unsigned long gen_arg_socketinfo(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	return (unsigned long) get_rand_socketinfo();
}

/*
 * Shared cleanup helper for any argtype whose generator hands back a
 * heap allocation that must be released after the syscall returns
 * (ARG_PATHNAME, ARG_IOVEC, ARG_SOCKADDR).
 */
static void cleanup_deferred_free(struct syscallrecord *rec, unsigned int argnum)
{
	deferred_free_enqueue((void *) get_argval(rec, argnum), NULL);
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
	[ARG_IOVEC] = {
		.name = "ARG_IOVEC",
		.generate = handle_arg_iovec,
		.cleanup = cleanup_deferred_free,
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

static unsigned long fill_arg(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum)
{
	enum argtype argtype;

	if (argnum > entry->num_args)
		return 0;

	argtype = get_argtype(entry, argnum);

	/* For fd-typed args, occasionally re-pick a low fd that previously
	 * succeeded for this exact (syscall, argnum) slot.  Targets the
	 * sweet spot where the kernel accepted the fd last time, so we keep
	 * exercising the post-validation path instead of bouncing off
	 * EBADF/EINVAL on a fresh random pick. */
	if (is_fdarg(argtype) && RAND_BOOL()) {
		int fd = pick_successful_fd(&entry->results[argnum - 1]);

		if (fd >= 0)
			return (unsigned long) fd;
	}

	/* Inverse of the success-bias above: with 70% probability, reject
	 * candidates whose bit is set in this slot's failed_fds bitmap and
	 * re-roll, up to FAILED_FD_REROLL_LIMIT times.  After that we fall
	 * through with whatever the last roll returned, so the explored fd
	 * space is never strictly closed off. */
	if (is_typed_fdarg(argtype)) {
		struct results *results = &entry->results[argnum - 1];
		bool filter = (rand() % 10) < 7;
		enum argtype effective_argtype = argtype;
		bool use_generic = false;
		int fd = 0;
		int tries;

		/* With ~1/WRONG_FD_TYPE_FREQ probability, swap the requested
		 * typed-fd subtype for a different one (or, less often, a
		 * generic fd from the global pool) before entering the reroll
		 * loop.  The swap is sticky across rerolls so the failed-fd
		 * filter still has a chance to drop known-bad (slot, fd)
		 * pairs for whatever fd source we ended up with. */
		if (ONE_IN(WRONG_FD_TYPE_FREQ)) {
			__atomic_fetch_add(&shm->stats.wrong_fd_type_substitutions,
					   1UL, __ATOMIC_RELAXED);
			if (ONE_IN(4)) {
				use_generic = true;
				__atomic_fetch_add(&shm->stats.wrong_fd_type_subst_generic,
						   1UL, __ATOMIC_RELAXED);
			} else {
				/* Pick uniformly from the ARG_FD_BPF_BTF .. ARG_FD_TIMERFD
				 * range excluding the requested argtype: sample one of
				 * the (range) other slots, then bump past argtype if
				 * we landed at-or-above it. */
				unsigned int range = ARG_FD_TIMERFD - ARG_FD_BPF_BTF;
				unsigned int pick = rand() % range;

				effective_argtype = ARG_FD_BPF_BTF + pick;
				if (effective_argtype >= argtype)
					effective_argtype++;
			}
		}

		for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
			fd = use_generic ? get_random_fd()
					 : get_typed_fd(effective_argtype);
			if (!filter || !fd_recently_failed(results, fd))
				break;
		}
		return (unsigned long) fd;
	}

	switch (argtype) {
	case ARG_UNDEFINED:
		return gen_undefined_arg(entry, rec, argnum);

	case ARG_FD: {
		struct results *results = &entry->results[argnum - 1];
		bool filter;
		int fd = 0;
		int tries;

		/* Prefer live fds returned by recent syscalls (70% of the time). */
		if (rand() % 10 < 7) {
			struct childdata *child = this_child();

			if (child != NULL) {
				int live_fd = get_child_live_fd(child);

				if (live_fd >= 0)
					return live_fd;
			}
		}
		if (RAND_BOOL()) {
			unsigned int i;
			/* If this is the 2nd or more ARG_FD, make it unique */
			for (i = 1; i < argnum; i++) {
				enum argtype arg;
				arg = get_argtype(entry, i);
				if (arg == ARG_FD)
					return get_new_random_fd();
			}
		}

		/* Same failed_fds re-roll bias as the typed-fd path above. */
		filter = (rand() % 10) < 7;
		for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
			fd = get_random_fd();
			if (!filter || !fd_recently_failed(results, fd))
				break;
		}
		return (unsigned long) fd;
	}

	case ARG_LEN:
		return (unsigned long) get_len();

	case ARG_ADDRESS:
		return handle_arg_address(entry, rec, argnum);

	case ARG_NON_NULL_ADDRESS:
		return (unsigned long) get_non_null_address();

	case ARG_MMAP:
		return (unsigned long) get_map();

	case ARG_PID:
		/* ~1 in 8: pass garbage to keep the ARG_PID consumers
		 * (kill, tkill, tgkill, ptrace, setpgid, getpgid, getsid,
		 * setpriority, getpriority, waitpid, wait4, sched_set...,
		 * sched_get..., perf_event_open, ...) hitting their
		 * input-validation paths; otherwise pull a pid from the
		 * producer-fed OBJ_PID pool fed by fork, vfork, clone,
		 * clone3, getpid, gettid, getppid.  Cold-pool fallback
		 * defers to get_pid()'s live-children bias inside
		 * get_random_pid_from_pool. */
		if (ONE_IN(8))
			return (unsigned long) (int32_t) rand32();
		return (unsigned long) get_random_pid_from_pool();

	case ARG_KEY_SERIAL:
		/* ~1 in 8: pass garbage to keep keyctl/add_key/request_key
		 * input-validation paths exercised; otherwise pull a serial
		 * from the producer-fed OBJ_KEY_SERIAL pool. */
		if (ONE_IN(8))
			return (unsigned long) (int32_t) rand32();
		return (unsigned long) get_random_key_serial();

	case ARG_TIMERID:
		/* ~1 in 8: pass garbage to keep timer_settime/_gettime/
		 * _getoverrun/_delete input-validation paths exercised;
		 * otherwise pull a tid from the producer-fed OBJ_TIMERID
		 * pool fed by timer_create. */
		if (ONE_IN(8))
			return (unsigned long) (int32_t) rand32();
		return (unsigned long) get_random_timerid();

	case ARG_AIO_CTX:
		/* ~1 in 8: pass garbage to keep io_submit/io_getevents/
		 * io_pgetevents/io_destroy/io_cancel input-validation paths
		 * exercised; otherwise pull a context from the producer-fed
		 * OBJ_AIO_CTX pool fed by io_setup. */
		if (ONE_IN(8))
			return (unsigned long) rand64();
		return get_random_aio_ctx();

	case ARG_SEM_ID:
		/* ~1 in 8: pass garbage to keep semctl/semop/semtimedop
		 * input-validation paths exercised; otherwise pull a semid
		 * from the producer-fed OBJ_SYSV_SEM pool fed by semget. */
		if (ONE_IN(8))
			return (unsigned long) (int) rand32();
		return (unsigned long) get_random_sysv_sem();

	case ARG_MSG_ID:
		/* ~1 in 8: pass garbage to keep msgctl/msgsnd/msgrcv
		 * input-validation paths exercised; otherwise pull a msqid
		 * from the producer-fed OBJ_SYSV_MSG pool fed by msgget. */
		if (ONE_IN(8))
			return (unsigned long) (int) rand32();
		return (unsigned long) get_random_sysv_msg();

	case ARG_SYSV_SHM:
		/* ~1 in 8: pass garbage to keep shmat/shmctl input-
		 * validation paths exercised; otherwise pull a shmid from
		 * the producer-fed OBJ_SYSV_SHM pool fed by shmget. */
		if (ONE_IN(8))
			return (unsigned long) (int) rand32();
		return (unsigned long) get_random_sysv_shm();

	case ARG_RANGE:
		return handle_arg_range(entry, rec, argnum);

	case ARG_OP:	/* Like ARG_LIST, but just a single value. */
		return handle_arg_op(entry, rec, argnum);

	case ARG_LIST:
		return handle_arg_list(entry, rec, argnum);

	case ARG_CPU:
		return (unsigned long) get_cpu();

	case ARG_NUMA_NODE:
		/* ~1 in 8: emit a wild small int so the kernel's
		 * nodes_valid / MAX_NUMNODES bound checks in mm/mempolicy.c
		 * stay exercised; otherwise pull a real online node id from
		 * the pool seeded at startup from
		 * /sys/devices/system/node/online. */
		if (ONE_IN(8))
			return (unsigned long) (rand32() & 0xFFFF);
		return (unsigned long) random_numa_node();

	case ARG_PATHNAME:
		return (unsigned long) generate_pathname();

	case ARG_IOVEC:
		return handle_arg_iovec(entry, rec, argnum);

	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
		/* We already set the len in the ARG_IOVEC/ARG_SOCKADDR case
		 * So here we just return what we had set there. */
		return get_argval(rec, argnum);

	case ARG_SOCKADDR:
		return handle_arg_sockaddr(entry, rec, argnum);

	case ARG_MODE_T:
		return handle_arg_mode_t(entry, rec, argnum);

	case ARG_SOCKETINFO:
		return (unsigned long) get_rand_socketinfo();

	default:
		outputerr("fill_arg: unhandled argtype %d for syscall %s (nr %d) arg %d\n",
			argtype, entry->name, rec->nr, argnum);
		break;
	}

	BUG("unreachable!\n");
}

/* Default-on scrub: any ARG_ADDRESS/ARG_NON_NULL_ADDRESS slot left
 * aliasing shared_regions or the libc heap arena gets redirected to
 * a writable address before the syscall is issued. Catches the
 * coverage-gap class where per-syscall sanitisers either don't call
 * avoid_shared_buffer() or miss specific slots. Length default is
 * page_size (conservative; bare ARG_ADDRESS carries no length info
 * and walking adjacent slots per dispatch is too expensive). */
static void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	unsigned int i;
	for (i = 1; i <= entry->num_args; i++) {
		enum argtype t = entry->argtype[i - 1];
		if (t != ARG_ADDRESS && t != ARG_NON_NULL_ADDRESS && t != ARG_RANGE)
			continue;
		unsigned long *slot;
		switch (i) {
		case 1: slot = &rec->a1; break;
		case 2: slot = &rec->a2; break;
		case 3: slot = &rec->a3; break;
		case 4: slot = &rec->a4; break;
		case 5: slot = &rec->a5; break;
		case 6: slot = &rec->a6; break;
		default: continue;
		}
		avoid_shared_buffer(slot, page_size);
	}
}

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec)
{
	/* Defensive: zero arg slots so any ARG_UNDEFINED entry doesn't
	 * inherit stale values from the previous syscall's record.  Also
	 * zero the post_state snapshot slot — sanitisers that use it
	 * allocate fresh in this dispatch, and a stale value left by a
	 * previous syscall (e.g. one whose post handler did not reach the
	 * deferred_freeptr) would otherwise survive into a post handler
	 * that now reads it as a live pointer.
	 *
	 * Only zero the slots that won't be overwritten below by fill_arg();
	 * the bulk memset of all six was wasted work for the common case of
	 * 4-6 argument syscalls. Switch fall-through unrolls the per-slot
	 * zero so the compiler can pick an efficient sequence. */
	switch (entry->num_args) {
	case 0: rec->a1 = 0; /* fall through */
	case 1: rec->a2 = 0; /* fall through */
	case 2: rec->a3 = 0; /* fall through */
	case 3: rec->a4 = 0; /* fall through */
	case 4: rec->a5 = 0; /* fall through */
	case 5: rec->a6 = 0; /* fall through */
	default: break;
	}
	rec->post_state = 0;

	/* num_args is the authority for which slots are present.
	 * Don't gate on argtype[i] != 0 — ARG_UNDEFINED is enum value 0,
	 * which would silently skip filling those slots even though
	 * fill_arg() handles ARG_UNDEFINED by returning a random value. */
	if (entry->num_args >= 1)
		rec->a1 = fill_arg(entry, rec, 1);
	if (entry->num_args >= 2)
		rec->a2 = fill_arg(entry, rec, 2);
	if (entry->num_args >= 3)
		rec->a3 = fill_arg(entry, rec, 3);
	if (entry->num_args >= 4)
		rec->a4 = fill_arg(entry, rec, 4);
	if (entry->num_args >= 5)
		rec->a5 = fill_arg(entry, rec, 5);
	if (entry->num_args >= 6)
		rec->a6 = fill_arg(entry, rec, 6);
}

void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec)
{
	unsigned int i;

	BUG_ON(entry == NULL);

	for_each_arg(entry, i) {
		enum argtype argtype;

		argtype = get_argtype(entry, i);

		if (argtype == ARG_PATHNAME)
			deferred_free_enqueue((void *) get_argval(rec, i), NULL);

		if (argtype == ARG_IOVEC)
			deferred_free_enqueue((void *) get_argval(rec, i), NULL);

		if (argtype == ARG_SOCKADDR)
			deferred_free_enqueue((void *) get_argval(rec, i), NULL);
	}
}

void generate_syscall_args(struct syscallrecord *rec)
{
	struct syscallentry *entry;

	lock(&rec->lock);

	entry = get_syscall_entry(rec->nr, rec->do32bit);
	rec->state = PREP;

	/* Reset post_state on every syscall step, before any branch.
	 * generic_sanitise() also clears it, but the minicorpus-replay
	 * path below skips generic_sanitise entirely; without this hoist,
	 * a sanitise-less syscall whose prior post handler did not reach
	 * deferred_freeptr would leave a stale pointer in post_state for
	 * the next syscall's post handler to dereference. */
	rec->post_state = 0;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		blanket_address_scrub(entry, rec);
		unlock(&rec->lock);
		return;
	}

	generic_sanitise(entry, rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);
	blanket_address_scrub(entry, rec);

	unlock(&rec->lock);
}
