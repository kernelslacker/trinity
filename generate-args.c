#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "arch.h"
#include "cmp_hints.h"
#include "debug.h"
#include "deferred-free.h"
#include "fd.h"
#include "maps.h"
#include "minicorpus.h"
#include "net.h"
#include "pathnames.h"
#include "random.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"	// num_online_cpus

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

static unsigned long handle_arg_address(struct syscallrecord *rec, unsigned int argnum)
{
	unsigned long addr = 0;

	if (argnum == 1)
		return (unsigned long) get_address();

	if (RAND_BOOL())
		return (unsigned long) get_address();

	/* Half the time, we look to see if earlier args were also ARG_ADDRESS,
	 * and munge that instead of returning a new one from get_address() */

	addr = find_previous_arg_address(rec, argnum);
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

static unsigned long handle_arg_range(struct syscallentry *entry, unsigned int argnum)
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
static unsigned long handle_arg_op(struct syscallentry *entry, unsigned int argnum, unsigned int call)
{
	const unsigned long *values = NULL;
	unsigned int num = 0;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 16: try a CMP hint as an undocumented command code. */
	if (ONE_IN(16) && cmp_hints_available(call))
		return cmp_hints_get(call);

	return values[rand() % num];
}

/*
 * OR a random number of bits from the list of values into a bitmask, and return it.
 */
static unsigned long handle_arg_list(struct syscallentry *entry, unsigned int argnum, unsigned int call)
{
	unsigned long mask = 0;
	unsigned int num = 0;
	const unsigned long *values = NULL;

	get_num_and_values(entry, argnum, &num, &values);

	/* ~1 in 8: OR in a shifted flag to probe for undocumented adjacent bits */
	if (ONE_IN(8)) {
		mask = set_rand_bitmask(num, values);
		mask |= shift_flag_bit(values[rand() % num]);
		return mask;
	}

	/* ~1 in 16: OR in a CMP hint as an undocumented flag bit. */
	if (ONE_IN(16) && cmp_hints_available(call)) {
		mask = set_rand_bitmask(num, values);
		mask |= cmp_hints_get(call);
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

static unsigned long handle_arg_mode_t(void)
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

static unsigned long gen_undefined_arg(unsigned int call)
{
	switch (rand() % 9) {
	case 0:
		if (cmp_hints_available(call))
			return cmp_hints_get(call);
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

static unsigned long fill_arg(struct syscallrecord *rec, unsigned int argnum)
{
	struct syscallentry *entry;
	unsigned int call;
	enum argtype argtype;

	call = rec->nr;
	entry = syscalls[call].entry;

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
		int fd = 0;
		int tries;

		for (tries = 0; tries < FAILED_FD_REROLL_LIMIT; tries++) {
			fd = get_typed_fd(argtype);
			if (!filter || !fd_recently_failed(results, fd))
				break;
		}
		return (unsigned long) fd;
	}

	switch (argtype) {
	case ARG_UNDEFINED:
		return gen_undefined_arg(call);

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
		return handle_arg_address(rec, argnum);

	case ARG_NON_NULL_ADDRESS:
		return (unsigned long) get_non_null_address();

	case ARG_MMAP:
		return (unsigned long) get_map();

	case ARG_PID:
		return (unsigned long) get_pid();

	case ARG_RANGE:
		return handle_arg_range(entry, argnum);

	case ARG_OP:	/* Like ARG_LIST, but just a single value. */
		return handle_arg_op(entry, argnum, call);

	case ARG_LIST:
		return handle_arg_list(entry, argnum, call);

	case ARG_CPU:
		return (unsigned long) get_cpu();

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
		return handle_arg_mode_t();

	case ARG_SOCKETINFO:
		return (unsigned long) get_rand_socketinfo();

	default:
		outputerr("fill_arg: unhandled argtype %d for syscall %s (nr %d) arg %d\n",
			argtype, entry->name, call, argnum);
		break;
	}

	BUG("unreachable!\n");
}

void generic_sanitise(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int call;

	call = rec->nr;
	entry = syscalls[call].entry;

	/* Defensive: zero arg slots so any ARG_UNDEFINED entry doesn't
	 * inherit stale values from the previous syscall's record. */
	memset(&rec->a1, 0, 6 * sizeof(unsigned long));

	if (entry->argtype[0] != 0)
		rec->a1 = fill_arg(rec, 1);
	if (entry->argtype[1] != 0)
		rec->a2 = fill_arg(rec, 2);
	if (entry->argtype[2] != 0)
		rec->a3 = fill_arg(rec, 3);
	if (entry->argtype[3] != 0)
		rec->a4 = fill_arg(rec, 4);
	if (entry->argtype[4] != 0)
		rec->a5 = fill_arg(rec, 5);
	if (entry->argtype[5] != 0)
		rec->a6 = fill_arg(rec, 6);
}

void generic_free_arg(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int i, call;

	call = rec->nr;

	entry = get_syscall_entry(call, rec->do32bit);
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

	entry = syscalls[rec->nr].entry;
	rec->state = PREP;

	/* For syscalls without sanitise callbacks, try replaying a
	 * saved arg set from the mini-corpus. If replay succeeds,
	 * skip generic_sanitise — the args are already populated. */
	if (entry->sanitise == NULL && minicorpus_replay(rec)) {
		rec->rettype = entry->rettype;
		unlock(&rec->lock);
		return;
	}

	generic_sanitise(rec);
	rec->rettype = entry->rettype;
	if (entry->sanitise)
		entry->sanitise(rec);

	unlock(&rec->lock);
}
