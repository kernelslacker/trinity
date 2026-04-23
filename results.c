/*
 * Routines to update the results counters
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include "debug.h"
#include "locks.h"
#include "results.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

unsigned long get_argval(struct syscallrecord *rec, unsigned int argnum)
{
	switch (argnum) {
	case 1:	return rec->a1;
	case 2:	return rec->a2;
	case 3:	return rec->a3;
	case 4:	return rec->a4;
	case 5:	return rec->a5;
	case 6:	return rec->a6;
	}
	unreachable();
}

static struct results * get_results_ptr(struct syscallentry *entry, unsigned int argnum)
{
	return &entry->results[argnum - 1];
}

static void store_successful_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;
	rlim_t lim = max_files_rlimit.rlim_cur;
	int fdmap_size = (lim == RLIM_INFINITY || lim > 1048576) ? 1048576 : (int)lim;

	if (fd < 0 || fd >= fdmap_size)
		return;

	if (results->fdmap == NULL) {
		results->fdmap = calloc(fdmap_size, sizeof(bool));
		if (results->fdmap == NULL)
			return;
	}
	results->fdmap[fd] = true;
}

static void store_successful_len(struct results *results, unsigned long value)
{
	if (!results->seen) {
		results->seen = true;
		results->min = value;
		results->max = value;
		return;
	}
	if (value < results->min)
		results->min = value;
	if (value > results->max)
		results->max = value;
}

void handle_success(struct syscallrecord *rec)
{
	struct syscallentry *entry;
	unsigned int i, call;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);
	BUG_ON(entry == NULL);

	for_each_arg(entry, i) {
		struct results *results;
		enum argtype argtype = get_argtype(entry, i);
		unsigned long value = get_argval(rec, i);

		results = get_results_ptr(entry, i);

		if (is_typed_fdarg(argtype)) {
			store_successful_fd(results, value);
			continue;
		}

		switch (argtype) {
		case ARG_FD:
			store_successful_fd(results, value);
			break;
		case ARG_LEN:
			store_successful_len(results, value);
			break;
		case ARG_UNDEFINED:
		case ARG_ADDRESS:
		case ARG_MODE_T:
		case ARG_NON_NULL_ADDRESS:
		case ARG_PID:
		case ARG_RANGE:
		case ARG_OP:
		case ARG_LIST:
		case ARG_CPU:
		case ARG_PATHNAME:
		case ARG_IOVEC:
		case ARG_IOVECLEN:
		case ARG_SOCKADDR:
		case ARG_SOCKADDRLEN:
		case ARG_MMAP:
		case ARG_SOCKETINFO:
		default:
			break;
		}
	}
}
