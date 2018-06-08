/*
 * Routines to update the results counters
 */

#include <errno.h>
#include "results.h"
#include "sanitise.h"
#include "syscall.h"
#include "tables.h"

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
	switch (argnum) {
	case 1:	return &entry->results1;
	case 2:	return &entry->results2;
	case 3:	return &entry->results3;
	case 4:	return &entry->results4;
	case 5:	return &entry->results5;
	case 6:	return &entry->results6;
	}
	unreachable();
}

static void store_successful_fd(struct results *results, unsigned long value)
{
	int fd = (int) value;

	// TODO: dynamically allocate fdmap on startup
	results->fdmap[fd] = TRUE;
}

static void store_successful_len(struct results *results, unsigned long value)
{
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
	entry = syscalls[call].entry;

	for_each_arg(entry, i) {
		struct results *results;
		enum argtype argtype = get_argtype(entry, i);
		unsigned long value = get_argval(rec, i);

		results = get_results_ptr(entry, i);

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
