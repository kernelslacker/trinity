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

		if (argtype == ARG_LEN)
			store_successful_len(results, value);
	}
}
