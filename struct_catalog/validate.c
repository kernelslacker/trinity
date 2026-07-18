/*
 * Struct-catalog init-only slot-shape validation.
 *
 * Carved out of struct_catalog/catalog.c: this TU owns the init-time
 * guard that catches syscall_struct_args[] rows whose registered
 * struct_desc lands on a slot the syscall's own argtype[] declares
 * as non-struct-shaped.  The dispatcher tolerates such a mismatch at
 * runtime (the desc fires against whatever argtype actually sits at
 * argidx-1, typically ARG_PATHNAME or a scalar length/fd) so nothing
 * aborts at build or runtime -- but the mis-map silently steers CMP
 * attribution at the wrong bytes.  The guard turns that into an
 * init-time BUG, called from struct_catalog_init() in registry.c.
 *
 * Validation is init-only with clean inputs (the registration table,
 * the syscall table, argtype metadata), so it's the natural first
 * candidate for a unit-test surface after the split.
 */

#include <stdbool.h>
#include <stddef.h>

#include "argtype-ops.h"
#include "debug.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

/*
 * Slot-shape guard for syscall_struct_args[] rows.
 *
 * argtype[] is 0-indexed; syscall_struct_args::arg_idx is 1-indexed.  The
 * off-by-one was caught in the 2026-06-11 audit when six of eight new rows
 * were silently mapping their struct_desc onto the wrong slot -- the
 * dispatcher tolerates the mismatch (the desc fires against whatever
 * argtype actually sits at argidx-1, typically ARG_PATHNAME or a scalar
 * length / fd) so nothing aborted at build or runtime.  This guard turns
 * that silent mis-map into an init-time BUG by demanding that the slot
 * named by (argidx - 1) is a pointer-bearing argtype that can plausibly
 * carry the registered struct:
 *
 *   - ARG_STRUCT_PTR_IN / OUT / INOUT  (schema-aware fill, primary user)
 *   - ARG_ADDRESS / ARG_NON_NULL_ADDRESS  (bespoke .sanitise owns the
 *     live fill, attribution-only catalog row for CMP steering)
 *   - ARG_IOVEC / ARG_IOVEC_IN  (alloc_iovec() owns the live fill;
 *     catalog row is attribution-only for the iov_base / iov_len CMP
 *     names, see the SC_IOVEC comment above the catalog slot)
 *   - ARG_SOCKADDR  (bespoke sockaddr generator owns the live fill;
 *     attribution-only catalog row for sa_family / port CMP names)
 *   - ARG_TIMESPEC / ARG_ITIMERSPEC / ARG_TIMEVAL / ARG_ITIMERVAL
 *     (time-shaped pointer slots; catalog row carries the named
 *     tv_sec / tv_nsec / tv_usec CMP attributions while the per-argtype
 *     filler owns the live struct contents)
 *   - ARG_UNDEFINED  (the syscall has not fully classified its
 *     argtypes -- the bespoke .sanitise owns the fill regardless;
 *     this case is permissive on purpose so the guard does not block
 *     the long tail of legacy syscallentries that still leave argtype
 *     unset.  Migrating those to concrete argtypes tightens the guard
 *     for free.)
 *
 * The rejected set is what the off-by-one bug actually lands on:
 * ARG_PATHNAME (filename slot), ARG_LEN, ARG_FD and all typed-fd
 * argtypes, ARG_MODE_T, ARG_PID, ARG_KEY_SERIAL, ARG_RANGE, ARG_OP,
 * ARG_LIST, ARG_CPU, ARG_NUMA_NODE, ARG_MMAP, ARG_SOCKETINFO, the
 * paired-length helpers (ARG_IOVECLEN, ARG_SOCKADDRLEN, ARG_STRUCT_SIZE),
 * etc. -- every scalar or string slot whose contents are not a struct
 * the kernel will dereference as the desc named here.
 */
static bool is_struct_slot_argtype(enum argtype t)
{
	switch (t) {
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_UNDEFINED:
		return true;
	default:
		return false;
	}
}

static const char *argtype_name(enum argtype t)
{
	if ((unsigned int) t < argtype_table_size && argtype_table[t].name != NULL)
		return argtype_table[t].name;
	return "<unknown>";
}

static void validate_one_against_table(const struct syscalltable *table,
				       unsigned int nr_syscalls,
				       const char *tablename,
				       const struct syscall_struct_arg *sa,
				       unsigned int *violations)
{
	struct syscallentry *entry;
	enum argtype t;
	int nr;

	nr = search_syscall_table(table, nr_syscalls, sa->syscall_name);
	if (nr < 0)
		return;		/* not present on this arch table -- not an error */
	if ((unsigned int) nr >= MAX_NR_SYSCALL)
		return;
	entry = table[nr].entry;
	if (entry == NULL)
		return;

	if (sa->arg_idx < 1 || sa->arg_idx > entry->num_args) {
		outputerr("struct_catalog: %s arg_idx %u out of range for "
			  "syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, entry->name,
			  entry->num_args, tablename);
		(*violations)++;
		return;
	}

	t = entry->argtype[sa->arg_idx - 1];
	if (!is_struct_slot_argtype(t)) {
		outputerr("struct_catalog: %s arg %u maps struct_desc \"%s\" "
			  "onto non-struct slot (argtype[%u]=%s, num_args=%u) "
			  "in %s -- argidx is 1-based, argtype[] is 0-based; "
			  "off-by-one?\n",
			  sa->syscall_name, sa->arg_idx,
			  sa->desc != NULL ? sa->desc->name : "<null>",
			  sa->arg_idx - 1, argtype_name(t),
			  entry->num_args, tablename);
		(*violations)++;
	}

	if (sa->discrim_arg_idx != 0 &&
	    (sa->discrim_arg_idx < 1 || sa->discrim_arg_idx > entry->num_args)) {
		outputerr("struct_catalog: %s arg %u discrim_arg_idx %u out of "
			  "range for syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, sa->discrim_arg_idx,
			  entry->name, entry->num_args, tablename);
		(*violations)++;
	}

	if (sa->discrim2_arg_idx != 0 &&
	    (sa->discrim2_arg_idx < 1 || sa->discrim2_arg_idx > entry->num_args)) {
		outputerr("struct_catalog: %s arg %u discrim2_arg_idx %u out of "
			  "range for syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, sa->discrim2_arg_idx,
			  entry->name, entry->num_args, tablename);
		(*violations)++;
	}
}

void validate_syscall_struct_args(void)
{
	const struct syscall_struct_arg_group *g;
	const struct syscall_struct_arg *sa;
	unsigned int violations = 0;

	FOR_EACH_SYSCALL_STRUCT_ARG(g, sa) {
		if (biarch) {
			validate_one_against_table(syscalls_64bit,
						   max_nr_64bit_syscalls,
						   "64bit table", sa,
						   &violations);
			validate_one_against_table(syscalls_32bit,
						   max_nr_32bit_syscalls,
						   "32bit table", sa,
						   &violations);
		} else {
			validate_one_against_table(syscalls,
						   max_nr_syscalls,
						   "syscall table", sa,
						   &violations);
		}
	}

	if (violations != 0) {
		outputerr("struct_catalog: %u syscall_struct_args[] entr%s "
			  "failed slot-shape validation -- see lines above\n",
			  violations, violations == 1 ? "y" : "ies");
		BUG("struct_catalog: syscall_struct_args[] slot-shape violation");
	}
}
