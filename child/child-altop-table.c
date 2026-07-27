/*
 * Alt-op string names, external-linkage lookup, the outer-bracket
 * eligibility gate, and the op_dispatch[] indirect-call table.  Pure
 * static metadata carved out of child-altop.c so make -j can compile
 * each half of the split in parallel.
 *
 * Function declarations for the many child-op entry points threaded
 * into op_dispatch[] arrive via child.h; the include set matches
 * child-altop.c's so the dispatch initialiser sees the same set of
 * prototypes it always did.
 */


#include <string.h>
#include "child.h"
#include "child-internal.h"
#include "params.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "strategy.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
#include "kernel/mount.h"
#include "kernel/if_packet.h"

/*
 * KCOV bracketing opt-in.  Read by the childop dispatcher.  The
 * per-op verdict lives in childop.def's fourth (uses_outer_bracket)
 * field; today only CHILD_OP_SYSCALL and CHILD_OP_SCHED_CYCLER are
 * false.  CHILD_OP_SYSCALL falls through to run_sequence_chain which
 * brackets per-syscall internally.  CHILD_OP_SCHED_CYCLER
 * (childops/misc/sched-cycler.c) calls random_syscall(child) in a
 * tight loop; an outer bracket would double-call ioctl(KCOV_ENABLE)
 * and the kernel returns -EBUSY which kcov_enable_trace currently
 * treats as fatal.
 *
 * Kept as an accessor (rather than a lookup table) so the compiler
 * can fold the switch into a constant-time check at the call site.
 * The uses_outer_bracket field is required on every CHILDOP() row
 * (the macro takes four arguments); a new row picks up the default
 * by passing true explicitly and needs no edit to this function.
 */
bool op_uses_outer_bracket(enum child_op_type op)
{
	switch (op) {
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket)	\
	case enum_name: return uses_outer_bracket;
#include "childop.def"
#undef CHILDOP
	case NR_CHILD_OP_TYPES:		break;
	}
	return true;
}

const char *alt_op_name(enum child_op_type op)
{
	switch (op) {
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket)	\
	case enum_name: return name_string;
#include "childop.def"
#undef CHILDOP
	case NR_CHILD_OP_TYPES:		break;
	}
	return "unknown";
}

/*
 * Reverse of alt_op_name(): looks up an op by its string form (as
 * emitted by alt_op_name) and returns the matching enum value.  Used
 * by the --canary-seed CLI flag parser to translate operator-supplied
 * op names into an override seed list.  Linear scan over
 * NR_CHILD_OP_TYPES; called at most a few times at startup, never on
 * the hot path.  Returns NR_CHILD_OP_TYPES when no match is found so
 * the caller can distinguish "unknown name" from any real enum value.
 */
enum child_op_type alt_op_lookup_by_name(const char *name)
{
	unsigned int i;

	if (name == NULL || *name == '\0')
		return NR_CHILD_OP_TYPES;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		const char *n = alt_op_name((enum child_op_type)i);
		if (n != NULL && strcmp(n, name) == 0)
			return (enum child_op_type)i;
	}
	return NR_CHILD_OP_TYPES;
}

/*
 * Dispatch table for the per-iteration childop call.  Indexed by
 * enum child_op_type; a NULL slot means "fall through to the
 * sequence-chain path" (CHILD_OP_SYSCALL is handled by the 95% fast
 * path in pick_op_type and reaches the dispatcher only when it ends
 * up running random_syscall via run_sequence_chain).
 *
 * A dense table replaces what was a 38-case switch in the dispatch
 * site: a single indirect call out of a cache-friendly array,
 * instead of the jump-table the compiler emits per branch site.
 */
bool (*const op_dispatch[NR_CHILD_OP_TYPES])(struct childdata *) = {
#define CHILDOP(enum_name, name_string, dispatch_fn, uses_outer_bracket)	\
	[enum_name] = dispatch_fn,
#include "childop.def"
#undef CHILDOP
};

_Static_assert(ARRAY_SIZE(op_dispatch) == NR_CHILD_OP_TYPES,
	"op_dispatch must have one slot per enum child_op_type");
