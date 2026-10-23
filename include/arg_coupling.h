#pragma once

#include "stats_ring.h"		/* enum stats_field */

struct syscallentry;
struct syscallrecord;

/*
 * Cross-arg consistency validator.  Runs between argument generation
 * and syscall dispatch to catch (buf_ptr, count) and similar coupled
 * argument pairs that are dead-on-arrival from the kernel's point of
 * view -- the kernel would reject them at the earliest validation
 * step, so the dispatch wastes a syscall, a kcov enable/disable
 * round-trip, and a stats update on a call that cannot exercise any
 * meaningful kernel path.
 *
 * A syscall whose sanitiser vets its slots is held to them here as well,
 * by the entry's .vet_final hook, since a rewrite after the sanitiser
 * (chain substitution, a RedQueen pin) can undo the vetting: the final
 * slots are the ones the kernel reads.
 *
 * @entry is the descriptor the caller is dispatching.  The rules read
 * it, and call its hook, in place of rec->entry: the record sits in
 * shared memory, where a sibling's stray write could point that
 * anywhere.
 *
 * Returns 0 when the rec passes (or no per-syscall rule applies);
 * returns -1 when an inconsistency is detected.  On -1 the caller
 * should skip the dispatch and synthesize a rejection retval so the
 * post path stays consistent with a normal kernel EINVAL failure;
 * the rejection is logged via outputerr() with a per-syscall tag.
 */
int validate_arg_coupling(struct syscallrecord *rec,
			  const struct syscallentry *entry);

/*
 * Count a repaired slot (STATS_FIELD_ARG_CONSTRAINT_REPAIRED) or an
 * over-extent shape left alone (_KEPT_INCOHERENT) on this child's stats
 * ring.  madvise's .vet_final hook counts its overlap repair here.
 */
void arg_coupling_bump(enum stats_field field);
