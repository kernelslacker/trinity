/*
 * Self-check for the replay class on each argtype_table[] row, which
 * corpus_argtype_refused() and corpus_argtype_stale_on_replay() read:
 * every argtype has to be classified, and an argtype with no class is
 * refused.
 */

#include <stdio.h>

#include "argtype-ops.h"
#include "debug.h"		/* BUG */
#include "minicorpus.h"		/* corpus_argtype_refused, corpus_argtype_stale_on_replay */
#include "utils-macros.h"	/* ARRAY_SIZE */

/* A row that leaves the class out is how a new argtype would reach the
 * corpora unexamined. */
static void every_argtype_is_classified(void)
{
	unsigned int t;

	for (t = 0; t < argtype_table_size; t++) {
		if (argtype_table[t].generate == NULL ||
		    argtype_table[t].replay != CORPUS_REPLAY_UNSET)
			continue;
		fprintf(stderr, "%s\n", argtype_table[t].name);
		BUG("corpus replay class: an argtype has no replay class");
	}
}

/* An argtype with no row has no class, so it is refused rather than
 * kept raw, and it is not zeroed: a refused call is never replayed. */
static void an_argtype_without_a_row_is_refused(void)
{
	const enum argtype unlisted[] = {
		(enum argtype) argtype_table_size,
		(enum argtype) (argtype_table_size + 1000),
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(unlisted); i++) {
		if (!corpus_argtype_refused(unlisted[i]) ||
		    corpus_argtype_stale_on_replay(unlisted[i]))
			BUG("corpus replay class: an argtype with no row was not refused");
	}
}

void corpus_replay_class_self_check(void);
void corpus_replay_class_self_check(void)
{
	every_argtype_is_classified();
	an_argtype_without_a_row_is_refused();
}
