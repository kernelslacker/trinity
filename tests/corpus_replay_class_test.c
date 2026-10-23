/*
 * Self-check for the replay class on each argtype_table[] row.  The
 * minicorpus and the chain corpus decide what to do with a saved value
 * by it, so every argtype has to say.
 */

#include <stdio.h>

#include "argtype-ops.h"
#include "debug.h"		/* BUG */

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

void corpus_replay_class_self_check(void);
void corpus_replay_class_self_check(void)
{
	every_argtype_is_classified();
}
