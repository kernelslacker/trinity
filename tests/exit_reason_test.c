/*
 * Self-check for exit_reason_is_clean() (include/exit.h).
 *
 * One predicate picks the exit code, gates the end-of-run warm-start
 * saves and forgives targeted-mode fast deaths.  A failure mode counted
 * clean saves a poisoned shm and exits 0; a clean reason counted dirty
 * drops an operator stop's saves.  Pin the exact set, plus the raw wait
 * statuses reap-fastdie.c feeds it (signal deaths are negative).
 */

#include <stdbool.h>
#include <stdio.h>

#include "debug.h"		/* BUG */
#include "exit.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

static const enum exit_reasons clean_reasons[] = {
	EXIT_REACHED_COUNT,
	EXIT_SIGINT,
	EXIT_USER_REQUEST,
	EXIT_EPOCH_DONE,
};

static bool listed_clean(int reason)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(clean_reasons); i++) {
		if ((int)clean_reasons[i] == reason)
			return true;
	}
	return false;
}

void exit_reason_clean_self_check(void);
void exit_reason_clean_self_check(void)
{
	static const int raw_statuses[] = { -9, -1, NUM_EXIT_REASONS, 255 };
	unsigned int i;
	int r;

	for (r = 0; r < NUM_EXIT_REASONS; r++) {
		if (exit_reason_is_clean((enum exit_reasons)r) != listed_clean(r)) {
			fprintf(stderr, "reason %d: %s\n",
				r, decode_exit((enum exit_reasons)r));
			BUG("exit_reason_is_clean: wrong verdict for a named reason");
		}
	}

	for (i = 0; i < ARRAY_SIZE(raw_statuses); i++) {
		if (exit_reason_is_clean((enum exit_reasons)raw_statuses[i])) {
			fprintf(stderr, "status %d\n", raw_statuses[i]);
			BUG("exit_reason_is_clean: a non-reason status counted clean");
		}
	}
}
