#pragma once

/*
 * Private cross-file declarations shared between main/trinity.c and
 * main/trinity-warmstart.c after the warm-start/bootstrap-helper carve.
 * Not part of the public trinity API -- external callers go through
 * include/trinity.h.
 */

#include "types.h"

/*
 * Returned by init_taint_and_handle_disabled_dump() to tell main()
 * whether to fall through to the next init phase or short-circuit to
 * finalize_and_exit, with INIT_FAILED reserved for the munge_tables()
 * error path.
 */
enum init_action {
	INIT_CONTINUE,
	INIT_DONE,
	INIT_FAILED,
};

/* Bootstrap helpers -- defined in main/trinity-warmstart.c, called
 * from main() in main/trinity.c in the order shown here. */
void init_main_process(char *argv[]);
void init_post_parse_io(void);
void init_main_early(void);
enum init_action init_taint_and_handle_disabled_dump(void);
void init_pre_fork(void);
bool run_oneshot_passes(void);
void publish_and_persist_seed(void);

/* Cross-run coverage carrier warm-start / persist pair -- defined in
 * main/trinity-warmstart.c, called from main() around the epoch/main
 * loop. */
void warm_start_all(void);
void persist_state_on_clean_exit(void);
