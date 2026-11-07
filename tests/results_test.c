/*
 * Self-check for the fd and length scoreboards handle_success() and
 * handle_failure() keep: they score the entry the dispatcher ran, and read
 * nothing a stray write to the shared record could move.
 */

#include <stdbool.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "results.h"
#include "syscall.h"

void results_self_check(void);
void results_self_check(void)
{
	static struct syscall_runtime rt;
	static struct syscallrecord rec;
	struct syscallentry entry = {
		.name = "results-probe",
		.num_args = 2,
		.fd_arg_mask = 1u << 0,
		.len_arg_mask = 1u << 1,
		.rt = &rt,
	};
	unsigned int i;

	results_init_one(&rt.results[1]);

	/* A number no table holds an entry at, as a stomp can leave it. */
	memset(&rec, 0, sizeof(rec));
	rec.nr = ~0U;
	rec.a1 = 5;
	rec.a2 = 64;
	handle_success(&rec, &entry);
	if (!(rt.results[0].success_fds[0] & (1u << 5)))
		BUG("results: a success did not score the dispatched entry's fd");
	if (rt.results[1].len_score.u.min != 64 ||
	    rt.results[1].len_score.u.max != 64)
		BUG("results: a success did not score the dispatched entry's length");

	rec.a1 = 7;
	for (i = 0; i < FAIL_RUN_THRESHOLD; i++)
		handle_failure(&rec, &entry);
	if (!fd_recently_failed(&rt.results[0], 7))
		BUG("results: a failure run did not score the dispatched entry's fd");
}
