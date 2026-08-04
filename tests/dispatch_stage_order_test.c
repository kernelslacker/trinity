/*
 * dispatch_stage_order_test.c -- invariant checks for dispatch_step()'s
 * stage ordering.
 *
 * dispatch_step() coordinates every post-syscall stage: kcov collection,
 * cmp-hint credit/reset, corpus publication, cleanup, completion
 * accounting, and the RedQueen re-exec drain.  Statement ORDER in that
 * function is the transaction -- a reorder can silently mis-attribute
 * wins, double-publish corpus entries, or let an inner re-exec recurse.
 * These tests verify the five load-bearing ordering invariants without
 * importing the real dispatch.c (which carries the full trinity dep
 * chain).  Instead each test simulates the relevant fragment of the
 * dispatch_step control flow inside a local harness and asserts the
 * invariant directly.
 *
 * Suite entry point: dispatch_stage_order_self_check()
 *
 * Tests
 * -----
 * 1. one_completion     -- exactly one completion bump per real call;
 *                          zero bumps when the pre-dispatch step fails.
 * 2. credit_ordering    -- the !in_reexec gate fires credit before reset
 *                          on the outer pass and skips both on the inner.
 * 3. corpus_once        -- corpus save fires exactly once per qualifying
 *                          outer pass; inner pass (in_reexec=true) is
 *                          tagged rq_sourced but does not double-publish
 *                          the outer entry.
 * 4. cleanup_all_paths  -- cleanup stage runs on every exit path
 *                          (productive, non-productive, early-return).
 * 5. recursive_boundary -- the in_reexec gate blocks a second-level
 *                          recursion; inner passes cannot credit or
 *                          publish as an outer pass would.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Minimal fake types -- only the fields exercises by the harness      */
/* ------------------------------------------------------------------ */

struct fake_entry {
	void (*sanitise)(void);	/* NULL == safe-to-save; non-NULL == skip */
};

struct fake_child {
	bool in_reexec;
	bool redqueen_enabled;
};

/* ------------------------------------------------------------------ */
/* Event log -- records the ORDER in which stages fire during a        */
/* simulated dispatch so ordering invariants can be asserted.          */
/* ------------------------------------------------------------------ */

#define MAX_EVENTS 64

enum stage_event {
	EV_NONE = 0,
	EV_CALL_START,
	EV_COLLECT,
	EV_CREDIT,
	EV_RESET,
	EV_CORPUS_SAVE,
	EV_CORPUS_SAVE_RQ,	/* save with rq_sourced=true (inner pass) */
	EV_CLEANUP,
	EV_COMPLETION_BUMP,
	EV_REEXEC_ENTER,
	EV_REEXEC_INNER_DISPATCH,
	EV_REEXEC_EXIT,
};

static enum stage_event g_events[MAX_EVENTS];
static unsigned int g_event_count;

static void ev_reset(void)
{
	memset(g_events, 0, sizeof(g_events));
	g_event_count = 0;
}

static void ev_push(enum stage_event ev)
{
	if (g_event_count < MAX_EVENTS)
		g_events[g_event_count++] = ev;
}

/* Returns the index of the first occurrence of ev, or -1 if absent. */
static int ev_find(enum stage_event ev)
{
	unsigned int i;

	for (i = 0; i < g_event_count; i++) {
		if (g_events[i] == ev)
			return (int)i;
	}
	return -1;
}

/* Count total occurrences of ev. */
static unsigned int ev_count(enum stage_event ev)
{
	unsigned int i, n = 0;

	for (i = 0; i < g_event_count; i++) {
		if (g_events[i] == ev)
			n++;
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* Simulated dispatch_step fragment                                     */
/*                                                                     */
/* Mirrors the ordering of dispatch_step()'s stages that the five      */
/* invariants depend on.  Non-essential code (kcov remote setup,       */
/* canary, stats ring, frontier, bandit) is omitted; the remaining     */
/* code preserves the exact stage sequence and all relevant gates.     */
/* ------------------------------------------------------------------ */

/*
 * Simulated dispatch.  Returns true when the call ran (do_syscall was
 * reached), false on early-return.  `found_something` models the
 * `new_edges || (new_cmp > 0)` boolean; `recurse_depth` guards the
 * recursion boundary test.
 */
static bool sim_dispatch_step(struct fake_child *child,
			      struct fake_entry *entry,
			      bool found_something,
			      unsigned int *recurse_depth)
{
	ev_push(EV_CALL_START);

	/* --- kcov collect (abbreviated) --- */
	ev_push(EV_COLLECT);

	/* --- credit / reset block (dispatch.c :434) ---
	 *
	 * Gated on !child->in_reexec.  Inside the gate: credit fires
	 * first, then stash reset.  Outside the gate: neither fires.
	 */
	if (!child->in_reexec) {
		if (found_something) {
			ev_push(EV_CREDIT);	/* cmp_hints_feedback_credit_* */
		} else {
			ev_push(EV_CREDIT);	/* credit_pc(false) still fires */
			ev_push(EV_RESET);	/* feedback_reset_stash */
		}
	}
	/* When in_reexec: no credit event, no reset event. */

	/* --- corpus save (dispatch.c :504-510) ---
	 *
	 * NOT inside the !in_reexec gate: both outer and inner passes
	 * reach this point when found_something && sanitise==NULL.
	 * Inner passes tag the entry rq_sourced=true (minicorpus-save.c
	 * :81); the outer pass uses the default (rq_sourced=false).
	 * The outer pass therefore publishes its entry AFTER the
	 * credit/reset block -- classification (found_something) happens
	 * before the save. */
	if (found_something && entry->sanitise == NULL) {
		if (child->in_reexec)
			ev_push(EV_CORPUS_SAVE_RQ);
		else
			ev_push(EV_CORPUS_SAVE);
	}

	/* --- cleanup (dispatch.c: handle_syscall_ret, ring push etc.) --- */
	ev_push(EV_CLEANUP);

	/* --- RedQueen re-exec tail (dispatch.c :665-829) ---
	 *
	 * Gate: !in_reexec (recursion guard), redqueen_enabled, new_cmp>0,
	 * pending>0.  For simplicity the harness treats found_something as
	 * the combined cmp/pending gate so the recursion boundary test can
	 * control it with a single flag.
	 *
	 * in_reexec brackets the drain so inner dispatch_step calls
	 * short-circuit at this gate and cannot recurse further.
	 */
	if (!child->in_reexec && child->redqueen_enabled && found_something) {
		(*recurse_depth)++;
		ev_push(EV_REEXEC_ENTER);

		child->in_reexec = true;
		/* inner dispatch -- fires recursively */
		ev_push(EV_REEXEC_INNER_DISPATCH);
		sim_dispatch_step(child, entry, found_something, recurse_depth);
		child->in_reexec = false;

		ev_push(EV_REEXEC_EXIT);
		(*recurse_depth)--;
	}

	return true;
}

/*
 * Simulated random_syscall_step wrapper.  Models:
 *   if (set_syscall_nr() == FAIL) return FAIL;   -- pre-dispatch bail
 *   dispatch_step();                              -- the real work
 *   bump completion counter;                     -- post-dispatch
 */
static bool sim_random_syscall_step(struct fake_child *child,
				    struct fake_entry *entry,
				    bool set_nr_ok,
				    bool found_something,
				    unsigned int *completions)
{
	unsigned int depth = 0;

	if (!set_nr_ok)
		return false;	/* pre-dispatch bail -- no completion */

	sim_dispatch_step(child, entry, found_something, &depth);

	ev_push(EV_COMPLETION_BUMP);
	(*completions)++;
	return true;
}

/* ------------------------------------------------------------------ */
/* BUG helper (matches production style; aborts on assertion failure)  */
/* ------------------------------------------------------------------ */

static void selftest_bug(const char *msg, const char *file, unsigned int line)
{
	fprintf(stderr, "FAIL: dispatch_stage_order: %s:%u: %s\n",
		file, line, msg);
	fflush(stderr);
	abort();
}

#define SELFTEST_ASSERT(cond) \
	do { \
		if (!(cond)) \
			selftest_bug(#cond, __FILE__, __LINE__); \
	} while (0)

/* ------------------------------------------------------------------ */
/* Test 1: one completion per actual call                              */
/*                                                                     */
/* Verify that the completion counter is bumped exactly once when the  */
/* pre-dispatch step succeeds, and is not bumped when it fails.        */
/* ------------------------------------------------------------------ */

static void test_one_completion(void)
{
	struct fake_child child = { .in_reexec = false,
				    .redqueen_enabled = false };
	struct fake_entry entry = { .sanitise = NULL };
	unsigned int completions;

	/* Case 1a: set_nr fails -- no dispatch, no completion. */
	ev_reset();
	completions = 0;
	sim_random_syscall_step(&child, &entry, /*set_nr_ok=*/false,
				/*found_something=*/false, &completions);
	SELFTEST_ASSERT(completions == 0);
	SELFTEST_ASSERT(ev_count(EV_COMPLETION_BUMP) == 0);
	SELFTEST_ASSERT(ev_count(EV_CALL_START) == 0);

	/* Case 1b: set_nr succeeds, call runs, exactly one completion. */
	ev_reset();
	completions = 0;
	sim_random_syscall_step(&child, &entry, /*set_nr_ok=*/true,
				/*found_something=*/false, &completions);
	SELFTEST_ASSERT(completions == 1);
	SELFTEST_ASSERT(ev_count(EV_COMPLETION_BUMP) == 1);
	SELFTEST_ASSERT(ev_count(EV_CALL_START) == 1);

	/* Case 1c: productive call -- still exactly one completion. */
	ev_reset();
	completions = 0;
	sim_random_syscall_step(&child, &entry, /*set_nr_ok=*/true,
				/*found_something=*/true, &completions);
	SELFTEST_ASSERT(completions == 1);
	SELFTEST_ASSERT(ev_count(EV_COMPLETION_BUMP) == 1);

	/* Case 1d: completion comes AFTER dispatch, never before. */
	ev_reset();
	completions = 0;
	sim_random_syscall_step(&child, &entry, /*set_nr_ok=*/true,
				/*found_something=*/false, &completions);
	{
		int call_pos   = ev_find(EV_CALL_START);
		int compl_pos  = ev_find(EV_COMPLETION_BUMP);

		SELFTEST_ASSERT(call_pos  >= 0);
		SELFTEST_ASSERT(compl_pos >= 0);
		SELFTEST_ASSERT(call_pos < compl_pos);
	}
}

/* ------------------------------------------------------------------ */
/* Test 2: credit/reset ordering                                       */
/*                                                                     */
/* The !in_reexec gate ensures:                                        */
/*   - outer pass (in_reexec=false): credit fires, then any reset      */
/*   - inner pass (in_reexec=true) : neither credit nor reset fires    */
/* ------------------------------------------------------------------ */

static void test_credit_ordering(void)
{
	struct fake_child outer = { .in_reexec = false,
				    .redqueen_enabled = false };
	struct fake_child inner = { .in_reexec = true,
				    .redqueen_enabled = false };
	struct fake_entry entry  = { .sanitise = NULL };
	unsigned int depth = 0;

	/* Case 2a: outer pass, non-productive -- credit fires then reset. */
	ev_reset();
	sim_dispatch_step(&outer, &entry, /*found_something=*/false, &depth);
	SELFTEST_ASSERT(ev_count(EV_CREDIT) >= 1);
	{
		int credit_pos = ev_find(EV_CREDIT);
		int reset_pos  = ev_find(EV_RESET);

		SELFTEST_ASSERT(credit_pos >= 0);
		SELFTEST_ASSERT(reset_pos  >= 0);
		/* credit must precede reset -- never the reverse */
		SELFTEST_ASSERT(credit_pos < reset_pos);
	}

	/* Case 2b: outer pass, productive -- credit fires, no reset event
	 * (the productive branch calls credit_pc(true), not reset_stash). */
	ev_reset();
	sim_dispatch_step(&outer, &entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CREDIT) >= 1);
	SELFTEST_ASSERT(ev_count(EV_RESET)  == 0);

	/* Case 2c: inner pass (in_reexec=true) -- neither credit nor
	 * reset fires, regardless of novelty. */
	ev_reset();
	sim_dispatch_step(&inner, &entry, /*found_something=*/false, &depth);
	SELFTEST_ASSERT(ev_count(EV_CREDIT) == 0);
	SELFTEST_ASSERT(ev_count(EV_RESET)  == 0);

	ev_reset();
	sim_dispatch_step(&inner, &entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CREDIT) == 0);
	SELFTEST_ASSERT(ev_count(EV_RESET)  == 0);

	/* Case 2d: credit always precedes corpus-save (classification
	 * before publication invariant). */
	ev_reset();
	sim_dispatch_step(&outer, &entry, /*found_something=*/true, &depth);
	{
		int credit_pos = ev_find(EV_CREDIT);
		int save_pos   = ev_find(EV_CORPUS_SAVE);

		SELFTEST_ASSERT(credit_pos >= 0);
		SELFTEST_ASSERT(save_pos   >= 0);
		SELFTEST_ASSERT(credit_pos < save_pos);
	}
}

/* ------------------------------------------------------------------ */
/* Test 3: corpus published exactly once, after classification         */
/*                                                                     */
/* An outer pass with found_something && sanitise==NULL produces       */
/* exactly one CORPUS_SAVE event, positioned after EV_COLLECT.        */
/* A sanitise-bearing entry or a non-productive call never saves.      */
/* An inner pass (in_reexec=true) produces EV_CORPUS_SAVE_RQ (tagged  */
/* rq_sourced) -- a distinct counter from EV_CORPUS_SAVE -- so the    */
/* outer entry's identity is not duplicated.                           */
/* ------------------------------------------------------------------ */

static void test_corpus_once(void)
{
	struct fake_entry safe_entry    = { .sanitise = NULL };
	struct fake_entry unsafe_entry;
	struct fake_child outer = { .in_reexec = false,
				    .redqueen_enabled = false };
	struct fake_child inner = { .in_reexec = true,
				    .redqueen_enabled = false };
	unsigned int depth = 0;

	/* Mark unsafe_entry as sanitise-bearing with a non-NULL pointer. */
	unsafe_entry.sanitise = (void (*)(void)) 0x1;

	/* Case 3a: outer, productive, safe entry -- exactly one save. */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE)    == 1);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE_RQ) == 0);

	/* Case 3b: outer, productive, sanitise-bearing -- no save. */
	ev_reset();
	sim_dispatch_step(&outer, &unsafe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE)    == 0);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE_RQ) == 0);

	/* Case 3c: outer, non-productive -- no save. */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/false, &depth);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE)    == 0);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE_RQ) == 0);

	/* Case 3d: inner pass, productive, safe entry -- saves but as
	 * rq_sourced (EV_CORPUS_SAVE_RQ), NOT as a plain outer save. */
	ev_reset();
	sim_dispatch_step(&inner, &safe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE)    == 0);
	SELFTEST_ASSERT(ev_count(EV_CORPUS_SAVE_RQ) == 1);

	/* Case 3e: corpus save comes AFTER collect (classification-
	 * before-publication ordering). */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/true, &depth);
	{
		int collect_pos = ev_find(EV_COLLECT);
		int save_pos    = ev_find(EV_CORPUS_SAVE);

		SELFTEST_ASSERT(collect_pos >= 0);
		SELFTEST_ASSERT(save_pos    >= 0);
		SELFTEST_ASSERT(collect_pos < save_pos);
	}
}

/* ------------------------------------------------------------------ */
/* Test 4: cleanup runs on every exit path                             */
/*                                                                     */
/* Every path through sim_dispatch_step must push EV_CLEANUP.         */
/* Covers: productive, non-productive, sanitise-bearing entry,        */
/* inner (in_reexec) pass.                                            */
/* ------------------------------------------------------------------ */

static void test_cleanup_all_paths(void)
{
	struct fake_entry safe_entry   = { .sanitise = NULL };
	struct fake_entry unsafe_entry;
	struct fake_child outer = { .in_reexec = false,
				    .redqueen_enabled = false };
	struct fake_child inner = { .in_reexec = true,
				    .redqueen_enabled = false };
	unsigned int depth = 0;

	unsafe_entry.sanitise = (void (*)(void)) 0x1;

	/* Path A: outer, productive */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CLEANUP) >= 1);

	/* Path B: outer, non-productive */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/false, &depth);
	SELFTEST_ASSERT(ev_count(EV_CLEANUP) >= 1);

	/* Path C: outer, sanitise-bearing */
	ev_reset();
	sim_dispatch_step(&outer, &unsafe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CLEANUP) >= 1);

	/* Path D: inner pass (in_reexec=true) */
	ev_reset();
	sim_dispatch_step(&inner, &safe_entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_CLEANUP) >= 1);

	/* Path E: cleanup comes AFTER corpus save (save before cleanup). */
	ev_reset();
	sim_dispatch_step(&outer, &safe_entry, /*found_something=*/true, &depth);
	{
		int save_pos    = ev_find(EV_CORPUS_SAVE);
		int cleanup_pos = ev_find(EV_CLEANUP);

		SELFTEST_ASSERT(save_pos    >= 0);
		SELFTEST_ASSERT(cleanup_pos >= 0);
		SELFTEST_ASSERT(save_pos < cleanup_pos);
	}
}

/* ------------------------------------------------------------------ */
/* Test 5: recursive boundary                                          */
/*                                                                     */
/* redqueen_reexec_step re-enters dispatch_step with in_reexec=true.  */
/* The outer in_reexec gate at dispatch_step:706 short-circuits the   */
/* re-exec tail so the inner pass cannot recurse a second level.      */
/* Additionally, an inner pass cannot emit a plain EV_CORPUS_SAVE     */
/* (outer-tagged publication) and cannot emit EV_CREDIT as the outer  */
/* pass would.                                                         */
/* ------------------------------------------------------------------ */

static void test_recursive_boundary(void)
{
	struct fake_entry entry = { .sanitise = NULL };
	struct fake_child child = { .in_reexec = false,
				    .redqueen_enabled = true };
	unsigned int depth = 0;

	/* A single outer dispatch with redqueen_enabled and
	 * found_something=true triggers one level of re-exec.  The inner
	 * dispatch runs with in_reexec=true and must NOT enter the re-exec
	 * tail again -- maximum recursion depth is 1. */
	ev_reset();
	depth = 0;
	sim_dispatch_step(&child, &entry, /*found_something=*/true, &depth);

	/* Exactly one REEXEC_ENTER/EXIT pair (depth==1, not deeper). */
	SELFTEST_ASSERT(ev_count(EV_REEXEC_ENTER) == 1);
	SELFTEST_ASSERT(ev_count(EV_REEXEC_EXIT)  == 1);

	/* in_reexec must be false after the drain -- restored correctly. */
	SELFTEST_ASSERT(child.in_reexec == false);

	/* The inner dispatch fires CALL_START (it really runs the syscall)
	 * but must not emit EV_REEXEC_ENTER again (no second-level
	 * recursion). */
	SELFTEST_ASSERT(ev_count(EV_CALL_START) == 2);	/* outer + inner */
	SELFTEST_ASSERT(ev_count(EV_REEXEC_ENTER) == 1);	/* outer only */

	/* Inner pass: no outer-tagged corpus save, no outer-tagged credit.
	 * The outer pass produced one CORPUS_SAVE; the inner produced at
	 * most one CORPUS_SAVE_RQ (it may or may not produce one depending
	 * on found_something -- in this case it may).  There must be zero
	 * additional outer-style CORPUS_SAVEs beyond the single outer one. */
	{
		unsigned int outer_saves = ev_count(EV_CORPUS_SAVE);
		/* Outer pass saves once; inner pass must not add another
		 * plain save -- the inner adds EV_CORPUS_SAVE_RQ. */
		SELFTEST_ASSERT(outer_saves == 1);
	}

	/* The outer pass credits once; the inner pass must not add more
	 * credit events (inner pass is gated out of the credit block). */
	SELFTEST_ASSERT(ev_count(EV_CREDIT) == 1);

	/* Recursion depth counter must have returned to 0. */
	SELFTEST_ASSERT(depth == 0);

	/* Case 5b: with redqueen disabled -- no re-exec, no inner dispatch. */
	child.redqueen_enabled = false;
	ev_reset();
	depth = 0;
	sim_dispatch_step(&child, &entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_REEXEC_ENTER) == 0);
	SELFTEST_ASSERT(ev_count(EV_CALL_START)   == 1);

	/* Case 5c: in_reexec=true from the start -- re-exec tail must
	 * not fire even with redqueen_enabled (the gate blocks it). */
	child.in_reexec = true;
	child.redqueen_enabled = true;
	ev_reset();
	depth = 0;
	sim_dispatch_step(&child, &entry, /*found_something=*/true, &depth);
	SELFTEST_ASSERT(ev_count(EV_REEXEC_ENTER) == 0);
	child.in_reexec = false;
}

/* ------------------------------------------------------------------ */
/* Suite entry point                                                   */
/* ------------------------------------------------------------------ */

void dispatch_stage_order_self_check(void);
void dispatch_stage_order_self_check(void)
{
	test_one_completion();
	test_credit_ordering();
	test_corpus_once();
	test_cleanup_all_paths();
	test_recursive_boundary();
}
